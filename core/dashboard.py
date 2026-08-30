"""Section 10 — Observability Dashboard & Metrics, Section 9.3 — Alert
Fatigue Control's operator tuning view, Section 7 — Feedback Loop &
Continuous Improvement.

Pure aggregation functions over AuditRecord/Trace/FalsePositiveReport
querysets, kept separate from the Django views in core/views.py so the
aggregation logic is directly testable without going through HTTP,
consistent with every other module in this project.
"""

import datetime

from django.utils import timezone

from . import policy_engine as pe
from .models import AuditRecord, FalsePositiveReport, Trace

DECISION_ACTIONS = ("ALLOW", "VERIFY", "MODIFY", "HUMAN_REVIEW", "BLOCK")


def _violation_threshold(dimension):
    """The single system-wide policy's configured threshold for
    `dimension` (core/config/policy.yaml), or None if it isn't configured
    at all — per core.policy_engine.dimension_violation_threshold. Used
    by the Trends-page "violation rate" metrics below. Resolved fresh on
    every call (no long-lived caching), consistent with
    load_policy_config's own no-cache-across-requests design."""
    return pe.dimension_violation_threshold(pe.load_policy_config(), dimension)


def _percentile(sorted_values, pct):
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * (pct / 100)
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1


# ---------------------------------------------------------------------------
# Section 10.1 — Real-Time Operational Metrics
# ---------------------------------------------------------------------------

def total_requests(since=None, user_ids=None):
    """Section 10.1: "Total Requests (24h): Count of all AI interactions
    processed in the last 24 hours, by use-case."

    user_ids: optional iterable of Trace.user_id values to restrict to —
    a manager's team (core.authz.team_user_ids); None means unscoped
    (every account predating this feature, e.g. a superuser, keeps seeing
    everything, matching this project's original no-auth behaviour)."""
    qs = Trace.objects.all()
    if since is not None:
        qs = qs.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(user_id__in=user_ids)
    return qs.count()


def decision_distribution(since=None, user_ids=None):
    """Section 10.1: "Decision Distribution: ALLOW / VERIFY / MODIFY /
    HUMAN_REVIEW / BLOCK counts and percentages." """
    qs = AuditRecord.objects.exclude(final_action__isnull=True)
    if since is not None:
        qs = qs.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    total = qs.count()
    counts = {action: qs.filter(final_action=action).count() for action in DECISION_ACTIONS}
    percentages = {
        action: (round(count / total * 100, 2) if total else 0.0)
        for action, count in counts.items()
    }
    return {"total": total, "counts": counts, "percentages": percentages}


def _response_metrics_values(user_ids=None):
    qs = AuditRecord.objects.all()
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    return [
        r["response_metrics"]
        for r in qs.values("response_metrics")
        if r["response_metrics"]
    ]


def latency_percentiles(user_ids=None):
    """Section 10.1: "Avg End-to-End Latency: P50 / P90 / P99 latency
    across all requests." """
    latencies = sorted(
        rm["latency_ms"] for rm in _response_metrics_values(user_ids=user_ids) if "latency_ms" in rm
    )
    return {
        "p50": _percentile(latencies, 50),
        "p90": _percentile(latencies, 90),
        "p99": _percentile(latencies, 99),
        "sample_size": len(latencies),
    }


def total_cost_today(user_ids=None):
    """Section 10.1: "Total AI Cost (Today): Cumulative cost from model
    usage." """
    today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    qs = AuditRecord.objects.filter(timestamp__gte=today_start)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    records = qs.values("response_metrics")
    return round(
        sum(r["response_metrics"].get("cost_usd", 0) for r in records if r["response_metrics"]), 6
    )


def cost_per_model(user_ids=None):
    """Section 10.1: "Cost Per Model: Which model is consuming the most
    budget and why." """
    totals = {}
    for rm in _response_metrics_values(user_ids=user_ids):
        model = rm.get("model_used")
        if not model:
            continue
        totals[model] = totals.get(model, 0) + rm.get("cost_usd", 0)
    return {model: round(cost, 6) for model, cost in totals.items()}


def active_human_review_queue_count(user_ids=None):
    """Section 10.1: "Active Human Review Queue: Current number of
    pending human review cases." """
    qs = AuditRecord.objects.filter(human_review_status="PENDING")
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    return qs.count()


# ---------------------------------------------------------------------------
# Section 10.2 — Safety & Quality Trend Metrics
# ---------------------------------------------------------------------------

def hallucination_rate(days=7, user_ids=None):
    """Section 10.2: "Hallucination Rate: Rolling 7-day average
    hallucination_risk score, with trend arrow." (trend arrow is a
    presentational concern for the template, not this function)."""
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    scores = [
        r["audit_quality"]["hallucination_risk_score"]
        for r in qs.values("audit_quality")
        if r["audit_quality"] and "hallucination_risk_score" in r["audit_quality"]
    ]
    return round(sum(scores) / len(scores), 4) if scores else None


def safety_violation_rate(days=7, user_ids=None):
    """Section 10.2: "Safety Violation Rate: Percentage of requests
    triggering safety_risk >= configured threshold." The "configured
    threshold" is the single system-wide policy's real threshold for
    safety_risk (core/config/policy.yaml, via
    policy_engine.dimension_violation_threshold), not a flat constant. If
    that dimension isn't configured at all, every request is excluded
    from both the numerator and denominator — there's no basis to judge
    it — rather than returning a misleading 0%."""
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    threshold = _violation_threshold("safety_risk")
    total = 0
    violations = 0
    if threshold is not None:
        for r in qs.values("audit_responsibility"):
            ar = r["audit_responsibility"]
            if not ar or "safety_risk_score" not in ar:
                continue
            total += 1
            if ar["safety_risk_score"] >= threshold:
                violations += 1
    return round(violations / total * 100, 2) if total else 0.0


def data_leakage_attempts(days=7, user_ids=None):
    """Section 10.2: "Data Leakage Attempts: Count of responses where
    data_leakage_risk_score >= 7." "Configured threshold" is the single
    system-wide policy's real threshold for data_leakage_risk (see
    safety_violation_rate's docstring for why this beats a flat constant).

    Extended (per explicit product decision, beyond the document's
    literal wording) to also count any request where the user's own
    prompt contained PII that Section 3 Step 2 2A had to redact and which
    the policy engine consequently MODIFYed: putting a phone number/
    email/etc into the prompt is itself a leakage attempt, even though
    the auditor's own data_leakage_risk_score often comes back low for
    these — the model is just echoing back what the user already typed,
    which isn't risky *from the model's own output*, but the attempt to
    push PII through the pipeline is exactly what this count exists to
    surface. A record is only ever counted once even if both conditions
    hold."""
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    threshold = _violation_threshold("data_leakage_risk")
    count = 0
    for r in qs.values("audit_responsibility", "pre_request", "final_action"):
        ar = r["audit_responsibility"]
        auditor_flagged = bool(ar) and threshold is not None and ar.get("data_leakage_risk_score", 0) >= threshold
        pre_request = r["pre_request"] or {}
        prompt_pii_modified = bool(pre_request.get("pii_detected_in_prompt")) and r["final_action"] == "MODIFY"
        if auditor_flagged or prompt_pii_modified:
            count += 1
    return count


def bias_detection_rate(days=7, user_ids=None):
    """Section 10.2: "Bias Detection Rate: Percentage of responses with
    bias_risk_score >= configured threshold, segmented by topic
    category." No "topic category" concept exists anywhere else in the
    document's schema or this project's models, so this returns the
    overall rate only — segmentation by topic is not implemented.
    "Configured threshold" is the single system-wide policy's real
    threshold for bias_risk (see safety_violation_rate's docstring)."""
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    threshold = _violation_threshold("bias_risk")
    total = 0
    detections = 0
    if threshold is not None:
        for r in qs.values("audit_responsibility"):
            ar = r["audit_responsibility"]
            if not ar or "bias_risk_score" not in ar:
                continue
            total += 1
            if ar["bias_risk_score"] >= threshold:
                detections += 1
    return round(detections / total * 100, 2) if total else 0.0


def blocked_request_rate(days=7, user_ids=None):
    """Section 10.2: "Blocked Request Rate: Percentage of total requests
    resulting in BLOCK, with drill-down by reason." """
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since).exclude(final_action__isnull=True)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    total = qs.count()
    blocked_qs = qs.filter(final_action="BLOCK")
    blocked = blocked_qs.count()

    by_reason = {}
    for record in blocked_qs.values("policy_rules_triggered"):
        for entry in record["policy_rules_triggered"] or []:
            by_reason[entry] = by_reason.get(entry, 0) + 1

    return {
        "rate": round(blocked / total * 100, 2) if total else 0.0,
        "blocked_count": blocked,
        "total": total,
        "by_reason": by_reason,
    }


def retry_verify_rate(days=7, user_ids=None):
    """Section 10.2: "Retry/Verify Rate: Percentage of requests requiring
    at least one retry, indicating model reliability." Counts a request as
    retried if EITHER the low-level execute_with_retry counter (Section 3
    Step 5: model-call failures/timeouts) OR the Step 9 VERIFY/RETRY
    regeneration loop (core.pipeline's verify_retry_count) fired at least
    once — these are two distinct retry mechanisms, and a request can hit
    either one independently."""
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    total = 0
    retried = 0
    for r in qs.values("response_metrics"):
        rm = r["response_metrics"]
        if not rm or "retry_count" not in rm:
            continue
        total += 1
        if rm["retry_count"] >= 1 or rm.get("verify_retry_count", 0) >= 1:
            retried += 1
    return round(retried / total * 100, 2) if total else 0.0


def human_review_rate(days=7, user_ids=None):
    """Section 10.2: "Human Review Rate: Percentage of requests requiring
    human review." """
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since).exclude(final_action__isnull=True)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    total = qs.count()
    human_review = qs.filter(final_action="HUMAN_REVIEW").count()
    return round(human_review / total * 100, 2) if total else 0.0


# ---------------------------------------------------------------------------
# Section 9.3 — Operator Dashboard Alert Tuning View
# ---------------------------------------------------------------------------

def false_positive_rate_by_dimension(dimension, days=7, user_ids=None):
    """Section 9.3: "False positive rate per dimension over the last 7 /
    30 days." A dimension's flag count = AuditRecords whose
    policy_rules_triggered mentions that dimension within the window;
    false positives = FalsePositiveReport rows for that dimension tied to
    those same AuditRecords."""
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)

    flagged_ids = [
        record["trace_id"]
        for record in qs.values("trace_id", "policy_rules_triggered")
        if any(f":{dimension}" in entry for entry in (record["policy_rules_triggered"] or []))
    ]
    flagged_count = len(flagged_ids)
    if flagged_count == 0:
        return {"flagged_count": 0, "false_positive_count": 0, "fpr": 0.0}

    false_positive_count = FalsePositiveReport.objects.filter(
        audit_record_id__in=flagged_ids, dimension=dimension, created_at__gte=since,
    ).count()

    return {
        "flagged_count": flagged_count,
        "false_positive_count": false_positive_count,
        "fpr": round(false_positive_count / flagged_count, 4),
    }


def simulate_threshold_change(bucket, dimension, new_threshold, days=7, user_ids=None):
    """Section 9.3: "Simulated impact: 'Adjusting hallucination_risk
    threshold from 7 to 8 would have reduced flags by 23% last week and
    potentially missed 2 confirmed hallucinations.'" Re-evaluates each
    historical AuditRecord's already-stored dimension score against the
    proposed threshold instead of the currently configured one, using the
    same higher-is-worse/higher-is-better direction table as the live
    policy engine (core.policy_engine, Section 4).

    A "confirmed" issue (as opposed to a false positive) is one with no
    matching FalsePositiveReport — this project has no other ground-truth
    source, so a flag not reported as a false positive is treated as
    confirmed, consistent with Section 7.1's "False Positive Reports"
    being the only concrete way this system has of knowing a flag was
    wrong.
    """
    config = pe.load_policy_config()
    current_threshold = config.get("thresholds", {}).get(bucket, {}).get(dimension)
    if current_threshold is None:
        # This bucket/dimension pair isn't configured at all (e.g.
        # toxicity_risk is no longer in `block` — it moved to
        # verify_warning). pe._dimension_breaches_threshold's >=/<=
        # comparison would otherwise crash on a None threshold; a
        # manager submitting a plausible-but-no-longer-valid combination
        # from the free-text bucket/dimension fields below should see an
        # honest "nothing to simulate" result, not a 500.
        return {
            "current_threshold": None,
            "proposed_threshold": new_threshold,
            "flags_before": 0,
            "flags_after": 0,
            "reduction_pct": 0.0,
            "missed_confirmed_issues": 0,
            "not_configured": True,
        }
    since = timezone.now() - datetime.timedelta(days=days)
    qs = AuditRecord.objects.filter(timestamp__gte=since)
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)

    flags_before = 0
    flags_after = 0
    missed_confirmed_issues = 0

    for record in qs:
        scores = {**(record.audit_quality or {}), **(record.audit_responsibility or {})}
        if scores.get(f"{dimension}_score") is None:
            continue

        was_flagged = pe._dimension_breaches_threshold(dimension, current_threshold, scores)
        now_flagged = pe._dimension_breaches_threshold(dimension, new_threshold, scores)

        if was_flagged:
            flags_before += 1
            if not now_flagged:
                is_confirmed = not FalsePositiveReport.objects.filter(
                    audit_record=record, dimension=dimension,
                ).exists()
                if is_confirmed:
                    missed_confirmed_issues += 1
        if now_flagged:
            flags_after += 1

    reduction_pct = round((flags_before - flags_after) / flags_before * 100, 2) if flags_before else 0.0

    return {
        "current_threshold": current_threshold,
        "proposed_threshold": new_threshold,
        "flags_before": flags_before,
        "flags_after": flags_after,
        "reduction_pct": reduction_pct,
        "missed_confirmed_issues": missed_confirmed_issues,
        "not_configured": False,
    }
