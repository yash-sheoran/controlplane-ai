"""HTTP views for Section 10's Observability Dashboard, Section 9.3's
alert-fatigue tuning view, and Section 7's feedback capture. Thin: all
aggregation logic lives in core/dashboard.py, all reviewer-decision logic
in core/decision_executor.py — these views just wire HTTP <-> that logic
and render templates, consistent with how core/views.py wires HTTP to
core/pre_request_analysis.py etc.
"""

import json

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from . import dashboard
from . import decision_executor as de
from .models import (
    AuditRecord,
    FalsePositiveReport,
    ReviewerAction,
    ThresholdChangeProposal,
    Trace,
    UserFeedback,
)


def dashboard_home(request):
    """Section 10.1 — Real-Time Operational Metrics."""
    since_24h = timezone.now() - timezone.timedelta(hours=24)
    decision_distribution = dashboard.decision_distribution()
    # Pre-zipped into rows: Django templates cannot look up a dict value by
    # a loop variable's key via dot notation (foo.bar always means the
    # literal key "bar"), so the view does the pairing instead.
    decision_rows = [
        {
            "action": action,
            "count": decision_distribution["counts"][action],
            "percentage": decision_distribution["percentages"][action],
        }
        for action in dashboard.DECISION_ACTIONS
    ]
    context = {
        "total_requests_24h": dashboard.total_requests(since=since_24h),
        "decision_distribution": decision_distribution,
        "decision_rows": decision_rows,
        "latency_percentiles": dashboard.latency_percentiles(),
        "total_cost_today": dashboard.total_cost_today(),
        "cost_per_model": dashboard.cost_per_model(),
        "active_human_review_queue_count": dashboard.active_human_review_queue_count(),
    }
    return render(request, "core/dashboard_home.html", context)


def dashboard_trends(request):
    """Section 10.2 — Safety & Quality Trend Metrics."""
    days = int(request.GET.get("days", 7))
    context = {
        "days": days,
        "hallucination_rate": dashboard.hallucination_rate(days=days),
        "safety_violation_rate": dashboard.safety_violation_rate(days=days),
        "data_leakage_attempts": dashboard.data_leakage_attempts(days=days),
        "bias_detection_rate": dashboard.bias_detection_rate(days=days),
        "blocked_request_rate": dashboard.blocked_request_rate(days=days),
        "retry_verify_rate": dashboard.retry_verify_rate(days=days),
        "human_review_rate": dashboard.human_review_rate(days=days),
    }
    return render(request, "core/dashboard_trends.html", context)


@require_http_methods(["GET", "POST"])
def human_review_queue(request):
    """Section 3 Step 9 HUMAN_REVIEW's queue + Section 7.1's reviewer
    gold-standard label. GET lists pending cases; POST applies a
    reviewer's decision to one of them."""
    if request.method == "POST":
        trace_id = request.POST.get("trace_id")
        decision = request.POST.get("decision")
        reviewer_id = request.POST.get("reviewer_id")
        decision_reason = request.POST.get("decision_reason", "")
        modified_response = request.POST.get("modified_response") or None

        record = get_object_or_404(AuditRecord, trace_id=trace_id)

        try:
            updated_case = de.apply_reviewer_decision(
                record.human_review or {}, decision=decision, reviewer_id=reviewer_id,
                modified_response=modified_response,
            )
        except ValueError as exc:
            return render(
                request, "core/human_review_queue.html",
                {"pending_cases": _pending_cases(), "error": str(exc)},
                status=400,
            )

        # decided_at is a real datetime (core.decision_executor is a pure,
        # DB-agnostic module); serialise it before storing in the JSONField.
        if updated_case.get("decided_at") is not None:
            updated_case["decided_at"] = updated_case["decided_at"].isoformat()

        record.human_review = updated_case
        record.human_review_status = "DECIDED"
        record.save(update_fields=["human_review", "human_review_status"])

        # Section 7.1: "the decision and rationale are logged as a
        # gold-standard label against the original audit scores" — a
        # dedicated, append-only row, distinct from the JSON snapshot above.
        ReviewerAction.objects.create(
            audit_record=record, reviewer_id=reviewer_id, decision=decision,
            decision_reason=decision_reason, modified_response=modified_response or "",
        )

        return render(
            request, "core/human_review_queue.html",
            {"pending_cases": _pending_cases(), "decided_case": updated_case},
        )

    return render(request, "core/human_review_queue.html", {"pending_cases": _pending_cases()})


def _pending_cases():
    return list(
        AuditRecord.objects.filter(human_review_status="PENDING").select_related("trace")
    )


@require_http_methods(["GET", "POST"])
def fpr_tuning(request):
    """Section 9.3 — Operator Dashboard Alert Tuning View."""
    context = {"result": None, "error": None}

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "report_false_positive":
            trace_id = request.POST.get("trace_id")
            dimension = request.POST.get("dimension")
            reported_by = request.POST.get("reported_by")
            reason = request.POST.get("reason", "")
            record = get_object_or_404(AuditRecord, trace_id=trace_id)
            FalsePositiveReport.objects.create(
                audit_record=record, dimension=dimension, reported_by=reported_by, reason=reason,
            )
            context["message"] = f"Recorded false-positive report for {dimension!r}."

        elif action == "check_fpr":
            use_case_id = request.POST.get("use_case_id")
            dimension = request.POST.get("dimension")
            days = int(request.POST.get("days", 7))
            context["result"] = dashboard.false_positive_rate_by_dimension(
                dimension, use_case_id=use_case_id, days=days,
            )
            context["result_dimension"] = dimension
            context["result_use_case_id"] = use_case_id

        elif action == "simulate_threshold_change":
            use_case_id = request.POST.get("use_case_id")
            bucket = request.POST.get("bucket")
            dimension = request.POST.get("dimension")
            new_threshold = float(request.POST.get("new_threshold"))
            days = int(request.POST.get("days", 7))
            context["simulation"] = dashboard.simulate_threshold_change(
                use_case_id, bucket, dimension, new_threshold, days=days,
            )

        elif action == "propose_threshold":
            proposal = ThresholdChangeProposal.objects.create(
                use_case_id=request.POST.get("use_case_id"),
                bucket=request.POST.get("bucket"),
                dimension=request.POST.get("dimension"),
                current_threshold=float(request.POST.get("current_threshold")),
                proposed_threshold=float(request.POST.get("proposed_threshold")),
                rationale=request.POST.get("rationale", ""),
            )
            context["proposal"] = proposal

    context["pending_proposals"] = list(ThresholdChangeProposal.objects.filter(status="PENDING"))
    return render(request, "core/fpr_tuning.html", context)


@csrf_exempt
@require_http_methods(["POST"])
def submit_thumbs_down(request, trace_id):
    """Section 7.1 User Thumbs-Down: "A lightweight user-facing feedback
    mechanism captures explicit dissatisfaction." A plain JSON API
    endpoint (unlike the dashboard's HTML-form views above) since this is
    meant to be called from the end-user-facing application, not the
    operator dashboard. csrf_exempt for the same reason core.views.
    create_request is: an external API caller has no Django session/CSRF
    cookie to present."""
    trace = get_object_or_404(Trace, request_id=trace_id)
    try:
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    feedback = UserFeedback.objects.create(trace=trace, comment=payload.get("comment", ""))
    return JsonResponse({"feedback_id": feedback.pk, "trace_id": str(trace_id)}, status=201)
