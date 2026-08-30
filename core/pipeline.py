"""Full pipeline wiring (this project's plan, Step 10).

Composes every previously standalone module into the actual request flow
for an already-ingested Trace (Section 3 Step 1, core.views.create_request):
pre-request analysis (Step 2) -> PROMPT-TIME Human Review policy audit
(new; see module-level note below) -> model router + execution + metrics
(Steps 3-5) -> auditing engine (Step 6) -> policy engine with session-risk
escalation (Step 8, Section 6.1) -> decision executor (Step 9), with
Section 8's regulation library applied throughout, persisting the full
AuditRecord / Trace / SessionState in MySQL.

PRODUCT DECISION — Human Review moved to the prompt stage: Human Review
used to be reachable only after a response already existed (via the
response-side policy engine's human_review bucket, via a hardcoded
fallback when the response auditor's own JSON failed validation twice, or
via VERIFY/RETRY exhaustion). It is now decided ONLY by auditing the raw
PROMPT, before any generation call, against a company-wide policy
document (core/config/company_policy.json) — see core.auditing_engine.
run_prompt_policy_audit and core.policy_engine.evaluate_prompt_policy.
Response-side auditing still scores quality/safety exactly as before and
can still BLOCK or MODIFY a response, but can never again produce
HUMAN_REVIEW (see core.policy_engine's RULE_ORDER comment); a response-
side concern that used to reach human review instead now surfaces as a
non-gating "Verify warning" (core.policy_engine.evaluate_verify_warnings),
delivered alongside the response rather than gating it.

This splits a request into two phases. Phase A (prompt-time): PII
pseudonymisation, complexity/risk analysis, the router's own pre-check,
then the new prompt-policy audit. Phase A resolves immediately to BLOCK,
or to ALLOW (falling straight through to Phase B in the same request —
today's original happy path, unchanged), or queues HUMAN_REVIEW and
returns early with no generation call. Phase B (generation + response
audit): runs immediately after Phase A's ALLOW, or later, once a manager
approves a queued case, via resume_after_prompt_review below.

PRODUCT DECISION — "use case" removed entirely: every request used to
carry a use_case_id selecting a per-use-case UseCaseProfile row (and,
through it, a per-use-case YAML policy file, geography, regulations, EU
AI Act high-risk flag, retention days). Every UseCaseProfile row that
ever existed had identical values for all of those except which policy
file it pointed at, so this is a behaviour-preserving collapse: one fixed
policy (core/config/policy.yaml) and the _FIXED_* constants below,
matching exactly what was already true for every use case.
"""

from django.db import transaction
from django.utils import timezone

from . import auditing_engine as ae
from . import decision_executor as de
from . import model_pipeline as mp
from . import policy_engine as pe
from . import pre_request_analysis as pra
from . import regulation_library as rl
from . import session_risk as sr
from .models import AuditRecord, SessionState, Trace

_EMPTY_SESSION_STATE = {
    "turn_number": 0, "session_risk_accumulator": 0.0, "recent_risk_scores": [],
    "verify_count": 0, "modify_count": 0, "human_review_count": 0,
    "was_blocked": False, "previous_decisions": [],
}

# See the "use case removed" module note above.
_FIXED_GEOGRAPHY = []
_FIXED_REGULATIONS = []
_FIXED_EU_AI_ACT_HIGH_RISK = False
_FIXED_AUDIT_RETENTION_DAYS = 90
_POLICY_PROFILE_VERSION = "default-policy"


def _load_session_state(session_id):
    try:
        session = SessionState.objects.get(session_id=session_id)
    except SessionState.DoesNotExist:
        return dict(_EMPTY_SESSION_STATE)
    return {
        "turn_number": session.turn_number,
        "session_risk_accumulator": session.session_risk_accumulator,
        "recent_risk_scores": session.recent_risk_scores,
        "verify_count": session.verify_count,
        "modify_count": session.modify_count,
        "human_review_count": session.human_review_count,
        "was_blocked": session.was_blocked,
        "previous_decisions": session.previous_decisions,
    }


def _save_session_state(session_id, state):
    SessionState.objects.update_or_create(
        session_id=session_id,
        defaults={
            "turn_number": state["turn_number"],
            "session_risk_accumulator": state["session_risk_accumulator"],
            "recent_risk_scores": state["recent_risk_scores"],
            "verify_count": state["verify_count"],
            "modify_count": state["modify_count"],
            "human_review_count": state["human_review_count"],
            "was_blocked": state["was_blocked"],
            "previous_decisions": state["previous_decisions"],
        },
    )


def _split_scores(scores):
    """Splits the auditing engine's flat {dim}_score/{dim}_reason dict
    into the quality/responsibility groups AuditRecord stores separately
    (Section 2.2 Decision 2's two parallel audit tracks)."""
    if not scores:
        return {}, {}
    quality = {}
    responsibility = {}
    for dim in ae.QUALITY_DIMENSIONS:
        for suffix in ("_score", "_reason"):
            key = f"{dim}{suffix}"
            if key in scores:
                quality[key] = scores[key]
    for dim in ae.RESPONSIBILITY_DIMENSIONS:
        for suffix in ("_score", "_reason"):
            key = f"{dim}{suffix}"
            if key in scores:
                responsibility[key] = scores[key]
    return quality, responsibility


def _run_single_attempt(model_id, prompt, timeout_s, max_retries, policy_config, pii_context):
    """One full generate + audit + policy-check attempt (Steps 3-5, then
    6). Raises model_pipeline.ModelExecutionError if the model call fails
    on every attempt."""
    response, elapsed_ms, retry_count = mp.execute_with_retry(
        model_id, prompt, timeout_s=timeout_s, max_retries=max_retries,
    )
    metrics = mp.collect_metrics(response, elapsed_ms, retry_count)

    audit_result = ae.run_auditing_engine(
        original_prompt=prompt, ai_response=response["text"], pre_request_flags=pii_context,
    )

    if not audit_result["validation_passed"]:
        # Was HUMAN_REVIEW; per product decision, response-side auditing
        # can never produce HUMAN_REVIEW any more (only the prompt-time
        # audit may queue a request for review, and that already ran
        # before generation). A response this system was unable to score
        # on ANY of the 12 dimensions is a "could not assess" situation,
        # not a content judgment — fail closed (BLOCK), matching the same
        # principle core.pre_request_analysis.RiskAnalysisError's own
        # docstring states for an equivalent pre-generation case ("let
        # this propagate rather than silently guessing a score for a
        # step this safety-critical").
        policy_result = {
            "final_action": "BLOCK",
            "rules_evaluated": [],
            "rules_triggered": [],
            "reason": "Auditor failed validation twice; response could not be assessed.",
        }
        verify_warnings = []
    else:
        policy_result = pe.evaluate_policy(policy_config, audit_result["scores"], context=pii_context)
        verify_warnings = pe.evaluate_verify_warnings(policy_config, audit_result["scores"])

    return {
        "response_text": response["text"],
        "metrics": metrics,
        "audit_result": audit_result,
        "policy_result": policy_result,
        "final_action": policy_result["final_action"],
        "verify_warnings": verify_warnings,
    }


def _dispatch(attempt, final_action, token_map):
    if final_action == "ALLOW":
        result = de.execute_allow(attempt["response_text"], token_map)
        result["verify_warnings"] = attempt.get("verify_warnings") or []
        return result
    if final_action == "MODIFY":
        result = de.execute_modify(attempt["response_text"])
        result["verify_warnings"] = attempt.get("verify_warnings") or []
        return result
    if final_action == "BLOCK":
        return de.execute_block(attempt["policy_result"]["reason"])
    raise ValueError(f"Unexpected final_action {final_action!r}")


def _run_pipeline_attempts(model_id, prompt, timeout_s, max_retries, policy_config, pii_context, token_map):
    """Runs the initial attempt, and — only if it comes back VERIFY —
    hands off to core.decision_executor.execute_verify_retry for the
    re-generate-with-escalation flow (Section 3 Step 9 VERIFY/RETRY),
    with a real attempt_fn that re-runs Steps 3-6 rather than a mock.

    Returns (final_attempt, exec_result, final_action).
    """
    attempt = _run_single_attempt(model_id, prompt, timeout_s, max_retries, policy_config, pii_context)
    final_action = attempt["final_action"]

    if final_action != "VERIFY":
        return attempt, _dispatch(attempt, final_action, token_map), final_action

    last_attempt = {"value": attempt}

    def attempt_fn(retry_model_id, enhanced_prompt):
        retry_attempt = _run_single_attempt(
            retry_model_id, prompt, timeout_s, max_retries, policy_config, pii_context,
        )
        last_attempt["value"] = retry_attempt
        return {
            "final_action": retry_attempt["final_action"],
            "response_text": retry_attempt["response_text"],
            "token_map": token_map,
            "verify_warnings": retry_attempt.get("verify_warnings") or [],
            "policy_trigger_reason": retry_attempt["policy_result"]["reason"],
        }

    exec_result = de.execute_verify_retry(attempt_fn, initial_model_id=model_id, max_retries=max_retries)
    return last_attempt["value"], exec_result, exec_result["final_decision"]


def _run_generation_and_response_audit(pseudonymized_prompt, policy_config, session_state,
                                        session_risk_threshold, pii_context, token_map, routing):
    """Phase B: Steps 3-9 for a request that has ALREADY cleared the
    prompt-time policy audit — either just now (a fresh ALLOW, same
    request) or previously (a manager just approved a queued case,
    resume_after_prompt_review below). `session_state` is deliberately
    passed in rather than reloaded internally, so a caller can supply
    either "the state loaded moments ago in this same request" (the
    ALLOW path) or "whatever is true right now" (the resume path, which
    may run long after the prompt was first queued).

    Returns a dict of every field the caller needs to persist. Raises
    model_pipeline.ModelExecutionError if generation fails on every
    attempt — deliberately NOT caught here (see module docstring's
    callers: both core.views.create_request and core.dashboard_views.
    playground already handle an uncaught process_request failure
    gracefully; a request that never produced a response is not "shown,
    with a warning" the way an audited-but-imperfect one is — there is no
    response to attach a warning to).
    """
    effective_policy_config = sr.get_effective_policy_config(policy_config, session_state, session_risk_threshold)
    timeout_s = policy_config["latency_budget_ms"] / 1000
    max_retries = policy_config["max_retries"]

    final_attempt, exec_result, final_action = _run_pipeline_attempts(
        routing["model"], pseudonymized_prompt, timeout_s, max_retries,
        effective_policy_config, pii_context, token_map,
    )
    quality, responsibility = _split_scores(final_attempt["audit_result"].get("scores"))

    # Section 3 Step 9's VERIFY/RETRY regeneration loop (decision_executor.
    # execute_verify_retry) is a distinct mechanism from Step 5's low-level
    # execute_with_retry (model-call failures/timeouts) — the latter's
    # retry_count already lives in final_attempt["metrics"], but the
    # former's attempt count was previously computed and discarded,
    # leaving core.dashboard.retry_verify_rate with nothing to detect a
    # request that went through Step 9's escalation flow at all.
    response_metrics = dict(final_attempt["metrics"])
    response_metrics["verify_retry_count"] = len(exec_result.get("retry_attempts") or [])

    return {
        "response_metrics": response_metrics,
        "audit_quality": quality,
        "audit_responsibility": responsibility,
        "composite_risk_score": final_attempt["audit_result"].get("composite_risk_score"),
        "auditor_model": final_attempt["audit_result"].get("auditor_model") or "",
        "recommended_action": final_attempt["audit_result"].get("recommended_action"),
        "policy_rules_evaluated": final_attempt["policy_result"].get("rules_evaluated", []),
        "policy_rules_triggered": final_attempt["policy_result"].get("rules_triggered", []),
        "final_action": final_action,
        "modification": exec_result.get("modification_log") if final_action == "MODIFY" else None,
        "verify_warnings": exec_result.get("verify_warnings") or [],
        "user_response_content": exec_result.get("user_response"),
        "disclosure_notice": exec_result.get("disclosure_notice"),
    }


def _finalize_turn(trace, session_state, risk, final_action, session_risk_window, audit_record, close_trace):
    """Shared tail for every process_request exit point except the
    prompt-time HUMAN_REVIEW path's early return: Section 6.1's
    session-risk accumulator update, and (when the turn is actually
    resolved) closing the trace. HUMAN_REVIEW is the one caller that
    updates session-risk here (this turn's contribution — it needed a
    human — is a permanent historical fact regardless of how a reviewer
    later decides) but passes close_trace=False, since nothing is
    resolved yet.
    """
    updated_session_state = sr.update_session_risk_accumulator(
        session_state, turn_risk_score=risk, turn_decision=final_action, window_size=session_risk_window,
    )
    _save_session_state(trace.session_id, updated_session_state)

    trace.final_decision = final_action
    if close_trace:
        trace.status = Trace.STATUS_CLOSED
        trace.closed_at = timezone.now()
        trace.save(update_fields=["status", "final_decision", "closed_at"])
    else:
        trace.save(update_fields=["final_decision"])

    user_response = audit_record.user_response or {}
    return {
        "final_action": final_action,
        "user_response": user_response.get("content"),
        "disclosure_notice": user_response.get("disclosure_notice"),
        "audit_record": audit_record,
    }


def process_request(trace):
    """Runs the complete pipeline for one already-ingested Trace and
    persists the full AuditRecord, updated Trace, and updated
    SessionState. Returns a dict: final_action, user_response,
    disclosure_notice, audit_record. See module docstring for the
    Phase A (prompt) / Phase B (generation+response) split.
    """
    policy_config = pe.load_policy_config()
    session_risk_threshold = policy_config.get("session_risk_threshold", 5.0)
    session_risk_window = policy_config.get("session_risk_window", sr.DEFAULT_SESSION_RISK_WINDOW)

    session_state = _load_session_state(trace.session_id)

    # Section 8 — Regulatory & Geography-Aware Compliance Module.
    compliance_metadata = rl.build_compliance_metadata(
        _FIXED_REGULATIONS, _FIXED_EU_AI_ACT_HIGH_RISK, _FIXED_AUDIT_RETENTION_DAYS,
    )

    # Section 3 Step 2 — Pre-Request Analysis. complexity/risk come from a
    # real model call (core.pre_request_analysis.analyze_prompt); a
    # repeated analyzer failure raises RiskAnalysisError, which is left to
    # propagate (rather than guessed at) since a wrong guess here could
    # route a harmful prompt around Step 3's BLOCK pre-check.
    pii_result = pra.detect_and_pseudonymize_pii(trace.raw_prompt)
    complexity, risk = pra.analyze_prompt(trace.raw_prompt, pii_detected=pii_result["pii_detected"])
    pii_context = {"pii_detected": pii_result["pii_detected"], "pii_categories": pii_result["pii_categories"]}
    pseudonymized_prompt = pii_result["pseudonymized_text"] or trace.raw_prompt

    pre_request_data = {
        "complexity_score": complexity,
        "risk_score": risk,
        "pii_detected_in_prompt": pii_result["pii_detected"],
        "pii_categories": pii_result["pii_categories"],
        "pseudonymisation_applied": pii_result["pii_detected"],
        # Persisted (not just used locally) so a prompt-time HUMAN_REVIEW
        # case can resume generation later, in a different request,
        # without re-deriving them — see resume_after_prompt_review.
        "pseudonymized_prompt": pseudonymized_prompt,
        "token_map": pii_result["token_map"],
    }

    # Section 3 Step 3 — Model Router.
    routing = mp.select_model(complexity, risk)

    common_kwargs = dict(
        trace=trace,
        geography=_FIXED_GEOGRAPHY,
        regulation_versions=compliance_metadata["regulation_versions"],
        compliance_metadata=compliance_metadata,
        pre_request=pre_request_data,
        model_routing=routing,
        policy_profile_version=_POLICY_PROFILE_VERSION,
        session_state_snapshot=session_state,
    )

    if routing["blocked"]:
        # Section 3 Step 3: "Risk 9-10 -> Route to BLOCK pre-check before
        # model call; may not proceed." No model call, no audit. A
        # different, orthogonal mechanism from the prompt-policy audit
        # below (capability/audit-strictness routing by risk score, not
        # company-policy topic matching) — left untouched.
        exec_result = de.execute_block(routing["selection_reason"])
        final_action = "BLOCK"
        with transaction.atomic():
            audit_record = AuditRecord.objects.create(
                **common_kwargs,
                final_action=final_action,
                policy_rules_evaluated=["ROUTER_PRE_CHECK"],
                policy_rules_triggered=["ROUTER_PRE_CHECK:risk_score"],
                user_response={"content": exec_result["user_response"], "disclosure_notice": None},
            )
        return _finalize_turn(trace, session_state, risk, final_action,
                               session_risk_window, audit_record, close_trace=True)

    # NEW — prompt-time Human Review policy audit (see module docstring).
    # Runs on the raw prompt (matching analyze_prompt's own precedent of
    # analysing the raw, not pseudonymised, text — pseudonymisation is a
    # generation-time protection, not an analysis-time one).
    company_policy = pe.load_company_policy()
    prompt_audit_result = ae.run_prompt_policy_audit(trace.raw_prompt, company_policy)
    if not prompt_audit_result["validation_passed"]:
        # This auditor's own infra failure (malformed JSON twice) is a
        # different concept from "response-audit triggering human
        # review" — "prevent silent failures" still applies here, and
        # HUMAN_REVIEW is exactly what this stage exists to decide.
        violated_policies = []
        prompt_audit_reason = prompt_audit_result["reason"]
        prompt_decision = "HUMAN_REVIEW"
    else:
        violated_policies = prompt_audit_result["violated_policies"]
        prompt_audit_reason = prompt_audit_result["reason"]
        prompt_decision = pe.evaluate_prompt_policy(company_policy, violated_policies)

    prompt_audit_data = {
        "decision": prompt_decision,
        "reason": prompt_audit_reason,
        "violated_policies": violated_policies,
        "policy_version": company_policy.get("version"),
    }
    prompt_policy_rules_triggered = [f"PROMPT_POLICY_CHECK:{c}" for c in violated_policies] or ["PROMPT_POLICY_CHECK"]

    if prompt_decision == "BLOCK":
        exec_result = de.execute_block(prompt_audit_reason)
        final_action = "BLOCK"
        with transaction.atomic():
            audit_record = AuditRecord.objects.create(
                **common_kwargs,
                prompt_audit=prompt_audit_data,
                final_action=final_action,
                policy_rules_evaluated=["PROMPT_POLICY_CHECK"],
                policy_rules_triggered=prompt_policy_rules_triggered,
                user_response={"content": exec_result["user_response"], "disclosure_notice": None},
            )
        return _finalize_turn(trace, session_state, risk, final_action,
                               session_risk_window, audit_record, close_trace=True)

    if prompt_decision == "HUMAN_REVIEW":
        exec_result = de.execute_prompt_human_review(prompt_audit_reason, violated_policies)
        final_action = "HUMAN_REVIEW"
        with transaction.atomic():
            audit_record = AuditRecord.objects.create(
                **common_kwargs,
                prompt_audit=prompt_audit_data,
                final_action=final_action,
                policy_rules_evaluated=["PROMPT_POLICY_CHECK"],
                policy_rules_triggered=prompt_policy_rules_triggered,
                human_review=exec_result["queued_case"],
                human_review_status="PENDING",
                user_response={"content": exec_result["user_response"], "disclosure_notice": None},
            )
        # Trace stays OPEN — nothing is resolved yet, no generation has
        # happened; resume_after_prompt_review closes it once a manager
        # decides. Session-risk still updates now (close_trace=False).
        return _finalize_turn(trace, session_state, risk, final_action,
                               session_risk_window, audit_record, close_trace=False)

    # ALLOW: fall through to Phase B immediately, in the same request —
    # no change to today's original happy path.
    phase_b = _run_generation_and_response_audit(
        pseudonymized_prompt, policy_config, session_state,
        session_risk_threshold, pii_context, pii_result["token_map"], routing,
    )
    with transaction.atomic():
        audit_record = AuditRecord.objects.create(
            **common_kwargs,
            prompt_audit=prompt_audit_data,
            response_metrics=phase_b["response_metrics"],
            audit_quality=phase_b["audit_quality"],
            audit_responsibility=phase_b["audit_responsibility"],
            composite_risk_score=phase_b["composite_risk_score"],
            auditor_model=phase_b["auditor_model"],
            recommended_action=phase_b["recommended_action"],
            policy_rules_evaluated=phase_b["policy_rules_evaluated"],
            policy_rules_triggered=phase_b["policy_rules_triggered"],
            final_action=phase_b["final_action"],
            modification=phase_b["modification"],
            verify_warnings=phase_b["verify_warnings"],
            user_response={
                "content": phase_b["user_response_content"],
                "disclosure_notice": phase_b["disclosure_notice"],
            },
        )
    return _finalize_turn(trace, session_state, risk, phase_b["final_action"],
                           session_risk_window, audit_record, close_trace=True)


def resume_after_prompt_review(audit_record):
    """Called from core.dashboard_views.human_review_queue's POST handler
    AFTER it has already recorded the reviewer's raw APPROVE/REJECT
    verdict onto audit_record.human_review/human_review_status via
    core.decision_executor.apply_prompt_review_decision — this is the
    function that actually ACTS on that verdict: REJECT stops here,
    permanently, with no generation ever attempted; APPROVE is what
    causes generation to happen for the very first time.

    final_action / human_review_status are deliberately left untouched
    here (already "HUMAN_REVIEW" / "DECIDED" by the time this runs) — that
    pair is the permanent, honest record of which gate this request went
    through and that a human decided it, independent of what the
    response-audit later finds. Everything the response-audit actually
    finds after an APPROVE is still fully recorded below (response_
    metrics/audit_quality/audit_responsibility/policy_rules_evaluated/
    modification/verify_warnings), just not folded into final_action
    itself — this matches how core.dashboard.human_review_rate already
    relies on final_action=="HUMAN_REVIEW" meaning exactly "this request
    needed a human", independent of what happened afterwards.

    Returns the same shape as process_request: final_action,
    user_response, disclosure_notice, audit_record.

    Raises model_pipeline.ModelExecutionError if APPROVE's generation
    call fails on every attempt — the caller must catch this, mirroring
    how core.views.create_request and core.dashboard_views.playground
    already handle an uncaught process_request failure. Nothing here is
    left half-saved if that happens: every field below is only assigned/
    saved after generation has already succeeded.
    """
    trace = audit_record.trace
    human_review = dict(audit_record.human_review or {})
    decision = human_review.get("decision")

    if decision == "REJECT":
        with transaction.atomic():
            audit_record.user_response = {"content": de.SAFE_BLOCK_MESSAGE, "disclosure_notice": None}
            audit_record.save(update_fields=["user_response"])
            trace.status = Trace.STATUS_CLOSED
            trace.closed_at = timezone.now()
            trace.save(update_fields=["status", "closed_at"])
        return {
            "final_action": "HUMAN_REVIEW",
            "user_response": de.SAFE_BLOCK_MESSAGE,
            "disclosure_notice": None,
            "audit_record": audit_record,
        }

    # APPROVE — resume with the same pseudonymised prompt/token map Phase
    # A already computed and persisted onto pre_request; recompute
    # routing/session state fresh rather than trusting anything that may
    # be stale by the time a reviewer gets to this.
    pre_request = audit_record.pre_request or {}
    pseudonymized_prompt = pre_request.get("pseudonymized_prompt") or trace.raw_prompt
    token_map = pre_request.get("token_map") or {}
    routing = mp.select_model(pre_request.get("complexity_score", 0), pre_request.get("risk_score", 0))
    pii_context = {
        "pii_detected": pre_request.get("pii_detected_in_prompt", False),
        "pii_categories": pre_request.get("pii_categories", []),
    }

    policy_config = pe.load_policy_config()
    fresh_session_state = _load_session_state(trace.session_id)

    phase_b = _run_generation_and_response_audit(
        pseudonymized_prompt, policy_config, fresh_session_state,
        policy_config.get("session_risk_threshold", 5.0), pii_context, token_map, routing,
    )

    human_review["final_user_response"] = phase_b["user_response_content"]
    with transaction.atomic():
        audit_record.human_review = human_review
        audit_record.response_metrics = phase_b["response_metrics"]
        audit_record.audit_quality = phase_b["audit_quality"]
        audit_record.audit_responsibility = phase_b["audit_responsibility"]
        audit_record.composite_risk_score = phase_b["composite_risk_score"]
        audit_record.auditor_model = phase_b["auditor_model"]
        audit_record.recommended_action = phase_b["recommended_action"]
        audit_record.policy_rules_evaluated = phase_b["policy_rules_evaluated"]
        audit_record.policy_rules_triggered = phase_b["policy_rules_triggered"]
        audit_record.modification = phase_b["modification"]
        audit_record.verify_warnings = phase_b["verify_warnings"]
        # This request's response was actually generated/audited under
        # THIS session state, not whatever was true back when the prompt
        # was first queued — session_state_snapshot documents "at the
        # time of this request", which for a resumed request means now.
        audit_record.session_state_snapshot = fresh_session_state
        audit_record.user_response = {
            "content": phase_b["user_response_content"],
            "disclosure_notice": phase_b["disclosure_notice"],
        }
        audit_record.save(update_fields=[
            "human_review", "response_metrics", "audit_quality", "audit_responsibility",
            "composite_risk_score", "auditor_model", "recommended_action",
            "policy_rules_evaluated", "policy_rules_triggered", "modification",
            "verify_warnings", "session_state_snapshot", "user_response",
        ])
        trace.status = Trace.STATUS_CLOSED
        trace.closed_at = timezone.now()
        trace.save(update_fields=["status", "closed_at"])

    return {
        "final_action": "HUMAN_REVIEW",
        "user_response": phase_b["user_response_content"],
        "disclosure_notice": phase_b["disclosure_notice"],
        "audit_record": audit_record,
    }
