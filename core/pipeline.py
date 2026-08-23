"""Full pipeline wiring (this project's plan, Step 10).

Composes every previously standalone module into the actual request flow
for an already-ingested Trace (Section 3 Step 1, core.views.create_request):
pre-request analysis (Step 2) -> model router + execution + metrics
(Steps 3-5) -> auditing engine (Step 6) -> policy engine with session-risk
escalation (Step 8, Section 6.1) -> decision executor (Step 9), with
Section 8's regulation library applied throughout, persisting the full
AuditRecord / Trace / SessionState in MySQL.
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


def _save_session_state(session_id, use_case, state):
    SessionState.objects.update_or_create(
        session_id=session_id,
        defaults={
            "use_case": use_case,
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


def _run_single_attempt(model_id, prompt, use_case, timeout_s, max_retries, policy_config, pii_context):
    """One full generate + audit + policy-check attempt (Steps 3-5, then
    6). Raises model_pipeline.ModelExecutionError if the model call fails
    on every attempt."""
    response, elapsed_ms, retry_count = mp.execute_with_retry(
        model_id, prompt, timeout_s=timeout_s, max_retries=max_retries,
    )
    metrics = mp.collect_metrics(response, elapsed_ms, retry_count)

    audit_result = ae.run_auditing_engine(
        original_prompt=prompt, ai_response=response["text"],
        use_case_profile=use_case.use_case_id, pre_request_flags=pii_context,
    )

    if not audit_result["validation_passed"]:
        # core.auditing_engine.run_auditing_engine already defaults to
        # HUMAN_REVIEW itself after two failed attempts; the policy
        # engine is not consulted on scores that don't exist.
        policy_result = {
            "final_action": "HUMAN_REVIEW",
            "rules_evaluated": [],
            "rules_triggered": [],
            "reason": "Auditor failed validation twice; defaulting to HUMAN_REVIEW.",
        }
    else:
        policy_result = pe.evaluate_policy(policy_config, audit_result["scores"], context=pii_context)

    return {
        "response_text": response["text"],
        "metrics": metrics,
        "audit_result": audit_result,
        "policy_result": policy_result,
        "final_action": policy_result["final_action"],
    }


def _dispatch(attempt, final_action, token_map):
    if final_action == "ALLOW":
        return de.execute_allow(attempt["response_text"], token_map)
    if final_action == "MODIFY":
        return de.execute_modify(attempt["response_text"])
    if final_action == "HUMAN_REVIEW":
        redacted, _ = de.redact_pii(attempt["response_text"] or "")
        return de.execute_human_review(
            audit_json=attempt["audit_result"].get("scores") or {},
            raw_response=attempt["response_text"],
            redacted_response=redacted,
            policy_trigger_reason=attempt["policy_result"]["reason"],
        )
    if final_action == "BLOCK":
        return de.execute_block(attempt["policy_result"]["reason"])
    raise ValueError(f"Unexpected final_action {final_action!r}")


def _run_pipeline_attempts(model_id, prompt, use_case, timeout_s, max_retries, policy_config,
                            pii_context, token_map):
    """Runs the initial attempt, and — only if it comes back VERIFY —
    hands off to core.decision_executor.execute_verify_retry for the
    re-generate-with-escalation flow (Section 3 Step 9 VERIFY/RETRY),
    with a real attempt_fn that re-runs Steps 3-6 rather than a mock.

    Returns (final_attempt, exec_result, final_action).
    """
    attempt = _run_single_attempt(model_id, prompt, use_case, timeout_s, max_retries, policy_config, pii_context)
    final_action = attempt["final_action"]

    if final_action != "VERIFY":
        return attempt, _dispatch(attempt, final_action, token_map), final_action

    last_attempt = {"value": attempt}

    def attempt_fn(retry_model_id, enhanced_prompt):
        retry_attempt = _run_single_attempt(
            retry_model_id, prompt, use_case, timeout_s, max_retries, policy_config, pii_context,
        )
        last_attempt["value"] = retry_attempt
        redacted, _ = de.redact_pii(retry_attempt["response_text"] or "")
        return {
            "final_action": retry_attempt["final_action"],
            "response_text": retry_attempt["response_text"],
            "token_map": token_map,
            "audit_json": retry_attempt["audit_result"].get("scores") or {},
            "redacted_response": redacted,
            "policy_trigger_reason": retry_attempt["policy_result"]["reason"],
        }

    exec_result = de.execute_verify_retry(attempt_fn, initial_model_id=model_id, max_retries=max_retries)
    return last_attempt["value"], exec_result, exec_result["final_decision"]


def process_request(trace):
    """Runs the complete pipeline for one already-ingested Trace and
    persists the full AuditRecord, updated Trace, and updated
    SessionState. Returns a dict: final_action, user_response,
    disclosure_notice, audit_record.
    """
    use_case = trace.use_case
    policy_config = pe.load_policy_config(use_case.use_case_id)
    session_risk_threshold = policy_config.get("session_risk_threshold", 5.0)
    session_risk_window = policy_config.get("session_risk_window", sr.DEFAULT_SESSION_RISK_WINDOW)

    session_state = _load_session_state(trace.session_id)
    effective_policy_config = sr.get_effective_policy_config(
        policy_config, session_state, session_risk_threshold,
    )

    # Section 8 — Regulatory & Geography-Aware Compliance Module.
    compliance_metadata = rl.build_compliance_metadata(
        use_case.regulations, use_case.eu_ai_act_high_risk, use_case.audit_retention_days,
    )

    # Section 3 Step 2 — Pre-Request Analysis.
    pii_result = pra.detect_and_pseudonymize_pii(trace.raw_prompt)
    complexity = pra.complexity_score(trace.raw_prompt)
    risk = pra.risk_score(trace.raw_prompt, pii_detected=pii_result["pii_detected"])
    pii_context = {"pii_detected": pii_result["pii_detected"], "pii_categories": pii_result["pii_categories"]}
    pseudonymized_prompt = pii_result["pseudonymized_text"] or trace.raw_prompt

    pre_request_data = {
        "complexity_score": complexity,
        "risk_score": risk,
        "pii_detected_in_prompt": pii_result["pii_detected"],
        "pii_categories": pii_result["pii_categories"],
        "pseudonymisation_applied": pii_result["pii_detected"],
    }

    # Section 3 Step 3 — Model Router.
    routing = mp.select_model(complexity, risk)

    common_kwargs = dict(
        trace=trace,
        geography=use_case.geography,
        regulation_versions=compliance_metadata["regulation_versions"],
        compliance_metadata=compliance_metadata,
        pre_request=pre_request_data,
        model_routing=routing,
        policy_profile_version=f"{use_case.use_case_id}-policy",
        session_state_snapshot=session_state,
    )

    if routing["blocked"]:
        # Section 3 Step 3: "Risk 9-10 -> Route to BLOCK pre-check before
        # model call; may not proceed." No model call, no audit.
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
    else:
        timeout_s = policy_config["latency_budget_ms"] / 1000
        max_retries = policy_config["max_retries"]

        try:
            final_attempt, exec_result, final_action = _run_pipeline_attempts(
                routing["model"], pseudonymized_prompt, use_case, timeout_s, max_retries,
                effective_policy_config, pii_context, pii_result["token_map"],
            )
        except mp.ModelExecutionError as exc:
            # Section 3 Step 7's "prevent silent failures" principle,
            # applied to a total model-execution failure: there is no
            # response to show or audit, so this defaults to HUMAN_REVIEW
            # rather than silently dropping the request.
            final_action = "HUMAN_REVIEW"
            final_attempt = {
                "metrics": {}, "audit_result": {"scores": None, "composite_risk_score": None,
                                                 "auditor_model": None, "recommended_action": None},
                "policy_result": {"rules_evaluated": [], "rules_triggered": [],
                                   "reason": f"Model execution failed after exhausting retries: {exc}"},
            }
            exec_result = de.execute_human_review(
                audit_json={}, raw_response=None, redacted_response=None,
                policy_trigger_reason=final_attempt["policy_result"]["reason"],
            )

        quality, responsibility = _split_scores(final_attempt["audit_result"].get("scores"))
        human_review_status = "PENDING" if final_action == "HUMAN_REVIEW" else None

        with transaction.atomic():
            audit_record = AuditRecord.objects.create(
                **common_kwargs,
                response_metrics=final_attempt["metrics"],
                audit_quality=quality,
                audit_responsibility=responsibility,
                composite_risk_score=final_attempt["audit_result"].get("composite_risk_score"),
                auditor_model=final_attempt["audit_result"].get("auditor_model") or "",
                recommended_action=final_attempt["audit_result"].get("recommended_action"),
                policy_rules_evaluated=final_attempt["policy_result"].get("rules_evaluated", []),
                policy_rules_triggered=final_attempt["policy_result"].get("rules_triggered", []),
                final_action=final_action,
                modification=exec_result.get("modification_log") if final_action == "MODIFY" else None,
                human_review=exec_result.get("queued_case") if final_action == "HUMAN_REVIEW" else None,
                human_review_status=human_review_status,
                user_response={
                    "content": exec_result.get("user_response"),
                    "disclosure_notice": exec_result.get("disclosure_notice"),
                },
            )

    # Section 6.1 — update the session's rolling risk accumulator for
    # subsequent turns, using this turn's pre-request risk score.
    updated_session_state = sr.update_session_risk_accumulator(
        session_state, turn_risk_score=risk, turn_decision=final_action,
        window_size=session_risk_window,
    )
    _save_session_state(trace.session_id, use_case, updated_session_state)

    trace.status = Trace.STATUS_CLOSED
    trace.final_decision = final_action
    trace.closed_at = timezone.now()
    trace.save(update_fields=["status", "final_decision", "closed_at"])

    return {
        "final_action": final_action,
        "user_response": exec_result.get("user_response"),
        "disclosure_notice": exec_result.get("disclosure_notice"),
        "audit_record": audit_record,
    }
