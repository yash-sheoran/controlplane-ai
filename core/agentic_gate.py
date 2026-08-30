"""Section 6.2 — Agentic Pipeline Protection.

A pre-action gate for AI agents that take actions (not just generate
text): before executing any tool call or external action, the system
audits the intended action description as if it were a response, and
holds high-risk actions for human confirmation. Also implements action
rollback tagging.

Standalone, independently tested module — reuses core.auditing_engine's
already-built auditor rather than duplicating it, consistent with every
other pipeline module in this project.
"""

from . import auditing_engine as ae

# Section 6.2: "Actions with safety_risk >= 7 or policy_violation_risk >=
# 6 are held for human confirmation before execution." These are fixed
# thresholds stated directly in this section, not the per-use-case
# configurable thresholds from Section 5/3 Step 8 — the doc does not
# qualify this rule by use case.
SAFETY_RISK_HOLD_THRESHOLD = 7
POLICY_VIOLATION_RISK_HOLD_THRESHOLD = 6


def gate_agent_action(action_description):
    """Section 6.2: "Before executing any tool call or external action,
    the system audits the intended action description as if it were a
    response." Reuses core.auditing_engine.run_auditing_engine, passing
    the action description in the same slot a generated response would
    occupy.

    Returns a dict: held_for_confirmation (bool), reason (str), audit
    (the full auditing-engine result), and action_log_entry — "Every
    agent action is logged with its audit score, enabling post-hoc
    reconstruction of the full decision chain."
    """
    audit_result = ae.run_auditing_engine(
        original_prompt="[agentic pre-action audit]",
        ai_response=action_description,
    )

    held = False
    reasons = []

    if audit_result["validation_passed"]:
        scores = audit_result["scores"]
        safety_risk = scores["safety_risk_score"]
        policy_violation_risk = scores["policy_violation_risk_score"]
        if safety_risk >= SAFETY_RISK_HOLD_THRESHOLD:
            held = True
            reasons.append(f"safety_risk {safety_risk} >= {SAFETY_RISK_HOLD_THRESHOLD}")
        if policy_violation_risk >= POLICY_VIOLATION_RISK_HOLD_THRESHOLD:
            held = True
            reasons.append(
                f"policy_violation_risk {policy_violation_risk} >= {POLICY_VIOLATION_RISK_HOLD_THRESHOLD}"
            )
    else:
        # Section 3 Step 7: two consecutive auditor failures default to
        # HUMAN_REVIEW rather than silently proceeding. The same
        # conservative principle applies here: an action whose risk
        # could not be assessed is held, never auto-approved.
        held = True
        reasons.append("Auditor failed validation twice; action held pending manual review.")

    action_log_entry = {
        "action_description": action_description,
        "audit_score": audit_result.get("scores"),
        "held_for_confirmation": held,
        "rollback_recommended": False,
        "rollback_reason": None,
    }

    return {
        "held_for_confirmation": held,
        "reason": "; ".join(reasons) if reasons else "No hold conditions met.",
        "audit": audit_result,
        "action_log_entry": action_log_entry,
    }


def tag_for_rollback(action_log_entry, reason):
    """Section 6.2: "The system supports action rollback tagging: if a
    downstream action is later found to have been triggered by a
    hallucinated or biased output, the rollback_recommended flag is set
    in the audit log." Returns an updated copy — does not mutate the
    input."""
    updated = dict(action_log_entry)
    updated["rollback_recommended"] = True
    updated["rollback_reason"] = reason
    return updated
