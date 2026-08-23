"""Section 6.1 — Compounding Risk Tracking.

session_risk_accumulator: a rolling average of risk scores across the
last N turns, a count of VERIFY/MODIFY/HUMAN_REVIEW decisions, and a flag
for whether any previous turn was BLOCKED. When the accumulator crosses a
configurable threshold, subsequent turns get a stricter policy profile.

Standalone, independently tested module, consistent with the other
pipeline modules: it operates on a plain dict shaped like the
core.models.SessionState model rather than the model instance itself, so
it has no DB dependency and no side effects. A future integration step is
responsible for loading a SessionState row into this shape, calling these
functions, and persisting the result back.
"""

import copy

from . import policy_engine as pe

# Section 6.1: "Rolling average of risk scores across the last N turns
# (configurable, default N = 5)."
DEFAULT_SESSION_RISK_WINDOW = 5


def update_session_risk_accumulator(session_state, turn_risk_score, turn_decision,
                                     window_size=DEFAULT_SESSION_RISK_WINDOW):
    """Section 6.1: updates a session's compounding-risk state for one
    new turn. `session_state` is a dict shaped like core.models.
    SessionState (turn_number, session_risk_accumulator,
    recent_risk_scores, verify_count, modify_count, human_review_count,
    was_blocked, previous_decisions). Returns a new, updated dict —
    does not mutate the input.
    """
    updated = dict(session_state)

    recent_risk_scores = list(updated.get("recent_risk_scores", []))
    recent_risk_scores.append(turn_risk_score)
    recent_risk_scores = recent_risk_scores[-window_size:]
    updated["recent_risk_scores"] = recent_risk_scores
    updated["session_risk_accumulator"] = sum(recent_risk_scores) / len(recent_risk_scores)

    updated["turn_number"] = updated.get("turn_number", 0) + 1

    # Section 6.1: "Count of VERIFY, MODIFY, and HUMAN_REVIEW decisions in
    # the current session." / "Flag if any previous turn in the session
    # was BLOCKED." Once set, was_blocked is never cleared by a later turn.
    if turn_decision == "VERIFY":
        updated["verify_count"] = updated.get("verify_count", 0) + 1
    elif turn_decision == "MODIFY":
        updated["modify_count"] = updated.get("modify_count", 0) + 1
    elif turn_decision == "HUMAN_REVIEW":
        updated["human_review_count"] = updated.get("human_review_count", 0) + 1
    elif turn_decision == "BLOCK":
        updated["was_blocked"] = True
    updated.setdefault("was_blocked", False)

    previous_decisions = list(updated.get("previous_decisions", []))
    previous_decisions.append(turn_decision)
    updated["previous_decisions"] = previous_decisions

    return updated


def is_escalated(session_state, session_risk_threshold):
    """Section 6.1: "When the session_risk_accumulator crosses a
    configurable threshold, the system escalates the strictness of the
    policy profile for subsequent turns."""
    return session_state.get("session_risk_accumulator", 0) >= session_risk_threshold


def escalate_policy_config(policy_config, escalation_step=1):
    """Section 6.1: "the system escalates the strictness of the policy
    profile for subsequent turns without requiring individual turn scores
    to be high." Tightens every numeric per-dimension threshold in each
    bucket (block/human_review/modify/verify) by escalation_step points,
    in whichever direction makes it fire more easily — using Section 4's
    own per-dimension direction table (core.policy_engine.HIGHER_IS_WORSE
    / HIGHER_IS_BETTER), already established in Section 3 Step 8's
    implementation: lower for higher-is-worse dimensions, higher for
    higher-is-better ones. Values are clamped to the valid [1,10] score
    range. Boolean flag thresholds (e.g. pii_detected) are left
    unchanged — they have no numeric "stricter" direction.
    """
    escalated = copy.deepcopy(policy_config)
    thresholds = escalated.get("thresholds", {})
    for bucket in thresholds.values():
        if not isinstance(bucket, dict):
            continue
        for key, value in list(bucket.items()):
            if isinstance(value, bool):
                continue
            if key in pe.HIGHER_IS_WORSE:
                bucket[key] = max(1, value - escalation_step)
            elif key in pe.HIGHER_IS_BETTER:
                bucket[key] = min(10, value + escalation_step)
    return escalated


def get_effective_policy_config(policy_config, session_state, session_risk_threshold,
                                 escalation_step=1):
    """Returns the escalated policy config when the session's
    accumulator has crossed session_risk_threshold, otherwise the
    original config unchanged."""
    if is_escalated(session_state, session_risk_threshold):
        return escalate_policy_config(policy_config, escalation_step)
    return policy_config
