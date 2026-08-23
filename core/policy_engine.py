"""Section 3 Step 8 — Policy Engine, Section 5 — Policy Engine
(Configurable Governance Layer), Section 4.1 — Composite Risk Score.

Deterministic, per-use-case threshold rules loaded from YAML policy
files, evaluated in the doc's fixed priority order: BLOCK, then
HUMAN_REVIEW, then MODIFY, then VERIFY, else ALLOW.

Independently unit-tested and, since this project's Step 10, composed
live in core/pipeline.py, which dispatches its final_action to
core/decision_executor.py.
"""

from pathlib import Path

import yaml

_POLICIES_DIR = Path(__file__).resolve().parent / "config" / "policies"

# Section 3 Step 8's fixed evaluation order, and Section 14.1's own naming
# for the "rules_evaluated" list ("BLOCK_CHECK", "HUMAN_REVIEW_CHECK",
# "MODIFY_CHECK", "VERIFY_CHECK").
RULE_ORDER = ["block", "human_review", "modify", "verify"]
_BUCKET_TO_ACTION = {
    "block": "BLOCK",
    "human_review": "HUMAN_REVIEW",
    "modify": "MODIFY",
    "verify": "VERIFY",
}

# Section 4's per-dimension scoring direction, taken from each dimension's
# own description (not just its category column):
#   - Quality dimensions score higher = better: Correctness ("Low =
#     incorrect claims"), Relevance ("Low = off-topic"), Completeness
#     ("Low = missing key components"), Instruction Following,
#     Consistency. A threshold is breached when the score is AT OR BELOW
#     the threshold.
#   - Hallucination Risk is grouped under the "Quality" track for AUDIT
#     EXECUTION purposes (Section 2.2 Decision 2's Track A), but its own
#     description ("High = dangerous") makes clear it scores like a risk
#     dimension, not like the other Quality dimensions.
#   - All Safety/Policy dimensions score higher = more dangerous. A
#     threshold is breached when the score is AT OR ABOVE the threshold.
# This is confirmed directly by Section 3 Step 8's own examples:
# "data_leakage_risk >= 9", "safety_risk >= 8" (higher-is-worse, >=), and
# "hallucination_risk >= 7 OR correctness <= 4" (hallucination_risk
# higher-is-worse >=; correctness higher-is-better <=).
HIGHER_IS_WORSE = {
    "hallucination_risk", "safety_risk", "bias_risk", "toxicity_risk",
    "data_leakage_risk", "policy_violation_risk", "prompt_injection_risk",
}
HIGHER_IS_BETTER = {
    "correctness", "relevance", "completeness", "instruction_following", "consistency",
}


def load_policy_config(use_case_id):
    """Section 3 Step 8 callout / Section 5.1: "All threshold values are
    stored in a per-use-case YAML policy file. Changing a threshold
    requires no code deployment — only a config reload." Reads fresh on
    every call (no in-process caching) so an edit to the file takes
    effect without restarting the app."""
    path = _POLICIES_DIR / f"{use_case_id}.yaml"
    with open(path, "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


def _dimension_breaches_threshold(dimension, threshold_value, scores):
    score = scores.get(f"{dimension}_score")
    if score is None:
        return False
    if dimension in HIGHER_IS_WORSE:
        return score >= threshold_value
    if dimension in HIGHER_IS_BETTER:
        return score <= threshold_value
    return False


def _bucket_fires(bucket, scores, context):
    """A threshold bucket (e.g. thresholds['block']) fires if ANY of its
    listed conditions is breached — Section 3 Step 8's own examples never
    combine more than one score condition within a single bucket with
    AND; Section 5.1's "modify: { data_leakage_risk: 5, pii_detected:
    true }" groups two independent trigger conditions the same way an
    ALLOW/VERIFY-style rule set conventionally does. Returns
    (fired: bool, triggering_key: str|None)."""
    for key, threshold_value in bucket.items():
        if key == "pii_detected":
            if bool(threshold_value) and bool(context.get("pii_detected", False)):
                return True, key
            continue
        if key in HIGHER_IS_WORSE or key in HIGHER_IS_BETTER:
            if _dimension_breaches_threshold(key, threshold_value, scores):
                return True, key
        # Any other, undocumented key is ignored rather than guessed at.
    return False, None


def evaluate_policy(policy_config, scores, context=None):
    """Section 3 Step 8 — Policy Engine. Evaluates BLOCK, then
    HUMAN_REVIEW, then MODIFY, then VERIFY thresholds in that fixed
    priority order; if none fire, the result is ALLOW.

    `scores` is the auditing engine's own validated output shape (Section
    3 Step 6/7): a dict of "{dimension}_score" / "{dimension}_reason"
    keys. `context` carries auxiliary pre-request flags such as
    pii_detected (Section 3 Step 2, 2A), which is not one of the 12 audit
    dimensions.

    Per Section 4.1: "Policy decisions are always made on individual
    dimension scores — not the composite — to prevent gaming." This
    function never reads a "composite_risk_score" key even if one is
    present in `scores`; only the 12 individual dimension scores (via
    HIGHER_IS_WORSE / HIGHER_IS_BETTER) and the pii_detected context flag
    can ever affect the returned final_action.

    Returns a dict: final_action, rules_evaluated, rules_triggered, reason.
    """
    context = context or {}
    thresholds = policy_config.get("thresholds", {})

    rules_evaluated = []
    for bucket_name in RULE_ORDER:
        rules_evaluated.append(f"{bucket_name.upper()}_CHECK")
        bucket = thresholds.get(bucket_name, {}) or {}
        fired, triggering_key = _bucket_fires(bucket, scores, context)
        if fired:
            return {
                "final_action": _BUCKET_TO_ACTION[bucket_name],
                "rules_evaluated": rules_evaluated,
                "rules_triggered": [f"{bucket_name.upper()}_CHECK:{triggering_key}"],
                "reason": f"{bucket_name} threshold breached on '{triggering_key}'.",
            }

    return {
        "final_action": "ALLOW",
        "rules_evaluated": rules_evaluated,
        "rules_triggered": [],
        "reason": "No policy thresholds breached.",
    }
