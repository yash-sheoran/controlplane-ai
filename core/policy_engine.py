"""Section 3 Step 8 — Policy Engine, Section 5 — Policy Engine
(Configurable Governance Layer), Section 4.1 — Composite Risk Score.

Deterministic threshold rules loaded from a single YAML policy file
(core/config/policy.yaml), evaluated in the doc's fixed priority order:
BLOCK, then HUMAN_REVIEW, then MODIFY, then VERIFY, else ALLOW.

Independently unit-tested and, since this project's Step 10, composed
live in core/pipeline.py, which dispatches its final_action to
core/decision_executor.py.
"""

import json
from pathlib import Path

import yaml

_POLICY_PATH = Path(__file__).resolve().parent / "config" / "policy.yaml"
_COMPANY_POLICY_PATH = Path(__file__).resolve().parent / "config" / "company_policy.json"

# Product decision: Human Review is decided ONLY by the prompt-time policy
# audit (see evaluate_prompt_policy / core.auditing_engine.run_prompt_
# policy_audit), never by the response-side audit below — so "human_review"
# is deliberately NOT one of these stages any more. It used to be (between
# "block" and "modify"); the bucket of the same name still exists in
# core/config/policy.yaml, but is now consulted only by
# evaluate_verify_warnings, never for routing here.
RULE_ORDER = ["block", "modify", "verify"]
_BUCKET_TO_ACTION = {
    "block": "BLOCK",
    "modify": "MODIFY",
    "verify": "VERIFY",
}

# Section 4's per-dimension warning phrasing for evaluate_verify_warnings,
# shown alongside a delivered response — never gates delivery, unlike
# RULE_ORDER above. Phrasing for hallucination_risk/bias_risk quotes the
# product decision's own example wording verbatim.
_VERIFY_WARNING_MESSAGES = {
    "hallucination_risk": "This response may contain hallucinated information.",
    "bias_risk": "Potential bias detected in this response.",
    "toxicity_risk": "This response may contain toxic or inappropriate content.",
    "safety_risk": "This response may raise safety concerns.",
    "data_leakage_risk": "This response may contain sensitive information.",
    "policy_violation_risk": "This response may not comply with policy.",
    "prompt_injection_risk": "This response may reflect a prompt-injection attempt.",
    "correctness": "This response may contain factual inaccuracies.",
    "relevance": "This response may not fully address your prompt.",
    "completeness": "This response may be missing key information.",
    "instruction_following": "This response may not fully follow your instructions.",
    "consistency": "This response may be internally inconsistent.",
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


def load_policy_config():
    """Section 3 Step 8 callout / Section 5.1: "Changing a threshold
    requires no code deployment — only a config reload." Reads fresh on
    every call (no in-process caching) so an edit to the file takes
    effect without restarting the app.

    One single, permanent policy for the whole system (core/config/
    policy.yaml) — this used to be per-use-case (a use_case_id parameter
    selected one of three YAML files), but "use case" was removed
    entirely as a product decision; see that file's own header note."""
    with open(_POLICY_PATH, "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


def load_company_policy():
    """The new prompt-time Human Review policy: one company-wide JSON
    file (not per-use-case, unlike load_policy_config above), naming the
    topics/categories that require human review before generation. Same
    "no code deployment, only a config reload" principle as
    load_policy_config: read fresh from disk on every call so an operator
    edit takes effect immediately."""
    with open(_COMPANY_POLICY_PATH, "r", encoding="utf-8") as config_file:
        return json.load(config_file)


def dimension_violation_threshold(policy_config, dimension):
    """The most sensitive (most inclusive) threshold configured for
    `dimension` across every bucket in this policy config — i.e. the
    value that would flag the widest range of scores as a "violation"
    for that dimension, independent of which bucket (if any) actually
    fired first for a given request (evaluate_policy stops at the first
    bucket that fires, so a dimension configured in more than one bucket,
    e.g. data_leakage_risk in both block and modify, never gets checked
    against its OTHER bucket's threshold for a request some earlier
    bucket already claimed).

    Used by core.dashboard's Trends-page "violation rate" metrics
    (safety_violation_rate, bias_detection_rate, data_leakage_attempts)
    so each request is judged against its own use case's real, configured
    policy thresholds rather than one flat constant applied regardless of
    use case.

    Returns None if this dimension isn't configured in any bucket for
    this use case (nothing to compare the score against).
    """
    thresholds = policy_config.get("thresholds", {})
    values = [bucket[dimension] for bucket in thresholds.values() if dimension in bucket]
    if not values:
        return None
    if dimension in HIGHER_IS_WORSE:
        return min(values)
    if dimension in HIGHER_IS_BETTER:
        return max(values)
    return None


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
    """Section 3 Step 8 — Policy Engine, response side. Evaluates BLOCK,
    then MODIFY, then VERIFY thresholds in that fixed priority order; if
    none fire, the result is ALLOW. Deliberately cannot return
    HUMAN_REVIEW: per product decision, only the prompt-time policy audit
    (evaluate_prompt_policy, run before generation) may ever queue a
    request for human review — see core.pipeline. A response-side concern
    that used to reach human_review at this stage now instead surfaces as
    a non-gating annotation via evaluate_verify_warnings below.

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


def evaluate_prompt_policy(company_policy, violated_category_keys):
    """Prompt-time Human Review policy. The prompt-auditor LLM
    (core.auditing_engine.run_prompt_policy_audit) only classifies WHICH
    company-policy categories a prompt matches; this function
    deterministically derives the actual decision from each matched
    category's own configured `action` — the same system-computes/
    AI-classifies split this codebase already uses between
    core.auditing_engine's recommended_action (stored for telemetry only)
    and evaluate_policy above (the only thing that actually gates a
    response). Category/custom-rule entries with enabled=false never
    contribute, even if named in violated_category_keys (defense in
    depth: the auditor's own response_schema should already exclude them
    from the valid enum).

    Priority: BLOCK beats HUMAN_REVIEW beats company_policy's own
    default_action — the same BLOCK-before-HUMAN_REVIEW precedence
    RULE_ORDER already applies on the response side.

    Returns final_action (str).
    """
    categories = company_policy.get("human_review_policy", {}).get("categories", {}) or {}
    actions = {key: cat["action"] for key, cat in categories.items() if cat.get("enabled")}
    for rule in company_policy.get("custom_rules", []) or []:
        if rule.get("enabled"):
            actions[rule["name"]] = rule["action"]

    triggered_actions = [actions[key] for key in violated_category_keys if key in actions]
    if "BLOCK" in triggered_actions:
        return "BLOCK"
    if "HUMAN_REVIEW" in triggered_actions:
        return "HUMAN_REVIEW"
    return company_policy.get("default_action", "ALLOW")


def evaluate_verify_warnings(policy_config, scores):
    """Non-gating response-side annotation, run alongside (never instead
    of) evaluate_policy. Collects EVERY breached dimension across the
    verify_warning bucket (response-routing-inert; see RULE_ORDER's
    comment above) and the verify bucket's quality dimensions — unlike
    evaluate_policy, which stops at the first bucket that fires, this
    collects ALL breaches at once, since more than one warning can
    legitimately apply to the same response simultaneously. Never
    affects final_action.

    Returns a list of {"dimension", "score", "message"} dicts.
    """
    thresholds = policy_config.get("thresholds", {})
    warnings = []
    seen = set()
    for bucket_name in ("verify_warning", "verify"):
        bucket = thresholds.get(bucket_name, {}) or {}
        for dimension, threshold_value in bucket.items():
            if dimension in seen or dimension not in (HIGHER_IS_WORSE | HIGHER_IS_BETTER):
                continue
            if _dimension_breaches_threshold(dimension, threshold_value, scores):
                seen.add(dimension)
                warnings.append({
                    "dimension": dimension,
                    "score": scores.get(f"{dimension}_score"),
                    "message": _VERIFY_WARNING_MESSAGES.get(
                        dimension, f"This response may have a concern with {dimension.replace('_', ' ')}."
                    ),
                })
    return warnings


def most_severe_verify_warning(warnings):
    """The Playground only ever shows ONE Verify warning per turn, not
    the full list evaluate_verify_warnings can return — several
    simultaneous ⚠️ badges on one response reads as noise, not signal.
    This picks the single most severe entry: for a scored dimension,
    severity is how bad its score is on a common 1-10 "worse" scale —
    HIGHER_IS_WORSE dimensions use the score directly, HIGHER_IS_BETTER
    dimensions use 11 - score, so e.g. a correctness of 1 ranks exactly
    as severe as a hallucination_risk of 10. The synthetic
    "retry_exhausted" entry (core.decision_executor.execute_verify_
    retry's exhaustion tail) has no score of its own, so it only wins
    when it is the only warning present.

    The FULL list is still computed and stored on AuditRecord.
    verify_warnings unabridged, for audit/trend purposes — only display
    is narrowed, via this function, not the underlying data.

    Returns the single most severe dict, or None if `warnings` is empty.
    """
    if not warnings:
        return None

    def severity(warning):
        score = warning.get("score")
        if score is None:
            return -1
        dimension = warning["dimension"]
        if dimension in HIGHER_IS_WORSE:
            return score
        if dimension in HIGHER_IS_BETTER:
            return 11 - score
        return 0

    return max(warnings, key=severity)
