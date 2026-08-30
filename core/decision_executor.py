"""Section 3 Step 9 — Decision Execution.

Implements all five decision paths: ALLOW, VERIFY/RETRY, MODIFY,
HUMAN_REVIEW, BLOCK.

Independently unit-tested and, since this project's Step 10, composed
live in core/pipeline.py. The queryable human-review queue and reviewer
UI live in core/dashboard_views.py (Step 9), which persists this
module's queued_case dict into AuditRecord.human_review.
"""

from cryptography.fernet import Fernet
from django.conf import settings
from django.utils import timezone

from . import model_pipeline
from . import pre_request_analysis as pra

# ---------------------------------------------------------------------------
# ALLOW
# ---------------------------------------------------------------------------


def execute_allow(response_text, token_map=None):
    """Section 3 Step 9 ALLOW: "Response passes all thresholds. Original
    (or de-pseudonymised) response is returned to the user." Reuses
    Section 3 Step 2, 2A's own reversible token map (core.pre_request_
    analysis.depseudonymize) rather than reimplementing it."""
    final_text = response_text
    if token_map:
        final_text = pra.depseudonymize(response_text, token_map)
    return {
        "final_decision": "ALLOW",
        "user_response": final_text,
    }


# ---------------------------------------------------------------------------
# MODIFY
# ---------------------------------------------------------------------------

# Section 9 MODIFY's own example placeholders are "[REDACTED:EMAIL]" and
# "[REDACTED:NAME]" — note "NAME", not "PERSON" (the category name used by
# Section 14.1's pii_categories and by Section 3 Step 2, 2A's reversible
# pseudonymisation, which this project already implements faithfully as
# "PERSON" there). These are two different mechanisms with two different
# doc-given placeholder vocabularies; both are honoured literally in their
# own context rather than unified into one made-up shared vocabulary.
_REDACTION_CATEGORY_LABELS = {"PERSON": "NAME"}

# Not "...has been modified to remove..." — per the product decision in
# execute_modify below, nothing in the response is ever removed/altered
# anymore, so the notice must not claim otherwise.
DEFAULT_DISCLOSURE_NOTICE = (
    "This response was flagged during audit for containing potentially sensitive information."
)


def redact_pii(text):
    """Section 3 Step 9 MODIFY: "Applies regex + NER-based PII masking
    (e.g. '[REDACTED:EMAIL]', '[REDACTED:NAME]')." Reuses the same
    detection engine as Section 3 Step 2, 2A, producing irreversible
    [REDACTED:CATEGORY] placeholders instead of reversible [CATEGORY_N]
    pseudonymisation tokens.

    Returns (redacted_text, categories_redacted).
    """
    if not text:
        return text or "", []

    analyzer = pra._get_analyzer()
    raw_results = analyzer.analyze(text=text, language="en")
    entities = pra._resolve_overlaps(raw_results)

    categories_redacted = []
    pieces = []
    cursor = 0
    for entity in entities:
        pieces.append(text[cursor:entity.start])
        category = entity.entity_type
        label = _REDACTION_CATEGORY_LABELS.get(category, category)
        pieces.append(f"[REDACTED:{label}]")
        if category not in categories_redacted:
            categories_redacted.append(category)
        cursor = entity.end
    pieces.append(text[cursor:])
    return "".join(pieces), categories_redacted


def _get_fernet():
    key = settings.MODIFICATION_LOG_ENCRYPTION_KEY
    if not key:
        raise RuntimeError(
            "MODIFICATION_LOG_ENCRYPTION_KEY is not configured; see .env.example."
        )
    return Fernet(key.encode("ascii") if isinstance(key, str) else key)


def encrypt_original_content(text):
    """Section 3 Step 9 MODIFY: "Logs the original content (encrypted)
    ... to the audit log for compliance review." Returns an ASCII token
    safe to store in a text/JSON field."""
    fernet = _get_fernet()
    return fernet.encrypt((text or "").encode("utf-8")).decode("ascii")


def decrypt_original_content(token):
    """The inverse of encrypt_original_content, for compliance review
    access to the pre-redaction original."""
    fernet = _get_fernet()
    return fernet.decrypt(token.encode("ascii")).decode("utf-8")


def execute_modify(response_text, disclosure_notice=DEFAULT_DISCLOSURE_NOTICE):
    """Section 3 Step 9 MODIFY — per explicit product decision, this no
    longer redacts anything: an LLM-GENERATED reply is delivered to the
    user exactly as generated, PII and all. It is still audited (which
    PII categories, if any, are present — logged below for the
    compliance trail) but never altered or masked.

    This is a deliberate divergence from Section 3 Step 9's own MODIFY
    description ("Applies regex + NER-based PII masking"); the
    PROMPT-side pseudonymisation (Section 3 Step 2, 2A — PII the USER
    types is replaced with a reversible placeholder before the model
    ever sees it) is unaffected and still happens exactly as before —
    only this RESPONSE-side redaction has been removed.

    disclosure_notice still accompanies the response, so the user knows
    this reply was flagged during audit, even though its content is
    unchanged.
    """
    _, categories_detected = redact_pii(response_text)
    return {
        "final_decision": "MODIFY",
        "user_response": response_text,
        "disclosure_notice": disclosure_notice,
        "modification_log": {
            "categories_detected": categories_detected,
        },
    }


# ---------------------------------------------------------------------------
# HUMAN_REVIEW
#
# Per explicit product decision, Human Review is now decided ONLY by a
# prompt-time policy audit (core.auditing_engine.run_prompt_policy_audit +
# core.policy_engine.evaluate_prompt_policy), run before any generation
# call — never by anything response-driven. So, unlike the response-
# shaped queued case this replaced (which carried a raw/redacted response
# and full audit JSON because a response already existed by the time
# HUMAN_REVIEW could fire), a case queued here never has a response yet:
# the reviewer sees the prompt plus which company-policy categories it
# matched and why. Approving is what causes generation to happen for the
# very first time (core.pipeline.resume_after_prompt_review) — there is
# nothing yet for a reviewer to hand-edit, so REVIEWER_DECISIONS is
# binary (APPROVE/REJECT), unlike the old response-stage APPROVE/MODIFY/
# REJECT.
# ---------------------------------------------------------------------------

REVIEWER_DECISIONS = {"APPROVE", "REJECT"}


def execute_prompt_human_review(reason, violated_policies):
    """Section 3 Step 9 HUMAN_REVIEW, prompt-time variant: "The user is
    informed of a review delay... The reviewer receives... the policy
    trigger reason." Queues the case (to be persisted by the caller) and
    returns the message shown to the user while they wait — no response
    exists yet, so there is nothing to show them but that.
    """
    queued_case = {
        "status": "PENDING",
        "violated_policies": violated_policies,
        "policy_trigger_reason": reason,
        "reviewer_id": None,
        "decision": None,
        "decided_at": None,
        "final_user_response": None,
    }
    return {
        "final_decision": "HUMAN_REVIEW",
        "user_response": (
            "Your request requires approval before it can be processed. "
            "You'll see the response here once it's reviewed."
        ),
        "queued_case": queued_case,
    }


def apply_prompt_review_decision(queued_case, decision, reviewer_id, decided_at=None):
    """Section 3 Step 9 HUMAN_REVIEW, prompt-time variant: "All reviewer
    actions are timestamped and attributed."

    - APPROVE: signals the caller (core.pipeline.resume_after_prompt_
      review) to now run generation for the first time; final_user_
      response is filled in by that caller once it has a real response,
      not by this pure function.
    - REJECT: nothing is ever generated; the same safe, generic message
      BLOCK uses is shown, applying that section's explicit principle
      (never reveal internal reasoning to the user) to this analogous
      case, which the doc does not spell out a separate message for.
    """
    if decision not in REVIEWER_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(REVIEWER_DECISIONS)}, got {decision!r}")
    if decided_at is None:
        decided_at = timezone.now()

    updated_case = dict(queued_case)
    updated_case.update({
        "status": "DECIDED",
        "decision": decision,
        "reviewer_id": reviewer_id,
        "decided_at": decided_at,
        "final_user_response": None if decision == "APPROVE" else SAFE_BLOCK_MESSAGE,
    })
    return updated_case


# ---------------------------------------------------------------------------
# BLOCK
# ---------------------------------------------------------------------------

# Quoted verbatim from Section 3 Step 9 BLOCK's own example.
SAFE_BLOCK_MESSAGE = "This response cannot be provided as it may contain sensitive information."

# Shown whenever a live model call (generation, risk analysis, or
# auditing) fails on every attempt — most likely a free-tier rate limit
# or a timeout — rather than a raw exception string or a silent, endless
# wait. Used by core.dashboard_views for both the synchronous Playground
# submit path and the manager-approval resume path.
SAFE_GENERATION_UNAVAILABLE_MESSAGE = (
    "This response could not be generated because the AI service is "
    "temporarily unavailable — it may have hit a rate limit or timed out. "
    "Please try again in a moment."
)


def execute_block(internal_reason):
    """Section 3 Step 9 BLOCK: "The original response is not returned...
    The block reason shown to the user does NOT reveal internal
    thresholds or scoring rules — only a generic explanation... The full
    block reason is logged in the audit trail accessible only to
    administrators."

    This function guarantees user_response never contains
    internal_reason, regardless of its content — the same single generic
    message is returned for every block, so no information can leak by
    the user comparing different possible messages. Enforcing that the
    admin log is only *visible* to administrators is an access-control
    concern for the (future) dashboard, not something a pure function can
    itself guarantee; what this function guarantees is that the two are
    kept structurally separate.
    """
    return {
        "final_decision": "BLOCK",
        "user_response": SAFE_BLOCK_MESSAGE,
        "admin_log": {"internal_reason": internal_reason},
    }


# ---------------------------------------------------------------------------
# VERIFY / RETRY
# ---------------------------------------------------------------------------

_TIER_ORDER = ["low", "mid", "high", "expert"]


def _current_tier_for_model(model_id):
    for tier, registered_model in model_pipeline.MODEL_REGISTRY.items():
        if registered_model == model_id:
            return tier
    return None


def _next_tier_up_model(model_id):
    """Section 3 Step 9: "On second retry, the router selects the next
    tier up." If already at the top tier (or the model is unrecognised),
    stays at the top tier — the doc describes no tier beyond "expert"."""
    current_tier = _current_tier_for_model(model_id)
    if current_tier is None:
        return model_pipeline.MODEL_REGISTRY["expert"]
    index = _TIER_ORDER.index(current_tier)
    next_index = min(index + 1, len(_TIER_ORDER) - 1)
    return model_pipeline.MODEL_REGISTRY[_TIER_ORDER[next_index]]


def _execute_resolved_outcome(outcome):
    """Dispatches a retry attempt's resolved (non-VERIFY) final_action to
    its own decision-path function. HUMAN_REVIEW is deliberately not one
    of these: a retry attempt's final_action comes from core.pipeline's
    response-side auditing/policy evaluation, which per product decision
    can no longer produce HUMAN_REVIEW at all (see core.policy_engine's
    RULE_ORDER comment) — only the prompt-time audit can, and that always
    runs before any retry loop even starts."""
    action = outcome["final_action"]
    if action == "ALLOW":
        result = execute_allow(outcome["response_text"], outcome.get("token_map"))
        result["verify_warnings"] = outcome.get("verify_warnings") or []
        return result
    if action == "MODIFY":
        result = execute_modify(outcome["response_text"])
        result["verify_warnings"] = outcome.get("verify_warnings") or []
        return result
    if action == "BLOCK":
        return execute_block(outcome.get("policy_trigger_reason", ""))
    raise ValueError(f"Unexpected resolved final_action from a retry attempt: {action!r}")


def execute_verify_retry(attempt_fn, initial_model_id, max_retries=2):
    """Section 3 Step 9 VERIFY/RETRY: "A new generation is requested. On
    first retry, the same model is used with an enhanced system prompt
    instructing it to be more careful. On second retry, the router
    selects the next tier up. Maximum retry count per request is
    configurable (default: 2)." (The doc continues: "If after two
    retries the score is still below threshold, the decision escalates
    to HUMAN_REVIEW" — superseded by later product decision: response-
    side auditing can never escalate to HUMAN_REVIEW, see this
    function's own exhaustion branch below.)

    `attempt_fn(model_id, enhanced_prompt) -> dict` represents one full
    generate + audit + policy-check attempt (Steps 4/6/7 composed), and
    must return at least {"final_action": str, "response_text": str},
    plus whatever else the resolved action needs (token_map for ALLOW,
    verify_warnings for ALLOW/MODIFY, policy_trigger_reason for BLOCK).
    It is the seam tests mock to control each attempt's outcome
    deterministically.

    On the first retry the doc explicitly calls for the *same* model with
    an enhanced prompt; the doc does not repeat the "enhanced prompt"
    qualifier for the second retry, which only names the tier escalation
    — so only the first retry is marked enhanced_prompt=True here.

    Returns whichever path's execute_* function the resolved outcome
    calls for, plus a `retry_attempts` list describing what happened at
    each retry.
    """
    model_id = initial_model_id
    attempts = []
    outcome = None

    for retry_number in range(1, max_retries + 1):
        enhanced_prompt = (retry_number == 1)
        if retry_number > 1:
            model_id = _next_tier_up_model(model_id)
        outcome = attempt_fn(model_id, enhanced_prompt)
        attempts.append({
            "retry_number": retry_number,
            "model_id": model_id,
            "enhanced_prompt": enhanced_prompt,
            "final_action": outcome["final_action"],
        })

        if outcome["final_action"] != "VERIFY":
            result = _execute_resolved_outcome(outcome)
            result["retry_attempts"] = attempts
            return result

    # "If after two retries the score is still below threshold, the
    # decision escalates to HUMAN_REVIEW" — per LATER product decision,
    # response-side auditing can never escalate to HUMAN_REVIEW at all
    # (only the prompt-time policy audit may queue a request for human
    # review, and that already ran, before this retry loop, on the
    # original prompt). So instead: deliver the last attempt's response
    # as-is, with its own per-dimension verify_warnings plus one
    # synthetic warning noting the retries didn't resolve the concern —
    # "the response should still be displayed to the user, with the
    # appropriate warning."
    result = execute_allow(
        outcome.get("response_text") if outcome else None,
        outcome.get("token_map") if outcome else None,
    )
    warnings = list(outcome.get("verify_warnings") or []) if outcome else []
    warnings.append({
        "dimension": "retry_exhausted",
        "score": None,
        "message": (
            "This response is shown after multiple attempts to improve it; "
            "it may still have quality issues."
        ),
    })
    result["verify_warnings"] = warnings
    result["retry_attempts"] = attempts
    return result
