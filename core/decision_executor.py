"""Section 3 Step 9 — Decision Execution.

Implements all five decision paths: ALLOW, VERIFY/RETRY, MODIFY,
HUMAN_REVIEW, BLOCK.

Standalone, independently tested module — not yet wired into the request
pipeline, for the same reason as the other pipeline modules: this project's
10-step plan puts the live Human Review Interface / dashboard and the
full end-to-end pipeline wiring in later, dedicated steps. This module
provides the correct decision-execution *logic*; persisting a real,
queryable human-review queue belongs with that dashboard step.
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

DEFAULT_DISCLOSURE_NOTICE = (
    "This response has been modified to remove sensitive information."
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
    """Section 3 Step 9 MODIFY: redacts PII, encrypts and logs the
    original content, and returns the modified response with an optional
    disclosure notice.

    Note: the doc's "For structured content, selectively removes or
    replaces flagged sections" names no concrete mechanism or field
    anywhere in the document beyond PII masking, so no additional
    structured-content removal logic is implemented here.
    """
    redacted_text, categories_redacted = redact_pii(response_text)
    encrypted_original = encrypt_original_content(response_text)
    return {
        "final_decision": "MODIFY",
        "user_response": redacted_text,
        "disclosure_notice": disclosure_notice,
        "modification_log": {
            "original_content_encrypted": encrypted_original,
            "modified_output": redacted_text,
            "categories_redacted": categories_redacted,
        },
    }


# ---------------------------------------------------------------------------
# HUMAN_REVIEW
# ---------------------------------------------------------------------------

DEFAULT_ESTIMATED_WAIT_MINUTES = 30
REVIEWER_DECISIONS = {"APPROVE", "MODIFY", "REJECT"}


def execute_human_review(audit_json, raw_response, redacted_response,
                          policy_trigger_reason, estimated_wait_minutes=DEFAULT_ESTIMATED_WAIT_MINUTES):
    """Section 3 Step 9 HUMAN_REVIEW: "The response is queued ... The
    user is informed of a review delay with an estimated wait time. The
    reviewer receives the full audit JSON, the raw and redacted
    responses, and the policy trigger reason."

    Returns the queued case (to be persisted by a future integration
    step) and the message shown to the user while they wait.
    """
    queued_case = {
        "status": "PENDING",
        "audit_json": audit_json,
        "raw_response": raw_response,
        "redacted_response": redacted_response,
        "policy_trigger_reason": policy_trigger_reason,
        "reviewer_id": None,
        "decision": None,
        "decided_at": None,
        "final_user_response": None,
    }
    return {
        "final_decision": "HUMAN_REVIEW",
        "user_response": (
            f"Your request is being reviewed by a human reviewer. "
            f"Estimated wait time: {estimated_wait_minutes} minutes."
        ),
        "estimated_wait_minutes": estimated_wait_minutes,
        "queued_case": queued_case,
    }


def apply_reviewer_decision(queued_case, decision, reviewer_id, modified_response=None, decided_at=None):
    """Section 3 Step 9 HUMAN_REVIEW: "The reviewer can approve, modify,
    or reject. All reviewer actions are timestamped and attributed."

    - APPROVE: the queued raw_response is sent to the user as-is.
    - MODIFY: `modified_response` (required) is sent to the user.
    - REJECT: nothing of the original response is returned; the same
      safe, generic message used by BLOCK is shown, applying that
      section's explicit principle (never reveal internal reasoning to
      the user) to this analogous case, which the doc does not spell out
      a separate message for.
    """
    if decision not in REVIEWER_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(REVIEWER_DECISIONS)}, got {decision!r}")
    if decision == "MODIFY" and not modified_response:
        raise ValueError("modified_response is required when decision is MODIFY")
    if decided_at is None:
        decided_at = timezone.now()

    if decision == "APPROVE":
        final_user_response = queued_case.get("raw_response")
    elif decision == "MODIFY":
        final_user_response = modified_response
    else:  # REJECT
        final_user_response = SAFE_BLOCK_MESSAGE

    updated_case = dict(queued_case)
    updated_case.update({
        "status": "DECIDED",
        "decision": decision,
        "reviewer_id": reviewer_id,
        "decided_at": decided_at,
        "final_user_response": final_user_response,
    })
    return updated_case


# ---------------------------------------------------------------------------
# BLOCK
# ---------------------------------------------------------------------------

# Quoted verbatim from Section 3 Step 9 BLOCK's own example.
SAFE_BLOCK_MESSAGE = "This response cannot be provided as it may contain sensitive information."


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
    its own decision-path function."""
    action = outcome["final_action"]
    if action == "ALLOW":
        return execute_allow(outcome["response_text"], outcome.get("token_map"))
    if action == "MODIFY":
        return execute_modify(outcome["response_text"])
    if action == "HUMAN_REVIEW":
        return execute_human_review(
            audit_json=outcome.get("audit_json", {}),
            raw_response=outcome.get("response_text"),
            redacted_response=outcome.get("redacted_response"),
            policy_trigger_reason=outcome.get("policy_trigger_reason", ""),
        )
    if action == "BLOCK":
        return execute_block(outcome.get("policy_trigger_reason", ""))
    raise ValueError(f"Unexpected resolved final_action from a retry attempt: {action!r}")


def execute_verify_retry(attempt_fn, initial_model_id, max_retries=2):
    """Section 3 Step 9 VERIFY/RETRY: "A new generation is requested. On
    first retry, the same model is used with an enhanced system prompt
    instructing it to be more careful. On second retry, the router
    selects the next tier up. If after two retries the score is still
    below threshold, the decision escalates to HUMAN_REVIEW. Maximum
    retry count per request is configurable (default: 2)."

    `attempt_fn(model_id, enhanced_prompt) -> dict` represents one full
    generate + audit + policy-check attempt (Steps 4/6/7 composed), and
    must return at least {"final_action": str, "response_text": str},
    plus whatever else the resolved action needs (token_map for ALLOW,
    audit_json/policy_trigger_reason for HUMAN_REVIEW/BLOCK). It is the
    seam tests mock to control each attempt's outcome deterministically.

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
    # decision escalates to HUMAN_REVIEW."
    result = execute_human_review(
        audit_json=outcome.get("audit_json", {}) if outcome else {},
        raw_response=outcome.get("response_text") if outcome else None,
        redacted_response=outcome.get("redacted_response") if outcome else None,
        policy_trigger_reason="Exhausted VERIFY/RETRY attempts without passing audit.",
    )
    result["retry_attempts"] = attempts
    return result
