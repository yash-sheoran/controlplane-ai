"""Section 3 Step 3 — Model Router, Step 4 — AI Model Execution,
Step 5 — Objective Metrics Collection.

Like core/pre_request_analysis.py, this is a standalone, independently
tested module — not yet wired into the request-ingestion endpoint. Doing
so now would require inventing behaviour for the Step 3 pre-check BLOCK
outcome and for how these results get persisted, both of which are the
Auditing Engine's and Decision Executor's explicit, separate concerns
(later steps). Wiring it in now would mean redoing that wiring once those
steps exist, so it is deferred.
"""

import json
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Step 3 — Model Router
# ---------------------------------------------------------------------------

# Section 11.1 tech stack names three concrete models across the low/mid/
# high tiers ("claude-haiku-4-5 (low-cost), Claude claude-sonnet-4-6 (mid),
# Claude Opus (high) — routed by complexity/risk"). "expert" reuses the
# high-tier model: Section 3 Step 3's "Risk 7-10 -> Highest-capability
# model" does not name a model beyond what is already registered as the
# top tier — it is a stricter *audit* treatment of the same call
# ("mandatory strictest audit profile"), not a different model.
MODEL_REGISTRY = {
    "low": "claude-haiku-4-5",
    "mid": "claude-sonnet-4-6",
    "high": "claude-opus",
    "expert": "claude-opus",
}


def select_model(complexity_score, risk_score):
    """Section 3 Step 3 — Model Router. Implements the doc's example
    routing table:

      Complexity 1-3,  Risk 1-4  -> Fast, low-cost model
      Complexity 4-7,  Risk 1-6  -> Mid-tier model
      Complexity 7-10, Risk 1-6  -> Powerful reasoning model
      Any complexity,  Risk 7-10 -> Highest-capability model + mandatory
                                    strictest audit profile
      Risk 9-10                  -> Route to BLOCK pre-check before model
                                    call; may not proceed

    The doc's own example table has two internal ambiguities, resolved
    here as follows (documented, not silently assumed away):

      * Risk 9-10 is simultaneously covered by "any complexity, risk 7-10
        -> highest-capability model" AND "risk 9-10 -> BLOCK pre-check".
        Section 3 Step 8's Policy Engine establishes that "CRITICAL BLOCK
        rules are checked first" among competing rules; the same
        precedence is applied here, so risk 9-10 always blocks.
      * "Complexity 4-7 -> mid-tier" and "Complexity 7-10 -> high-tier"
        both literally include complexity=7. The boundary is resolved in
        favour of the more capable tier, i.e. the mid-tier band is
        treated as complexity 4-6 and the high-tier band as 7-10.

    Returns a dict: blocked, tier, model, mandatory_strict_audit,
    selection_reason, candidate_models_evaluated.
    """
    if risk_score >= 9:
        return {
            "blocked": True,
            "tier": None,
            "model": None,
            "mandatory_strict_audit": False,
            "selection_reason": (
                f"Risk score {risk_score} >= 9: routed to BLOCK pre-check "
                "before model call; request may not proceed."
            ),
            "candidate_models_evaluated": [],
        }

    if risk_score >= 7:
        tier = "expert"
        reason = (
            f"Risk score {risk_score} in [7,8]: any complexity routes to the "
            "highest-capability model with a mandatory strictest audit profile."
        )
    elif complexity_score >= 7:
        tier = "high"
        reason = (
            f"Complexity score {complexity_score} in [7,10] with risk <= 6: "
            "powerful reasoning model."
        )
    elif complexity_score >= 4:
        tier = "mid"
        reason = (
            f"Complexity score {complexity_score} in [4,6] with risk <= 6: "
            "mid-tier model."
        )
    else:
        tier = "low"
        reason = (
            f"Complexity score {complexity_score} in [1,3] with risk <= 6: "
            "fast, low-cost model."
        )

    return {
        "blocked": False,
        "tier": tier,
        "model": MODEL_REGISTRY[tier],
        "mandatory_strict_audit": tier == "expert",
        "selection_reason": reason,
        "candidate_models_evaluated": list(MODEL_REGISTRY.values()),
    }


# ---------------------------------------------------------------------------
# Step 4 — AI Model Execution
# ---------------------------------------------------------------------------

# Section 1.3/11.1: the prototype demonstrates the full pipeline "with
# simulated models". The model identifiers named in Section 11.1
# (claude-haiku-4-5, claude-sonnet-4-6, Claude Opus) are this document's own
# placeholder names for the prototype, not real callable model strings, so
# call_generating_model simulates a response rather than making a live API
# call. It is the seam tests mock to control token counts, finish_reason,
# and failures.


class ModelExecutionError(Exception):
    """Raised when a model call fails on every attempt (initial + retries)."""


def call_generating_model(model_id, prompt):
    """A single, unretried simulated call to the generating model.

    Returns a dict shaped like a real model API response:
      {"model": str, "text": str,
       "usage": {"input_tokens": int, "output_tokens": int},
       "finish_reason": str}
    """
    input_tokens = max(1, len(prompt.split()))
    output_tokens = max(1, input_tokens // 2)
    return {
        "model": model_id,
        "text": f"[simulated response from {model_id}]",
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
        "finish_reason": "stop",
    }


def execute_with_retry(model_id, prompt, timeout_s=5.0, max_retries=2, backoff_base_s=0.05):
    """Section 3 Step 4: "Timeout enforcement (per use-case profile) ...
    Retry logic with exponential back-off (max 2 retries; retry count is
    recorded in metrics)."

    Wraps call_generating_model: a call that raises, or that takes longer
    than timeout_s, is treated as a failed attempt and retried (up to
    max_retries) with exponential back-off between attempts.

    Returns (response: dict, elapsed_ms: float, retry_count: int) on
    success. Raises ModelExecutionError if every attempt fails.
    """
    attempt = 0
    last_error = None
    overall_start = time.perf_counter()

    while attempt <= max_retries:
        call_start = time.perf_counter()
        try:
            response = call_generating_model(model_id, prompt)
            call_duration_s = time.perf_counter() - call_start
            if call_duration_s > timeout_s:
                raise TimeoutError(
                    f"Model call to {model_id} exceeded timeout of {timeout_s}s "
                    f"(took {call_duration_s:.3f}s)"
                )
            elapsed_ms = (time.perf_counter() - overall_start) * 1000
            return response, elapsed_ms, attempt
        except Exception as exc:  # noqa: BLE001 - any failure triggers a retry
            last_error = exc
            attempt += 1
            if attempt <= max_retries:
                time.sleep(backoff_base_s * (2 ** (attempt - 1)))

    elapsed_ms = (time.perf_counter() - overall_start) * 1000
    raise ModelExecutionError(
        f"Model call to {model_id} failed after {max_retries} retries "
        f"(elapsed {elapsed_ms:.1f}ms): {last_error}"
    ) from last_error


# ---------------------------------------------------------------------------
# Step 5 — Objective Metrics Collection
# ---------------------------------------------------------------------------

_PRICING_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "model_pricing.json"


def _load_pricing_config():
    """Section 3 Step 5 callout: "Cost is calculated from a pricing config
    file that can be updated independently of code deployments." Read
    fresh on every call (no in-process caching) so an edit to the file
    takes effect without restarting the app."""
    with open(_PRICING_CONFIG_PATH, "r", encoding="utf-8") as config_file:
        return json.load(config_file)


def collect_metrics(response, elapsed_ms, retry_count, ttft_ms=None):
    """Section 3 Step 5: "Immediately after the model API returns, the
    system captures" model_used / input_tokens / output_tokens /
    total_tokens / latency_ms / ttft_ms / retry_count / cost_usd /
    finish_reason. Every value here is read directly from the response
    object or from a value measured by the caller — none is estimated.
    (Section 6 callout: "The auditing model is never asked to estimate
    these values.")
    """
    model_used = response["model"]
    input_tokens = response["usage"]["input_tokens"]
    output_tokens = response["usage"]["output_tokens"]
    finish_reason = response["finish_reason"]

    pricing = _load_pricing_config()
    model_pricing = pricing.get(model_used, pricing["_default"])
    cost_usd = (
        (input_tokens / 1000) * model_pricing["input_price_per_1k_usd"]
        + (output_tokens / 1000) * model_pricing["output_price_per_1k_usd"]
    )

    return {
        "model_used": model_used,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "latency_ms": round(elapsed_ms, 3),
        "ttft_ms": ttft_ms,
        "retry_count": retry_count,
        "cost_usd": round(cost_usd, 6),
        "finish_reason": finish_reason,
    }
