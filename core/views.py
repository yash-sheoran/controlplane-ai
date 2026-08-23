import json
import uuid

from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from . import pipeline
from .models import Trace, UseCaseProfile

# Section 3 Step 9's five decision outcomes map to these HTTP statuses:
# ALLOW/MODIFY/BLOCK are all *successful, complete* responses (BLOCK is a
# deliberate content decision, not an error), so 200; HUMAN_REVIEW has no
# final content yet, so 202 Accepted (processing).
_STATUS_CODE_BY_FINAL_ACTION = {
    "ALLOW": 200, "MODIFY": 200, "BLOCK": 200, "HUMAN_REVIEW": 202,
}


def health_check(request):
    """Lightweight liveness endpoint for this step's smoke test.

    Not part of the architecture doc's request pipeline (that begins with
    Step 2 — Request Ingestion) — this only confirms the Django project and
    its database connection are wired up correctly.
    """
    return JsonResponse({"status": "ok"})


# Section 3 Step 1 Failure row: "All failures in this step result in a 503
# with a safe error message; the trace is never lost." The doc specifies a
# single status code (503) for every failure mode in this step — it does not
# distinguish a separate 400 for bad input — so this message and status are
# reused for every rejected/failed request below.
SAFE_ERROR_MESSAGE = "The request could not be processed. Please try again."


def _safe_error_response():
    return JsonResponse({"error": SAFE_ERROR_MESSAGE}, status=503)


@csrf_exempt
@require_http_methods(["POST"])
def create_request(request):
    """Section 3 Step 1 — Request Ingestion & Trace Initialisation.

    Inputs: raw_prompt, user_id, session_id, use_case_id, client_metadata
    Outputs: request_id (UUID), trace_object (open), timestamp
    Latency: < 2 ms (in-memory)
    Failure: all failures in this step result in a 503 with a safe error
    message; the trace is never lost.
    """
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _safe_error_response()

    if not isinstance(payload, dict):
        return _safe_error_response()

    raw_prompt = payload.get("raw_prompt")
    user_id = payload.get("user_id")
    session_id = payload.get("session_id")
    use_case_id = payload.get("use_case_id")
    client_metadata = payload.get("client_metadata")

    if not isinstance(raw_prompt, str) or not raw_prompt.strip():
        return _safe_error_response()
    if not isinstance(user_id, str) or not user_id.strip():
        return _safe_error_response()
    if not isinstance(use_case_id, str) or not use_case_id.strip():
        return _safe_error_response()

    if client_metadata is None:
        client_metadata = {}
    if not isinstance(client_metadata, dict):
        return _safe_error_response()

    try:
        session_uuid = uuid.UUID(str(session_id))
    except (ValueError, TypeError, AttributeError):
        return _safe_error_response()

    try:
        use_case = UseCaseProfile.objects.get(use_case_id=use_case_id, is_active=True)
    except UseCaseProfile.DoesNotExist:
        return _safe_error_response()

    # Section 3 Step 1: "the trace is never lost" — wrap creation in an
    # atomic transaction so a trace is either fully committed and returned
    # to the caller, or not created at all; never a partial/corrupt row.
    try:
        with transaction.atomic():
            trace = Trace.objects.create(
                session_id=session_uuid,
                user_id=user_id,
                use_case=use_case,
                raw_prompt=raw_prompt,
                client_metadata=client_metadata,
            )
    except Exception:
        return _safe_error_response()

    # This project's Step 10: the trace, already safely committed above,
    # now runs through the full pipeline (pre-request analysis -> model
    # router/execution/metrics -> auditing engine -> policy engine with
    # session-risk escalation -> decision executor). If this stage fails
    # unexpectedly, the trace is still not lost — it stays OPEN with no
    # final_decision — but the caller still gets the same safe response
    # Section 3 Step 1 specifies for any failure in this endpoint.
    try:
        result = pipeline.process_request(trace)
    except Exception:
        return _safe_error_response()

    return JsonResponse(
        {
            "request_id": str(trace.request_id),
            "session_id": str(trace.session_id),
            "status": result["final_action"],
            "message": result["user_response"],
            "disclosure_notice": result["disclosure_notice"],
            "timestamp": trace.timestamp.isoformat(),
        },
        status=_STATUS_CODE_BY_FINAL_ACTION.get(result["final_action"], 200),
    )
