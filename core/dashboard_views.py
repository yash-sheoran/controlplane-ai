"""HTTP views for Section 10's Observability Dashboard, Section 9.3's
alert-fatigue tuning view, and Section 7's feedback capture. Thin: all
aggregation logic lives in core/dashboard.py, all reviewer-decision logic
in core/decision_executor.py — these views just wire HTTP <-> that logic
and render templates, consistent with how core/views.py wires HTTP to
core/pre_request_analysis.py etc.
"""

import json
import uuid

from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from . import dashboard
from . import decision_executor as de
from . import pipeline
from . import policy_engine as pe
from .authz import manager_required, team_user_ids
from .models import (
    AuditRecord,
    FalsePositiveReport,
    ReviewerAction,
    ThresholdChangeProposal,
    Trace,
    UserFeedback,
)


@manager_required
def dashboard_home(request):
    """Section 10.1 — Real-Time Operational Metrics, scoped to the
    logged-in manager's own team (see core.authz.team_user_ids; None for
    a superuser means unscoped, matching this account's pre-auth,
    sees-everything behaviour)."""
    user_ids = team_user_ids(request.user)
    since_24h = timezone.now() - timezone.timedelta(hours=24)
    decision_distribution = dashboard.decision_distribution(user_ids=user_ids)
    # Pre-zipped into rows: Django templates cannot look up a dict value by
    # a loop variable's key via dot notation (foo.bar always means the
    # literal key "bar"), so the view does the pairing instead.
    decision_rows = [
        {
            "action": action,
            "count": decision_distribution["counts"][action],
            "percentage": decision_distribution["percentages"][action],
        }
        for action in dashboard.DECISION_ACTIONS
        if action != "VERIFY"  # not a resting decision — always 0, not shown on Overview
    ]
    context = {
        "total_requests_24h": dashboard.total_requests(since=since_24h, user_ids=user_ids),
        "decision_distribution": decision_distribution,
        "decision_rows": decision_rows,
        "latency_percentiles": dashboard.latency_percentiles(user_ids=user_ids),
        "total_cost_today": dashboard.total_cost_today(user_ids=user_ids),
        "cost_per_model": dashboard.cost_per_model(user_ids=user_ids),
        "active_human_review_queue_count": dashboard.active_human_review_queue_count(user_ids=user_ids),
    }
    return render(request, "core/dashboard_home.html", context)


@manager_required
def dashboard_trends(request):
    """Section 10.2 — Safety & Quality Trend Metrics, scoped to the
    logged-in manager's own team."""
    user_ids = team_user_ids(request.user)
    days = int(request.GET.get("days", 7))
    context = {
        "days": days,
        "hallucination_rate": dashboard.hallucination_rate(days=days, user_ids=user_ids),
        "safety_violation_rate": dashboard.safety_violation_rate(days=days, user_ids=user_ids),
        "data_leakage_attempts": dashboard.data_leakage_attempts(days=days, user_ids=user_ids),
        "bias_detection_rate": dashboard.bias_detection_rate(days=days, user_ids=user_ids),
        "blocked_request_rate": dashboard.blocked_request_rate(days=days, user_ids=user_ids),
        "retry_verify_rate": dashboard.retry_verify_rate(days=days, user_ids=user_ids),
        "human_review_rate": dashboard.human_review_rate(days=days, user_ids=user_ids),
    }
    return render(request, "core/dashboard_trends.html", context)


# Sidebar-facing labels for a decided HUMAN_REVIEW case, keyed by
# ReviewerAction/apply_prompt_review_decision's own decision values.
# "MODIFY" is kept, unused, for forward compatibility — apply_prompt_
# review_decision itself only ever produces APPROVE/REJECT today.
_REVIEW_DECISION_LABELS = {"APPROVE": "APPROVED", "MODIFY": "MODIFIED", "REJECT": "REJECTED"}


def _my_human_review_requests(user_id_value, limit=50):
    """Sidebar 'Requests' tab: every HUMAN_REVIEW case this account's own
    prompts have produced, pending or decided, newest first — distinct
    from human_review_queue's manager-facing, pending-only, whole-team
    view. Clicking one takes the employee straight back to that turn in
    its session (see the #turn-<trace_id> anchor in playground.html)."""
    records = (
        AuditRecord.objects.filter(trace__user_id=user_id_value, final_action="HUMAN_REVIEW")
        .select_related("trace")
        .order_by("-trace__timestamp")[:limit]
    )
    requests_list = []
    for record in records:
        title = (record.trace.raw_prompt or "").strip() or "Request"
        if len(title) > 60:
            title = title[:57] + "..."
        review = record.human_review or {}
        if review.get("generation_failed"):
            status = "FAILED"
        elif record.human_review_status == "DECIDED":
            status = _REVIEW_DECISION_LABELS.get(review.get("decision"), "DECIDED")
        else:
            status = "PENDING"
        requests_list.append({
            "trace_id": record.trace_id,
            "session_id": record.trace.session_id,
            "title": title,
            "timestamp": record.trace.timestamp,
            "status": status,
        })
    return requests_list


def _chat_history(user_id_value, current_session_id, limit=50):
    """Sidebar data for the ChatGPT-style playground: one entry per
    session_id this user has used, newest activity first, titled with
    that session's first prompt (there's no dedicated chat/title model —
    session_id grouping of Trace rows is the only notion of a "chat")."""
    session_rows = list(
        Trace.objects.filter(user_id=user_id_value)
        .values("session_id")
        .annotate(last_activity=Max("timestamp"))
        .order_by("-last_activity")[:limit]
    )
    session_ids = [row["session_id"] for row in session_rows]

    first_prompt_by_session = {}
    for trace in (
        # Filtered by user_id too (not just session_id__in=session_ids): if
        # a session_id were ever shared across two accounts, an unfiltered
        # lookup here could surface the OTHER account's earliest prompt as
        # this chat's sidebar title.
        Trace.objects.filter(session_id__in=session_ids, user_id=user_id_value)
        .order_by("timestamp")
    ):
        if trace.session_id not in first_prompt_by_session:
            first_prompt_by_session[trace.session_id] = trace.raw_prompt

    history = []
    for row in session_rows:
        sid = row["session_id"]
        title = (first_prompt_by_session.get(sid) or "New chat").strip() or "New chat"
        if len(title) > 60:
            title = title[:57] + "..."
        history.append({
            "session_id": sid,
            "title": title,
            "last_activity": row["last_activity"],
            "is_current": str(sid) == str(current_session_id),
        })
    return history


@login_required
@require_http_methods(["GET", "POST"])
def playground(request):
    """Browser-facing form for submitting a prompt through the full
    pipeline (Section 3 Step 1 -> Step 9) and seeing the decision inline,
    instead of via curl. CSRF-protected like the other dashboard forms
    (see the note on core.views.create_request being the CSRF-exempt,
    external-API equivalent of this same pipeline entry point). Open to
    any authenticated account — employee or manager.

    Presented as a ChatGPT-style UI: GET with no ?session= always starts a
    brand new chat (fresh session_id); GET with ?session=<uuid> resumes
    that session's thread; the left-hand sidebar (see _chat_history)
    lists every session this account has used so far. Identity is always
    request.user.username — never client-supplied — both so a chat is
    reliably "yours" across visits and so a manager's team-scoped
    dashboards (dashboard_home/dashboard_trends/etc.) can trust
    Trace.user_id as the real, un-spoofable account that made it."""
    user_id_value = request.user.username

    if request.method == "POST":
        session_param = request.POST.get("session_id")
        try:
            session_id = str(uuid.UUID(session_param)) if session_param else str(uuid.uuid4())
        except ValueError:
            session_id = str(uuid.uuid4())

        # Reject attaching to a session_id some other account already
        # owns. Without this, a client-supplied session_id (the hidden
        # form field is normally round-tripped verbatim, but nothing stops
        # a crafted POST from naming any UUID) would let one account's
        # turns write into — and, via core.pipeline's SessionState, which
        # is keyed ONLY on session_id with no user field at all —
        # permanently mutate another account's compounding session-risk
        # state, silently tightening or loosening the policy thresholds
        # applied to that other account's next turn.
        if Trace.objects.filter(session_id=session_id).exclude(user_id=user_id_value).exists():
            return HttpResponseForbidden("That session does not belong to your account.")
    else:
        session_param = request.GET.get("session")
        try:
            session_id = str(uuid.UUID(session_param)) if session_param else str(uuid.uuid4())
        except ValueError:
            session_id = str(uuid.uuid4())

    context = {
        "session_id": session_id,
        "error": None,
    }

    if request.method == "POST":
        raw_prompt = (request.POST.get("raw_prompt") or "").strip()

        # A turn that went to prompt-time HUMAN_REVIEW can sit OPEN for an
        # indeterminate time with no visible feedback once the composer is
        # usable again — an employee unsure whether their message actually
        # sent naturally retypes/resends it, silently creating a second
        # (or third) pending case for the exact same request. Refuse an
        # exact-text resubmission while an earlier one in this session is
        # still unresolved, rather than queuing a duplicate.
        is_duplicate_pending = raw_prompt and Trace.objects.filter(
            session_id=session_id, user_id=user_id_value, raw_prompt=raw_prompt, status=Trace.STATUS_OPEN,
        ).exists()

        if not raw_prompt:
            context["error"] = "A prompt is required."
        elif is_duplicate_pending:
            # Silently no-op rather than surfacing a visible message: the
            # guard's job is just to stop a second pending case from being
            # created, per product decision, not to explain itself on screen.
            pass
        else:
            trace = Trace.objects.create(
                session_id=uuid.UUID(session_id), user_id=user_id_value, raw_prompt=raw_prompt,
            )
            try:
                pipeline.process_request(trace)
            except Exception:
                # Most likely cause in practice: the live Gemini calls
                # (risk analysis, generation, auditing) hitting the
                # free-tier rate limit, or timing out. process_request
                # persists nothing on this path — the trace is left OPEN
                # with no AuditRecord (see core.pipeline.resume_after_
                # prompt_review's matching note) — so a minimal record is
                # created here, purely so this turn resolves to a clear
                # "failed" bubble on this and every future render instead
                # of a blank, pill-less ghost turn forever (see the
                # turn-building loop below: final_action=None never
                # happens on any successful path, so it's an unambiguous
                # signal this turn never completed).
                AuditRecord.objects.create(
                    trace=trace,
                    user_response={"content": de.SAFE_GENERATION_UNAVAILABLE_MESSAGE, "disclosure_notice": None},
                )
                trace.status = Trace.STATUS_CLOSED
                trace.closed_at = timezone.now()
                trace.save(update_fields=["status", "closed_at"])
                context["error"] = de.SAFE_GENERATION_UNAVAILABLE_MESSAGE

    # Rendered as a chat thread (see core/templates/core/playground.html),
    # so every turn needs its actual response text/status, not just the
    # one just submitted — Trace itself doesn't carry that (AuditRecord
    # does), hence the separate lookup below rather than relying on
    # Trace's reverse `audit_record` accessor (which raises
    # AuditRecord.DoesNotExist for any turn that never finished a full
    # pipeline run, e.g. failed before an AuditRecord was created).
    # Filtered by user_id (not just session_id) so guessing/reusing
    # another account's session UUID can't surface or resume their chat.
    turns = list(
        Trace.objects.filter(session_id=session_id, user_id=user_id_value).order_by("timestamp")
    )
    audit_records_by_trace_id = {
        record.trace_id: record
        for record in AuditRecord.objects.filter(trace__session_id=session_id, trace__user_id=user_id_value)
    }
    for turn in turns:
        record = audit_records_by_trace_id.get(turn.request_id)
        response = (record.user_response if record else None) or {}
        turn.chat_disclosure_notice = response.get("disclosure_notice")
        # Only the single most relevant warning is shown in chat — the
        # full, unabridged list stays on the AuditRecord itself for
        # audit/trend purposes (see pe.most_severe_verify_warning).
        top_warning = pe.most_severe_verify_warning(record.verify_warnings if record else None)
        turn.verify_warnings = [top_warning] if top_warning else []

        # A live-model failure (rate limit/timeout) can happen either
        # synchronously — record.final_action stays None, since no
        # successful path ever leaves it unset, see the POST handler
        # above — or during a manager's approval resume, in which case
        # human_review_queue's POST handler marks human_review
        # ["generation_failed"] instead (final_action there is already
        # the permanent "HUMAN_REVIEW" record of which gate this request
        # went through, so it can't double as this signal). Either way
        # it's shown identically: a fixed message, never a blank bubble
        # or an endless "pending" wait.
        review = (record.human_review or {}) if record else {}
        turn.generation_failed = record is not None and (
            record.final_action is None or bool(review.get("generation_failed"))
        )

        # A decided HUMAN_REVIEW case overrides both the placeholder
        # "your request is being reviewed" text and the HUMAN_REVIEW
        # status pill with the reviewer's actual outcome, once one exists.
        if turn.generation_failed:
            turn.review_status_label = None
            turn.chat_response = de.SAFE_GENERATION_UNAVAILABLE_MESSAGE
        elif record is not None and record.human_review_status == "DECIDED":
            turn.review_status_label = _REVIEW_DECISION_LABELS.get(review.get("decision"), "DECIDED")
            turn.chat_response = review.get("final_user_response")
        else:
            turn.review_status_label = None
            turn.chat_response = response.get("content")

        # Playground status pill: a plain ALLOW carries no pill at all —
        # nothing went wrong, nothing needs a label (a Verify warning, if
        # any, already says everything worth saying on its own). Every
        # other outcome gets a plain-language label instead of the raw
        # enum value; MODIFY additionally gets an info button explaining
        # itself instead of the old inline disclosure text.
        if turn.generation_failed:
            turn.status_pill_label = "Failed"
            turn.status_pill_css = "failed"
        elif turn.review_status_label:
            turn.status_pill_label = turn.review_status_label
            turn.status_pill_css = turn.review_status_label.lower()
        elif turn.final_decision == "MODIFY":
            turn.status_pill_label = "Modified"
            turn.status_pill_css = "modify"
        elif turn.final_decision == "BLOCK":
            turn.status_pill_label = "Blocked"
            turn.status_pill_css = "block"
        elif turn.final_decision == "HUMAN_REVIEW":
            turn.status_pill_label = "Pending for manager review"
            turn.status_pill_css = "human_review"
        else:
            turn.status_pill_label = None
            turn.status_pill_css = None
    context["turns"] = turns
    context["my_requests"] = _my_human_review_requests(user_id_value)

    chat_history = _chat_history(user_id_value, session_id)
    context["chat_history"] = chat_history
    # Topbar title: this chat's own title (its first prompt, truncated —
    # same value _chat_history already computed for the sidebar), falling
    # back to "New chat" for a session with no turns yet.
    current_chat = next((c for c in chat_history if c["is_current"]), None)
    context["chat_title"] = current_chat["title"] if current_chat else "New chat"

    return render(request, "core/playground.html", context)


@login_required
@require_http_methods(["GET"])
def playground_pending_status(request):
    """Polled from playground.html while a turn is showing "Pending for
    manager review", so an approval/rejection (core.pipeline.
    resume_after_prompt_review, run from a manager's own request, minutes
    or hours later) reaches the employee's chat without them needing to
    manually refresh. Pass `ids` as a comma-separated list of the
    request_ids the page currently has rendered as pending; only ones
    that (a) belong to the logged-in user and (b) aren't fully resolved
    yet are echoed back — an id dropping out of the response tells the
    caller that turn was just resolved.

    "Fully resolved" is deliberately more than just human_review_status
    != "PENDING": core.dashboard_views.human_review_queue's POST handler
    flips that flag to "DECIDED" immediately on APPROVE, before calling
    core.pipeline.resume_after_prompt_review — a live model call that can
    take several seconds — so that a second, racing decision on the same
    case is rejected rather than double-processed. In that window,
    human_review_status already reads "DECIDED" but human_review's
    final_user_response is still None. Reloading the employee's page
    right then would land on the same "no response was recorded"
    fallback as a genuine failure, for a request that's actually still in
    flight — so an approved-but-not-yet-generated case is still treated
    as pending here. REJECT has no such window: apply_prompt_review_
    decision fills in final_user_response synchronously, before
    human_review_status is ever saved.

    A case where resume_after_prompt_review actually raised (live model
    rate limit/timeout) looks identical in the DB to that same in-flight
    window — human_review_status is already "DECIDED", final_user_
    response is still None — except human_review_queue's POST handler
    additionally marks it "generation_failed": true right when this
    happens. That marker is treated as resolved, not pending, here — the
    generation genuinely isn't coming, so the poll must stop and let the
    caller reload onto the "failed" turn instead of waiting forever.
    """
    ids = []
    for raw_id in (request.GET.get("ids") or "").split(","):
        raw_id = raw_id.strip()
        if not raw_id:
            continue
        try:
            ids.append(uuid.UUID(raw_id))
        except ValueError:
            continue  # malformed input from the query string; just skip it

    still_pending = []
    for record in AuditRecord.objects.filter(trace_id__in=ids, trace__user_id=request.user.username):
        if record.human_review_status != "DECIDED":
            still_pending.append(record.trace_id)
            continue
        review = record.human_review or {}
        if review.get("generation_failed"):
            continue
        if review.get("decision") == "APPROVE" and review.get("final_user_response") is None:
            still_pending.append(record.trace_id)

    return JsonResponse({"still_pending": [str(i) for i in still_pending]})


@manager_required
@require_http_methods(["GET", "POST"])
def human_review_queue(request):
    """Section 3 Step 9 HUMAN_REVIEW's queue + Section 7.1's reviewer
    gold-standard label — now prompt-time: every pending case here is a
    PROMPT that matched the company policy (core/config/
    company_policy.json), queued BEFORE any generation call, so there is
    never a reply to show yet, only the prompt and why it was flagged.
    GET lists pending cases FOR THE MANAGER'S OWN TEAM ONLY; POST applies
    a reviewer's decision to one of them — APPROVE/REJECT only (see
    core.decision_executor.apply_prompt_review_decision: there is nothing
    yet for a reviewer to hand-edit). reviewer_id is always the logged-in
    manager's own username — never a free-text field — so the
    gold-standard label can be trusted."""
    user_ids = team_user_ids(request.user)
    reviewer_id = request.user.username

    if request.method == "POST":
        trace_id = request.POST.get("trace_id")
        decision = request.POST.get("decision")
        decision_reason = request.POST.get("decision_reason", "")

        record = get_object_or_404(AuditRecord, trace_id=trace_id)
        if user_ids is not None and record.trace.user_id not in user_ids:
            return HttpResponseForbidden("That case does not belong to your team.")
        if record.human_review_status != "PENDING":
            # Without this check a case could be re-decided (silently
            # overwriting a prior gold-standard label with a second,
            # contradictory ReviewerAction) or decided even though it was
            # never actually queued for human review in the first place.
            return render(
                request, "core/human_review_queue.html",
                {"pending_cases": _pending_cases(user_ids=user_ids), "error": "That case is not pending review."},
                status=400,
            )

        try:
            updated_case = de.apply_prompt_review_decision(
                record.human_review or {}, decision=decision, reviewer_id=reviewer_id,
            )
        except ValueError as exc:
            return render(
                request, "core/human_review_queue.html",
                {"pending_cases": _pending_cases(user_ids=user_ids), "error": str(exc)},
                status=400,
            )

        # decided_at is a real datetime (core.decision_executor is a pure,
        # DB-agnostic module); serialise it before storing in the JSONField.
        if updated_case.get("decided_at") is not None:
            updated_case["decided_at"] = updated_case["decided_at"].isoformat()

        record.human_review = updated_case
        record.human_review_status = "DECIDED"
        record.save(update_fields=["human_review", "human_review_status"])

        # Section 7.1: "the decision and rationale are logged as a
        # gold-standard label against the original audit scores" — a
        # dedicated, append-only row, distinct from the JSON snapshot
        # above. Logged unconditionally (the reviewer's judgment call
        # happened regardless of whether generation below succeeds).
        ReviewerAction.objects.create(
            audit_record=record, reviewer_id=reviewer_id, decision=decision,
            decision_reason=decision_reason,
        )

        # APPROVE is what actually triggers generation, for the first
        # time, now that a human has cleared the prompt (REJECT is
        # already fully resolved above — see apply_prompt_review_
        # decision). A live model call can fail; mirrors how core.views.
        # create_request and core.dashboard_views.playground already
        # handle an uncaught process_request failure.
        try:
            pipeline.resume_after_prompt_review(record)
        except Exception:
            # Most likely cause: the live Gemini call (generation or
            # response audit) hitting the free-tier rate limit, or timing
            # out. Persisted as a fact on the record (not just a
            # one-render message) so the employee's own Playground poll
            # (playground_pending_status) stops waiting and shows a clear
            # failure instead of polling forever. _pending_cases() no
            # longer lists this case at all once human_review_status is
            # DECIDED, so this render is the only place a manager sees it
            # — hence the narrow, one-off notice below rather than a
            # persisted, general error banner.
            failed_review = dict(record.human_review or {})
            failed_review["generation_failed"] = True
            record.human_review = failed_review
            record.save(update_fields=["human_review"])
            trace = record.trace
            trace.status = Trace.STATUS_CLOSED
            trace.closed_at = timezone.now()
            trace.save(update_fields=["status", "closed_at"])
            return render(
                request, "core/human_review_queue.html",
                {
                    "pending_cases": _pending_cases(user_ids=user_ids),
                    "generation_failed_notice": (
                        f"Decision recorded for trace {record.trace_id}, but "
                        f"{de.SAFE_GENERATION_UNAVAILABLE_MESSAGE} "
                        "The employee has not yet received a reply."
                    ),
                },
                status=502,
            )

        return render(
            request, "core/human_review_queue.html",
            {"pending_cases": _pending_cases(user_ids=user_ids), "decided_case": updated_case},
        )

    return render(request, "core/human_review_queue.html", {"pending_cases": _pending_cases(user_ids=user_ids)})


def _pending_cases(user_ids=None):
    # No explicit ordering before this returned whatever order the DB
    # happened to store rows in, not anything meaningful to a reviewer.
    qs = AuditRecord.objects.filter(
        human_review_status="PENDING",
    ).select_related("trace").order_by("-trace__timestamp")
    if user_ids is not None:
        qs = qs.filter(trace__user_id__in=user_ids)
    return list(qs)


@manager_required
@require_http_methods(["GET", "POST"])
def fpr_tuning(request):
    """Section 9.3 — Operator Dashboard Alert Tuning View, scoped to the
    logged-in manager's own team. reported_by is always the logged-in
    manager's own username — never a free-text field."""
    user_ids = team_user_ids(request.user)
    context = {"result": None, "error": None}

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "report_false_positive":
            trace_id = request.POST.get("trace_id")
            dimension = request.POST.get("dimension")
            reason = request.POST.get("reason", "")
            record = get_object_or_404(AuditRecord, trace_id=trace_id)
            if user_ids is not None and record.trace.user_id not in user_ids:
                return HttpResponseForbidden("That case does not belong to your team.")
            FalsePositiveReport.objects.create(
                audit_record=record, dimension=dimension, reported_by=request.user.username, reason=reason,
            )
            context["message"] = f"Recorded false-positive report for {dimension!r}."

        elif action == "check_fpr":
            dimension = request.POST.get("dimension")
            days = int(request.POST.get("days", 7))
            context["result"] = dashboard.false_positive_rate_by_dimension(
                dimension, days=days, user_ids=user_ids,
            )
            context["result_dimension"] = dimension

        elif action == "simulate_threshold_change":
            bucket = request.POST.get("bucket")
            dimension = request.POST.get("dimension")
            new_threshold = float(request.POST.get("new_threshold"))
            days = int(request.POST.get("days", 7))
            context["simulation"] = dashboard.simulate_threshold_change(
                bucket, dimension, new_threshold, days=days, user_ids=user_ids,
            )

        elif action == "propose_threshold":
            # A threshold change is a system-wide policy proposal, not
            # tied to any one team's requests — reviewed via Django admin
            # (core/admin.py) regardless of which manager proposed it, so
            # this intentionally stays unscoped.
            proposal = ThresholdChangeProposal.objects.create(
                bucket=request.POST.get("bucket"),
                dimension=request.POST.get("dimension"),
                current_threshold=float(request.POST.get("current_threshold")),
                proposed_threshold=float(request.POST.get("proposed_threshold")),
                rationale=request.POST.get("rationale", ""),
            )
            context["proposal"] = proposal

    context["pending_proposals"] = list(ThresholdChangeProposal.objects.filter(status="PENDING"))
    return render(request, "core/fpr_tuning.html", context)


@csrf_exempt
@require_http_methods(["POST"])
def submit_thumbs_down(request, trace_id):
    """Section 7.1 User Thumbs-Down: "A lightweight user-facing feedback
    mechanism captures explicit dissatisfaction." A plain JSON API
    endpoint (unlike the dashboard's HTML-form views above) since this is
    meant to be called from the end-user-facing application, not the
    operator dashboard. csrf_exempt for the same reason core.views.
    create_request is: an external API caller has no Django session/CSRF
    cookie to present."""
    trace = get_object_or_404(Trace, request_id=trace_id)
    try:
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    feedback = UserFeedback.objects.create(trace=trace, comment=payload.get("comment", ""))
    return JsonResponse({"feedback_id": feedback.pk, "trace_id": str(trace_id)}, status=201)
