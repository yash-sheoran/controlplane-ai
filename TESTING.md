# ControlPlane.ai — Testing Guide

A step-by-step guide to exercising every endpoint and every flow in the
prototype, with exact inputs and expected results. Read the **"Defaults you
must review before real use"** section first — several values currently in
the repo are hackathon-prototype placeholders, not production-ready
settings.

Prerequisites: setup completed per `README.md` (venv, MySQL, migrations,
`.env`, spaCy model, the three seeded `UseCaseProfile` rows).

---

## 0. Defaults you must review before real use 

Everything below is either a security-sensitive default, a hackathon
placeholder value, or a config that ships empty and needs real business
input. None of these block local testing — they block anything beyond it.

### 0.1 Security-sensitive defaults (`controlplane/settings.py`, `.env`)

| Item | Current value | Why it must change |
|---|---|---|
| `SECRET_KEY` (`controlplane/settings.py:28`) | `django-insecure-+&xk42v@w5=3(m46_s2u^amc_p&&q1$wble%6+m8id0wq)*^_1` | Django's own auto-generated dev key, literally prefixed `django-insecure-`. Must be replaced with a secret, randomly generated value (and moved out of source control into `.env`) before any non-local deployment. |
| `DEBUG` (`controlplane/settings.py:31`) | `True` | Must be `False` outside local development — `DEBUG=True` leaks stack traces and settings to any visitor. |
| `ALLOWED_HOSTS` (`controlplane/settings.py:33`) | `[]` | Empty; only works because `DEBUG=True` currently masks the check. Must list your real domain(s) once `DEBUG=False`. |
| `DB_USER` / `DB_PASSWORD` (`.env`) | `root` / *(empty)* | Local-dev-only MySQL credentials with no password. Use a dedicated, credentialed DB user for anything shared. |
| `MODIFICATION_LOG_ENCRYPTION_KEY` (`.env`) | A key was generated for local use (`386Zj6c...`, not shown in full here — check your own `.env`) | This Fernet key encrypts the *original, pre-redaction* content logged on every MODIFY decision (Section 3 Step 9). It is **not** committed to git (`.env` is gitignored) — but if you copy this repo to a new environment, you must generate your own key (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) and keep it secret and stable. Losing it makes all previously-logged encrypted originals unrecoverable; rotating it without a migration plan does the same. |
| Django superuser | None created yet | Run `python manage.py createsuperuser` — needed for `/admin/` and for approving/rejecting threshold-change proposals. |

### 0.2 Use-case profiles — currently minimal, need real business config

The setup script in `README.md` seeds exactly this, and nothing more:

```python
UseCaseProfile.objects.get_or_create(use_case_id=uc, defaults={"name": uc})
```

Every other field is left at its model default:

| Field | Default | What it should actually be |
|---|---|---|
| `geography` | `[]` | The real ISO country/region codes this use case operates in (e.g. `["IN", "EU"]`) — drives which regulations get applied. |
| `regulations` | `[]` | The real regulation IDs that apply (`GDPR`, `DPDP`, `CCPA`, `EU_AI_Act`, `HIPAA` — see `core/config/regulations/`). Currently empty means **no regulation rules are applied to any seeded use case** until you set this. |
| `model_tier_preference` | `"mid"` | Not currently read by the router (Section 3 Step 3's routing table decides purely from complexity/risk — see `core/model_pipeline.py`), but should still reflect your intended default tier. |
| `session_risk_window` | `5` | The document's own stated default ("N = 5") — usually fine as-is. |
| `audit_retention_days` | `90` | The document's stated *minimum* (Section 10.3). Regulated use cases should raise this. |
| `eu_ai_act_high_risk` | `False` | **A judgment call the document leaves to the operator** (it references "EU AI Act Annex III high-risk categories" without enumerating them or giving a classification rule). If any of your real use cases should be treated as EU AI Act high-risk, you must set this explicitly — nothing infers it automatically. |

**Action:** before testing beyond the golden-path examples below, update your
seeded `UseCaseProfile` rows (via `/admin/` or shell) with real `geography`,
`regulations`, and `eu_ai_act_high_risk` values for your actual use cases.

### 0.3 Policy thresholds — two of three profiles are illustrative placeholders

`core/config/policies/DecisionSupport.yaml` is a literal transcription of
the architecture document's own concrete example (Section 5.1) — its
numbers are real, document-sourced values.

`core/config/policies/CustomerSupport.yaml` and
`core/config/policies/InternalKnowledge.yaml` are **explicitly flagged in
their own file headers as illustrative placeholders** — the source
document gives no concrete threshold numbers for these two profiles
anywhere. Current values:

| Use case | `session_risk_threshold` | Notes |
|---|---|---|
| DecisionSupport | `5.0` | Placeholder (no doc value exists for the threshold itself, only for the window size) |
| CustomerSupport | `6.0` | Placeholder |
| InternalKnowledge | `5.5` | Placeholder |

**Action:** replace the `thresholds:` block and `session_risk_threshold` in
`CustomerSupport.yaml` and `InternalKnowledge.yaml` with your organization's
actual risk tolerances before relying on their MODIFY/VERIFY/HUMAN_REVIEW/BLOCK
behavior for anything real. No code change or redeploy is needed — these
are read fresh from disk on every request.

### 0.4 Regulation version strings — three of five are placeholders

`core/config/regulations/GDPR.yaml` (`2024-Q4`) and `DPDP.yaml` (`2024-Q2`)
use version strings taken directly from the architecture document's own
example. `CCPA.yaml` (`2024-Q1`), `EU_AI_Act.yaml` (`2024-Q3`), and
`HIPAA.yaml` (`2024-Q1`) have **no document-given version** — these three
strings are illustrative placeholders you should replace with your actual
tracked regulation version/review dates.

### 0.5 No real authentication on reviewer/user identity

`reviewer_id` (human-review decisions) and `user_id` (request ingestion) are
free-text strings accepted as-is — there is no login, token, or identity
check tying them to a real person. Anyone who can reach the dashboard forms
or API can submit a decision under any `reviewer_id` they type. Fine for a
hackathon demo; **not fine** for anything where "who approved this" needs
to be trustworthy — that requires wiring these endpoints to real
authentication (Django's built-in auth, SSO, etc.) before production use.

---

## 1. Endpoints at a glances

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health/` | Liveness check |
| POST | `/api/requests/` | Submit a prompt through the full pipeline |
| POST | `/api/feedback/<request_id>/thumbs-down/` | Record user dissatisfaction |
| GET | `/dashboard/` | Operational metrics overview |
| GET | `/dashboard/trends/` | Safety/quality trend metrics |
| GET, POST | `/dashboard/human-review/` | List pending cases / submit a reviewer decision |
| GET, POST | `/dashboard/fpr-tuning/` | Check FPR, simulate a threshold change, propose a change, report a false positive |
| GET | `/admin/` | Django admin — browse all models, approve/reject threshold proposals |

All examples below assume the dev server is running at
`http://127.0.0.1:8000` (`python manage.py runserver`).

---

## 2. Health check

```bash
curl http://127.0.0.1:8000/api/health/
```

**Expected:** `200 OK`, body `{"status": "ok"}`. If this fails, nothing
else will work — check the server is running and migrations are applied.

---

## 3. Submit a request — `/api/requests/`

This is the main endpoint. It runs the full pipeline (pre-request analysis
→ routing → simulated model call → auditing → policy engine → decision
executor) and persists a `Trace` + `AuditRecord` in MySQL.

**Request shape (all flows):**

```json
{
  "raw_prompt": "string, required",
  "user_id": "string, required",
  "session_id": "uuid v4 string, required",
  "use_case_id": "CustomerSupport | InternalKnowledge | DecisionSupport, required",
  "client_metadata": {"optional": "object"}
}
```

**Response shape (all flows):**

```json
{
  "request_id": "uuid",
  "session_id": "uuid",
  "status": "ALLOW | MODIFY | HUMAN_REVIEW | BLOCK",
  "message": "string or null",
  "disclosure_notice": "string or null",
  "timestamp": "ISO-8601"
}
```

`VERIFY` never appears as a final `status` — it always resolves into one
of the other four (see flow D/E below).

### Flow A — ALLOW

A plain prompt with no PII and no high-risk keywords.

```bash
curl -X POST http://127.0.0.1:8000/api/requests/ \
  -H "Content-Type: application/json" \
  -d '{
        "raw_prompt": "What are your business hours?",
        "user_id": "test-user-1",
        "session_id": "11111111-1111-4111-8111-111111111111",
        "use_case_id": "CustomerSupport"
      }'
```

**Expected:** HTTP `200`, `"status": "ALLOW"`, `"message"` containing the
simulated model response text, `"disclosure_notice": null`.

**Check in the DB:**

```bash
python manage.py shell -c "
from core.models import Trace, AuditRecord
t = Trace.objects.latest('timestamp')
print('trace.status:', t.status, '| final_decision:', t.final_decision)
r = AuditRecord.objects.get(trace=t)
print('final_action:', r.final_action)
print('audit_quality keys:', list(r.audit_quality.keys()))
print('audit_responsibility keys:', list(r.audit_responsibility.keys()))
print('response_metrics:', r.response_metrics)
"
```

**Expected:** `trace.status = CLOSED`, `final_decision = ALLOW`, the audit
record's `final_action = ALLOW`, both score dicts populated (12 dimensions
total across the two), and `response_metrics` containing `model_used`,
`input_tokens`, `output_tokens`, `latency_ms`, `cost_usd`, `finish_reason`.

### Flow B — BLOCK (router pre-check)

A prompt matching the Critical risk band (Section 3 Step 2, 2C) —
deterministically scores `risk_score = 9`, which the Model Router
pre-check blocks *before any model call is made* (Section 3 Step 3).

```bash
curl -X POST http://127.0.0.1:8000/api/requests/ \
  -H "Content-Type: application/json" \
  -d '{
        "raw_prompt": "This is a regulated decision affecting a safety-critical hospital system.",
        "user_id": "test-user-1",
        "session_id": "22222222-2222-4222-8222-222222222222",
        "use_case_id": "DecisionSupport"
      }'
```

**Expected:** HTTP `200`, `"status": "BLOCK"`, `"message"` exactly:
`"This response cannot be provided as it may contain sensitive information."`
— the same generic message regardless of the actual trigger, per Section 3
Step 9's "does NOT reveal internal thresholds or scoring rules."

**Check in the DB:**

```bash
python manage.py shell -c "
from core.models import AuditRecord
r = AuditRecord.objects.latest('timestamp')
print('final_action:', r.final_action)
print('policy_rules_triggered:', r.policy_rules_triggered)
print('response_metrics (should be empty — no model call happened):', r.response_metrics)
"
```

**Expected:** `final_action = BLOCK`, `policy_rules_triggered =
["ROUTER_PRE_CHECK:risk_score"]`, `response_metrics = {}` (proving no
model call happened before the block).

### Flow C — MODIFY (PII detection)

A prompt containing PII. Every seeded use case's `modify` policy bucket
treats `pii_detected: true` as an automatic trigger (Section 5.1 example).

```bash
curl -X POST http://127.0.0.1:8000/api/requests/ \
  -H "Content-Type: application/json" \
  -d '{
        "raw_prompt": "Please update my contact email to john.smith@example.com.",
        "user_id": "test-user-1",
        "session_id": "33333333-3333-4333-8333-333333333333",
        "use_case_id": "InternalKnowledge"
      }'
```

**Expected:** HTTP `200`, `"status": "MODIFY"`, `"disclosure_notice"` set
to a non-null string (default: *"This response has been modified to
remove sensitive information."*).

Note: the redaction target is the **model's response text**, not your
original prompt (Section 3 Step 9: "The response is passed to a
redaction/modification module"). The simulated model's canned reply never
echoes your prompt's PII back, so `"message"` will look like
`"[simulated response from ...]"` unchanged — the MODIFY *path* fired
correctly (confirmed by `status` and the log below), but there is nothing
in this particular stub reply to visibly redact.

**Check in the DB:**

```bash
python manage.py shell -c "
from core.models import AuditRecord
r = AuditRecord.objects.latest('timestamp')
print('final_action:', r.final_action)
print('pre_request:', r.pre_request)
print('modification log keys:', list(r.modification.keys()))
print('categories_redacted:', r.modification['categories_redacted'])
"
```

**Expected:** `final_action = MODIFY`, `pre_request['pii_detected_in_prompt']
= True` with `EMAIL` in `pii_categories`, and a `modification` dict with
`original_content_encrypted`, `modified_output`, `categories_redacted` keys.

To confirm the encryption genuinely round-trips:

```bash
python manage.py shell -c "
from core.models import AuditRecord
from core.decision_executor import decrypt_original_content
r = AuditRecord.objects.latest('timestamp')
print(decrypt_original_content(r.modification['original_content_encrypted']))
"
```

**Expected:** prints the original (unredacted) simulated response text.

### Flow D & E — VERIFY/RETRY, then HUMAN_REVIEW (needs a shell session)

The simulated auditor (`core.auditing_engine.call_auditor_model`) is a
**deterministic stub that ignores prompt content** — it always reports
"no issues" unless mocked. This means VERIFY and HUMAN_REVIEW-by-audit-score
cannot be triggered by prompt content alone through `curl`; they require
patching that one function, which only works inside the same Python
process — so use `python manage.py shell`, not a separate `curl` call
against the running dev server.

Open a shell and run this in one paste:

```python
python manage.py shell
```

```python
import json
from unittest.mock import patch
from core.models import Trace, UseCaseProfile

from core import pipeline

use_case = UseCaseProfile.objects.get(use_case_id="DecisionSupport")
trace = Trace.objects.create(user_id="manual-test", use_case=use_case,
                              raw_prompt="Summarise this document for me.")

def audit_payload(**overrides):
    payload = {}
    for dim in ["correctness", "relevance", "completeness", "instruction_following", "consistency"]:
        payload[f"{dim}_score"] = 9
        payload[f"{dim}_reason"] = "ok"
    for dim in ["hallucination_risk", "safety_risk", "bias_risk", "toxicity_risk",
                "data_leakage_risk", "policy_violation_risk", "prompt_injection_risk"]:
        payload[f"{dim}_score"] = 1
        payload[f"{dim}_reason"] = "ok"
    payload["recommended_action"] = "ALLOW"
    payload.update(overrides)
    return json.dumps(payload)

# --- Flow D: VERIFY on the first attempt, then a clean retry succeeds ---
bad = audit_payload(hallucination_risk_score=6, recommended_action="VERIFY")   # DecisionSupport verify threshold is 6
good = audit_payload()  # all clear
with patch("core.auditing_engine.call_auditor_model", side_effect=[bad, good]):
    result = pipeline.process_request(trace)
print("Flow D result:", result["final_action"])  # expect: ALLOW
print("retry_attempts recorded:", len(result.get("audit_record") and [] or []))
```

**Expected:** `Flow D result: ALLOW` — the first attempt triggered VERIFY,
the retry (same model, "enhanced" prompt per Section 3 Step 9) came back
clean, and the request resolved to ALLOW without ever reaching the user
as a delay/queue.

```python
# --- Flow E: VERIFY on every attempt, retries exhausted -> HUMAN_REVIEW ---
trace2 = Trace.objects.create(user_id="manual-test", use_case=use_case,
                               raw_prompt="Summarise this document for me.")
with patch("core.auditing_engine.call_auditor_model", return_value=bad):
    result2 = pipeline.process_request(trace2)
print("Flow E result:", result2["final_action"])  # expect: HUMAN_REVIEW
print("message:", result2["user_response"])
```

**Expected:** `Flow E result: HUMAN_REVIEW`, with `message` telling the
user their request is queued with an estimated wait time (default 30
minutes). Confirm the queue entry:

```python
from core.models import AuditRecord
r = AuditRecord.objects.get(trace=trace2)
print(r.human_review_status)         # PENDING
print(r.human_review["policy_trigger_reason"])
```

### Flow F — HUMAN_REVIEW directly from an audit score

Same shell session as above:

```python
trace3 = Trace.objects.create(user_id="manual-test", use_case=use_case,
                               raw_prompt="Give me guidance on this matter.")
hr_payload = audit_payload(safety_risk_score=7, recommended_action="HUMAN_REVIEW")  # DecisionSupport human_review threshold is 7
with patch("core.auditing_engine.call_auditor_model", return_value=hr_payload):
    result3 = pipeline.process_request(trace3)
print("Flow F result:", result3["final_action"])  # expect: HUMAN_REVIEW
```

**Expected:** `HUMAN_REVIEW`, triggered directly by the safety_risk score
rather than by exhausting VERIFY retries.

---

## 4. Multi-turn session-risk escalation

Demonstrates Section 6.1: a rolling average of per-turn risk scores that,
once it crosses a threshold, tightens policy thresholds for later turns in
the *same session*.

```bash
SID="44444444-4444-4444-8444-444444444444"
for i in 1 2 3 4 5; do
  curl -s -X POST http://127.0.0.1:8000/api/requests/ \
    -H "Content-Type: application/json" \
    -d "{\"raw_prompt\": \"Please advise on this financial advice matter.\", \"user_id\": \"escalation-test\", \"session_id\": \"$SID\", \"use_case_id\": \"DecisionSupport\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])"
done
```

("financial advice" scores in the 7–8 risk band per Section 3 Step 2, 2C —
each turn alone is well below any BLOCK/HUMAN_REVIEW threshold.)

**Check the accumulator:**

```bash
python manage.py shell -c "
from core.models import SessionState
s = SessionState.objects.get(session_id='44444444-4444-4444-8444-444444444444')
print('turn_number:', s.turn_number)
print('recent_risk_scores:', s.recent_risk_scores)
print('session_risk_accumulator:', s.session_risk_accumulator)
print('previous_decisions:', s.previous_decisions)
"
```

**Expected:** `turn_number = 5`, `recent_risk_scores` holding the last 5
per-turn risk scores, and `session_risk_accumulator` equal to their
average. If that average reaches DecisionSupport's `session_risk_threshold`
(`5.0`), a 6th turn in this same session gets evaluated against
*tightened* thresholds (`core/session_risk.py:escalate_policy_config`) —
see `core.tests.BorderlineSessionEscalationIntegrationTests` for a fully
worked, deterministic version of this same scenario.

---

## 5. Thumbs-down feedback

```bash
curl -X POST "http://127.0.0.1:8000/api/feedback/<request_id>/thumbs-down/" \
  -H "Content-Type: application/json" \
  -d '{"comment": "This answer was not helpful."}'
```

Replace `<request_id>` with a real `request_id` from any earlier response.

**Expected:** HTTP `201`, body `{"feedback_id": <int>, "trace_id": "<uuid>"}`.
An unknown `request_id` returns `404`. The body may be omitted entirely
(still returns `201`, with an empty comment).

**Check:**

```bash
python manage.py shell -c "
from core.models import UserFeedback
f = UserFeedback.objects.latest('created_at')
print(f.trace_id, f.comment, f.reviewed)
"
```

**Expected:** `reviewed = False` — thumbs-down entries start unreviewed
(Section 7.1: "flagged for reviewer attention").

---

## 6. Dashboard — `/dashboard/`

Open in a browser, or check headlessly:

```bash
curl -s http://127.0.0.1:8000/dashboard/ | grep -o 'id="total-requests-24h">[^<]*'
```

**Expected:** the count of requests submitted in the last 24 hours,
matching however many you've run through Sections 3–4 above. The page also
shows decision distribution (with a bar chart), latency percentiles, total
cost today, cost per model, and the active human-review queue count.

`/dashboard/trends/?days=7` shows hallucination rate, safety violation
rate, data leakage attempts, bias detection rate, blocked-request rate,
retry/verify rate, and human-review rate over the given window (default 7
days; pass `?days=30` for a longer one).

---

## 7. Human review queue — `/dashboard/human-review/`

Unlike `/api/requests/` and the feedback endpoint (both external-API
endpoints, exempt from CSRF protection), this is a genuine **browser-facing
dashboard form**, correctly CSRF-protected like any real Django form. The
simplest way to test it is a browser: open the URL, fill in the form for a
pending row, submit. If you want to script it instead, you need a cookie
jar and the page's own CSRF token — a bare `curl -X POST -d ...` with no
token will get HTTP `403 CSRF verification failed`, and that is the form
working correctly, not a bug.

**GET** — list pending cases:

```bash
curl -s http://127.0.0.1:8000/dashboard/human-review/ | grep -o 'data-trace-id="[^"]*"'
```

**Expected:** one row per `AuditRecord` with `human_review_status =
PENDING` (e.g. from Flow E or F above).

**POST** — submit a reviewer decision, scripted with a cookie jar. Pick a
real pending `trace_id` from the list above:

```bash
COOKIES=$(mktemp)
CSRF=$(curl -s -c "$COOKIES" http://127.0.0.1:8000/dashboard/human-review/ \
  | grep -o 'csrfmiddlewaretoken" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')

curl -s -b "$COOKIES" -c "$COOKIES" -X POST http://127.0.0.1:8000/dashboard/human-review/ \
  --data-urlencode "csrfmiddlewaretoken=$CSRF" \
  --data-urlencode "trace_id=<pending-trace-id>" \
  --data-urlencode "reviewer_id=alice" \
  --data-urlencode "decision=APPROVE"
```

Valid `decision` values: `APPROVE`, `MODIFY` (also requires
`modified_response=<text>`), `REJECT`.

**Expected:** HTTP `200`, and the page now shows "Decision recorded:
APPROVE". Submitting `decision=MAYBE` (invalid) returns HTTP `400` with an
error message, and does **not** change the case's status.

**Check the gold-standard label was recorded:**

```bash
python manage.py shell -c "
from core.models import AuditRecord, ReviewerAction
r = AuditRecord.objects.get(trace_id='<pending-trace-id>')
print('human_review_status:', r.human_review_status)   # DECIDED
print('final_user_response:', r.human_review['final_user_response'])
a = ReviewerAction.objects.get(audit_record=r)
print('reviewer_id:', a.reviewer_id, '| decision:', a.decision)
"
```

**Expected:** `human_review_status = DECIDED`, and a `ReviewerAction` row
exists — this is the "gold-standard label" the doc's feedback loop
(Section 7.1) is built on. Re-loading `/dashboard/human-review/` no longer
lists this case as pending.

---

## 8. FPR tuning — `/dashboard/fpr-tuning/`

Also a real browser-facing dashboard form (see the CSRF note in Section 7
— same reasoning applies here). Four independent form actions on the same
page/endpoint. Get one shared cookie jar + CSRF token first, then reuse
both for all four actions below:

```bash
COOKIES=$(mktemp)
CSRF=$(curl -s -c "$COOKIES" http://127.0.0.1:8000/dashboard/fpr-tuning/ \
  | grep -o 'csrfmiddlewaretoken" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
```

### 8.1 Report a false positive

```bash
curl -s -b "$COOKIES" -c "$COOKIES" -X POST http://127.0.0.1:8000/dashboard/fpr-tuning/ \
  --data-urlencode "csrfmiddlewaretoken=$CSRF" \
  --data-urlencode "action=report_false_positive" \
  --data-urlencode "trace_id=<any-existing-trace-id>" \
  --data-urlencode "dimension=hallucination_risk" \
  --data-urlencode "reported_by=alice" \
  --data-urlencode "reason=Manually verified as correct."
```

**Expected:** HTTP `200`, page shows "Recorded false-positive report for
'hallucination_risk'." A `FalsePositiveReport` row is created.

### 8.2 Check false-positive rate for a dimension

```bash
curl -s -b "$COOKIES" -c "$COOKIES" -X POST http://127.0.0.1:8000/dashboard/fpr-tuning/ \
  --data-urlencode "csrfmiddlewaretoken=$CSRF" \
  --data-urlencode "action=check_fpr" \
  --data-urlencode "use_case_id=DecisionSupport" \
  --data-urlencode "dimension=hallucination_risk" \
  --data-urlencode "days=30"
```

**Expected:** a result block showing `flagged_count`, `false_positive_count`,
and `fpr` (= the second divided by the first) for that dimension, over the
last 30 days, for that use case.

### 8.3 Simulate a threshold change

```bash
curl -s -b "$COOKIES" -c "$COOKIES" -X POST http://127.0.0.1:8000/dashboard/fpr-tuning/ \
  --data-urlencode "csrfmiddlewaretoken=$CSRF" \
  --data-urlencode "action=simulate_threshold_change" \
  --data-urlencode "use_case_id=DecisionSupport" \
  --data-urlencode "bucket=verify" \
  --data-urlencode "dimension=hallucination_risk" \
  --data-urlencode "new_threshold=8" \
  --data-urlencode "days=30"
```

**Expected:** a result block showing the current vs. proposed threshold,
`flags_before`/`flags_after` (how many historical requests would have been
flagged under each), `reduction_pct`, and `missed_confirmed_issues` (flags
that would stop firing under the new threshold and were never reported as
false positives — i.e., presumed real issues the looser threshold would miss).

### 8.4 Propose a threshold change

```bash
curl -s -b "$COOKIES" -c "$COOKIES" -X POST http://127.0.0.1:8000/dashboard/fpr-tuning/ \
  --data-urlencode "csrfmiddlewaretoken=$CSRF" \
  --data-urlencode "action=propose_threshold" \
  --data-urlencode "use_case_id=DecisionSupport" \
  --data-urlencode "bucket=verify" \
  --data-urlencode "dimension=hallucination_risk" \
  --data-urlencode "current_threshold=6" \
  --data-urlencode "proposed_threshold=8" \
  --data-urlencode "rationale=High FPR observed over the last 30 days."
```

**Expected:** HTTP `200`, page shows "Proposal #N created, status
PENDING." — and the proposal now appears in the "Pending proposals" table
on the same page.

---

## 9. Admin — approving a threshold proposal

1. Go to `http://127.0.0.1:8000/admin/` and log in with your superuser
   account (see Section 0.1 — none exists until you create one).
2. Under **Core → Threshold change proposals**, select the proposal
   created in Section 8.4.
3. From the Actions dropdown, choose **"Approve selected threshold change
   proposals"** (or **"Reject..."**) and click **Go**.

**Expected:** the proposal's `status` becomes `APPROVED` (or `REJECTED`),
with `reviewed_by` set to your admin username and `reviewed_at` stamped.

Note: approving a proposal here **only records the decision** — it does
not automatically rewrite the corresponding `core/config/policies/*.yaml`
file. Per Section 5's "config reload, no code deployment" model, actually
applying an approved change means manually editing that YAML file's
threshold to match; there is no auto-apply wiring in this prototype.

You can also browse every other model here (`UseCaseProfile`, `PolicyConfig`,
`Trace`, `SessionState`, `AuditRecord`, `ReviewerAction`, `UserFeedback`,
`FalsePositiveReport`) — useful for spot-checking any of the flows above
without writing shell scripts.

---

## 10. Running the automated suite instead

Everything demonstrated manually above (and considerably more edge-case
coverage) is already encoded as automated tests. To re-run all of it:

```bash
python manage.py test core -v 2
```

To re-run just one flow's tests, e.g. the end-to-end scenarios from
Section 3-4:

```bash
python manage.py test core.tests.EndToEndPipelineScenarioTests -v 2
python manage.py test core.tests.SessionRiskEscalationLivePipelineTests -v 2
python manage.py test core.tests.HumanReviewDecisionViewTests -v 2
python manage.py test core.tests.FprTuningViewTests -v 2
```

**Expected:** all pass (`OK`), against a real MySQL test database created
and destroyed automatically — no mocked DB layer.

---

## 11. Cleaning up test data

Everything in Sections 2–9 writes real rows to your MySQL database. To
reset before a clean demo run:

```bash
python manage.py shell -c "
from core.models import Trace, SessionState, ReviewerAction, UserFeedback, FalsePositiveReport, ThresholdChangeProposal
ReviewerAction.objects.all().delete()
UserFeedback.objects.all().delete()
FalsePositiveReport.objects.all().delete()
ThresholdChangeProposal.objects.all().delete()
SessionState.objects.all().delete()
Trace.objects.all().delete()  # cascades to AuditRecord
print('cleared')
"
```

This does **not** delete your `UseCaseProfile` rows — re-seed those
separately only if you want to reset their configuration too.
