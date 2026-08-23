# ControlPlane.ai

A Django + MySQL implementation of the ControlPlane.ai Responsible AI Control
Layer architecture (Accenture Hackathon, 2026). It wraps an AI interaction in
a full control loop: pre-request analysis (PII detection, complexity/risk
scoring) → model routing → simulated model execution + objective metrics →
AI-as-judge auditing across 12 dimensions → a deterministic policy engine
(with multi-turn session-risk escalation and geography/regulation rules) →
one of five decision paths (ALLOW / VERIFY-RETRY / MODIFY / HUMAN_REVIEW /
BLOCK) → an operator dashboard and feedback loop.

## Requirements

- Python 3.14 (works with 3.11+; developed against 3.14)
- MySQL 8+ (developed against MySQL 9.7 via Homebrew)
- macOS/Linux shell (setup below uses Homebrew for MySQL)

## Setup

```bash
# 1. MySQL (skip if you already have a server running)
brew install mysql
brew services start mysql
mysql -u root -e "CREATE DATABASE IF NOT EXISTS controlplane_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# 2. Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. spaCy's small English model (used for PERSON/ORGANIZATION/LOCATION
#    PII detection — see requirements.txt for details)
python -m spacy download en_core_web_sm

# 4. Environment config
cp .env.example .env
# Edit .env: set DB_USER/DB_PASSWORD if not using local root-with-no-password,
# and set MODIFICATION_LOG_ENCRYPTION_KEY to a real Fernet key:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 5. Migrate
python manage.py migrate

# 6. Create an admin user (for /admin/ and human-review approvals)
python manage.py createsuperuser

# 7. Seed the three baseline use-case profiles
python manage.py shell -c "
from core.models import UseCaseProfile
for uc in ['CustomerSupport', 'InternalKnowledge', 'DecisionSupport']:
    UseCaseProfile.objects.get_or_create(use_case_id=uc, defaults={'name': uc})
"

# 8. Run
python manage.py runserver
```

## Running the tests

```bash
python manage.py test core -v 2
```

The suite runs against a real MySQL test database (`test_controlplane_db`),
created and torn down automatically — no mocked DB layer.

## Using it

### Submit a request

```bash
curl -X POST http://127.0.0.1:8000/api/requests/ \
  -H "Content-Type: application/json" \
  -d '{
        "raw_prompt": "What are your business hours?",
        "user_id": "demo-user",
        "session_id": "11111111-1111-4111-8111-111111111111",
        "use_case_id": "CustomerSupport"
      }'
```

Response shape:

```json
{
  "request_id": "...",
  "session_id": "...",
  "status": "ALLOW",
  "message": "...",
  "disclosure_notice": null,
  "timestamp": "..."
}
```

`status` is one of `ALLOW`, `MODIFY`, `HUMAN_REVIEW` (HTTP 202 — the response
is a wait notice, not final content), or `BLOCK`. `VERIFY` is never a final
status — it always resolves into one of the other four after the
retry/escalation flow (Section 3 Step 9).

### Demonstrating each decision path

- **ALLOW** — any everyday prompt with no PII and no high-risk keywords.
- **BLOCK** — a prompt matching the Critical risk band, e.g. *"This is a
  regulated decision affecting a safety-critical hospital system."*
  Triggers the Model Router's pre-check block (risk score 9–10) before any
  model call is made.
- **MODIFY** — a prompt containing PII, e.g. *"Please update my email to
  john.smith@example.com."* Every use-case's policy config treats detected
  PII as an automatic MODIFY trigger.
- **HUMAN_REVIEW / VERIFY** — these depend on the *generated response's*
  audit scores, which the simulated model/auditor stubs don't vary by
  prompt content (see "Simulated models" below) — reachable live only by
  mocking `core.auditing_engine.call_auditor_model`, as the test suite does
  in `core.tests.EndToEndPipelineScenarioTests`.

### Dashboard

- `/dashboard/` — decision distribution, latency/cost, human review queue size
- `/dashboard/trends/` — hallucination/safety/bias/leakage trend rates
- `/dashboard/human-review/` — pending HUMAN_REVIEW queue + reviewer decision form
- `/dashboard/fpr-tuning/` — false-positive-rate lookup, threshold-change simulation and proposal
- `/admin/` — Django admin: all models, plus approve/reject actions for threshold proposals

### Feedback

```bash
curl -X POST http://127.0.0.1:8000/api/feedback/<request_id>/thumbs-down/ \
  -H "Content-Type: application/json" -d '{"comment": "Not helpful"}'
```

## Architecture notes

- **Simulated models.** Section 1.3/11.1 of the architecture document
  explicitly permit a prototype "with simulated models," and the model IDs
  the document names (`claude-haiku-4-5`, `claude-sonnet-4-6`) aren't real
  callable model identifiers — so `core/model_pipeline.py` and
  `core/auditing_engine.py` simulate the generating model and the auditor
  deterministically rather than calling a live API. Every seam
  (`call_generating_model`, `call_auditor_model`) is a plain function, so
  swapping in a real API call later is a drop-in replacement.
- **Module layout mirrors the document's pipeline stages** — one module per
  stage (`pre_request_analysis.py`, `model_pipeline.py`, `auditing_engine.py`,
  `policy_engine.py`, `session_risk.py`, `agentic_gate.py`,
  `decision_executor.py`, `regulation_library.py`, `dashboard.py`),
  independently unit-tested, then composed by `core/pipeline.py` and
  exposed at `/api/requests/` (`core/views.py`).
- **Policy thresholds live in YAML files** (`core/config/policies/`), not
  code, per the document's own "config reload, no code deployment" framing.
  Only `DecisionSupport.yaml`'s thresholds are a literal transcription of a
  document example (Section 5.1); `CustomerSupport.yaml` and
  `InternalKnowledge.yaml` use clearly-flagged illustrative placeholder
  values, since the document gives no concrete numbers for those two
  profiles anywhere.
- **Regulations live in YAML files** (`core/config/regulations/`) — GDPR,
  DPDP, CCPA, EU_AI_Act, HIPAA — versioned per Section 8. GDPR/DPDP's
  version strings and GDPR's 72-hour breach notification window are taken
  directly from the document; the other three regulations' version strings
  are illustrative placeholders (no document-given values exist for them).

### Known inconsistencies in the source document

Found while implementing, and resolved by following the document's literal
wording rather than picking a number that "looks right":

1. Section 4.1's composite-risk formula, applied to the Appendix's (14.1)
   own worked example, yields 3.3 — not the 2.8 the Appendix states.
2. Section 3 Step 8's illustrative rule examples use different threshold
   numbers than Section 5.1's actual concrete `DecisionSupport` YAML
   example. `DecisionSupport.yaml` follows 5.1's literal numbers.
3. Section 3 Step 4 says "30s for DecisionSupport"; Section 5.1's own YAML
   example says `latency_budget_ms: 8000` (8s) for the same profile.
   `DecisionSupport.yaml` follows 5.1's literal value.

See the module docstrings for the full reasoning behind each.
