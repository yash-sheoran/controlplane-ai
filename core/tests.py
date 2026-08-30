import json
import time
import uuid
from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth.models import User
from django.test import TestCase

from . import agentic_gate as ag
from . import auditing_engine as ae
from . import dashboard
from . import decision_executor as de
from . import model_pipeline as mp
from . import policy_engine as pe
from . import pre_request_analysis as pra
from . import regulation_library as rl
from . import session_risk as sr
from .models import (
    AuditRecord,
    FalsePositiveReport,
    ReviewerAction,
    SessionState,
    ThresholdChangeProposal,
    Trace,
    UserFeedback,
    UserProfile,
)
from .views import SAFE_ERROR_MESSAGE


def _make_manager(username, password="testpass123!"):
    """Test helper: a manager account whose team-scoped dashboard views
    (core.dashboard_views, gated by core.authz.manager_required) will see
    Trace/AuditRecord rows created with user_id=username — i.e. the
    manager's own team, per core.authz.team_user_ids, is themselves plus
    any employee profiles pointing back at them."""
    user = User.objects.create_user(username=username, email=f"{username}@example.com", password=password)
    UserProfile.objects.create(user=user, role=UserProfile.ROLE_MANAGER)
    return user


def _make_employee(username, manager_user, password="testpass123!"):
    user = User.objects.create_user(username=username, email=f"{username}@example.com", password=password)
    UserProfile.objects.create(user=user, role=UserProfile.ROLE_EMPLOYEE, manager=manager_user.profile)
    return user


class HealthCheckTests(TestCase):
    """Smoke test for the step-1 scaffolding: the Django project boots, URL
    routing works, and a request round-trips through the app."""

    def test_health_check_returns_ok(self):
        response = self.client.get("/api/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})


class CoreModelsRegisteredInAdminTests(TestCase):
    """Confirms the 5 core models required by this step are registered with
    the Django admin site, so they are visible/manageable there."""

    def test_all_core_models_registered(self):
        for model in (Trace, SessionState, AuditRecord):
            self.assertIn(model, admin.site._registry, f"{model.__name__} not registered in admin")


class CoreModelsEmptyOnFreshMigrationTests(TestCase):
    """On a freshly migrated test database, every core table starts empty."""

    def test_tables_start_empty(self):
        self.assertEqual(Trace.objects.count(), 0)
        self.assertEqual(SessionState.objects.count(), 0)
        self.assertEqual(AuditRecord.objects.count(), 0)


class CoreModelsRelationshipTests(TestCase):
    """Sanity-checks the relationships and fields declared on the core models
    against the architecture doc's schemas (Section 5.1, 6.1, 6.3, 14.1, 14.2)."""

    def test_trace_opens_with_uuid_and_open_status(self):
        trace = Trace.objects.create(
            user_id="user-1",
            raw_prompt="What is the loan approval policy?",
            client_metadata={"channel": "web"},
        )
        self.assertIsNotNone(trace.request_id)
        self.assertEqual(trace.status, Trace.STATUS_OPEN)
        self.assertIsNone(trace.final_decision)

    def test_session_state_tracks_accumulator_and_history(self):
        session = SessionState.objects.create(
            turn_number=3,
            session_risk_accumulator=1.9,
            previous_decisions=["ALLOW", "ALLOW"],
        )
        self.assertEqual(session.previous_decisions, ["ALLOW", "ALLOW"])
        self.assertFalse(session.was_blocked)

    def test_audit_record_one_to_one_with_trace(self):
        trace = Trace.objects.create(
            user_id="user-1",
            raw_prompt="Summarise this contract.",
        )
        record = AuditRecord.objects.create(
            trace=trace,
            geography=["IN", "EU"],
            regulation_versions={"GDPR": "2024-Q4", "DPDP": "2024-Q2"},
            composite_risk_score=2.8,
            auditor_model="claude-sonnet-4-6",
            auditor_confidence=0.91,
            recommended_action="ALLOW",
            final_action="ALLOW",
        )
        self.assertEqual(trace.audit_record, record)
        self.assertEqual(record.recommended_action, "ALLOW")


class RequestIngestionAPITests(TestCase):
    """Section 3 Step 1 — Request Ingestion & Trace Initialisation.

    Inputs: raw_prompt, user_id, session_id, client_metadata
    Outputs: request_id (UUID), trace_object (open), timestamp
    Failure: all failures in this step result in a 503 with a safe error
    message; the trace is never lost.
    """

    url = "/api/requests/"

    def setUp(self):
        self.session_id = str(uuid.uuid4())
        self.valid_payload = {
            "raw_prompt": "What is your refund policy?",
            "user_id": "user-42",
            "session_id": self.session_id,
            "client_metadata": {"channel": "web"},
        }

    def post(self, payload):
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload)
        else:
            body = payload
        return self.client.post(self.url, data=body, content_type="application/json")

    # --- Success path -----------------------------------------------------

    def test_valid_request_creates_trace_and_runs_the_full_pipeline(self):
        """This project's Step 10: /api/requests/ now runs the full
        pipeline (Steps 2-9), so a successful request closes the trace
        with a real final_decision rather than leaving it OPEN — the
        contract Step 2 originally tested, before those later steps
        existed to wire in. With the default stub's "no issues" scores,
        this deterministically resolves to ALLOW."""
        response = self.post(self.valid_payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(Trace.objects.count(), 1)

        trace = Trace.objects.get()
        self.assertEqual(trace.raw_prompt, self.valid_payload["raw_prompt"])
        self.assertEqual(trace.user_id, self.valid_payload["user_id"])
        self.assertEqual(str(trace.session_id), self.session_id)
        self.assertEqual(trace.client_metadata, {"channel": "web"})
        self.assertEqual(trace.status, Trace.STATUS_CLOSED)
        self.assertEqual(trace.final_decision, "ALLOW")

        audit_record = AuditRecord.objects.get(trace=trace)
        self.assertEqual(audit_record.final_action, "ALLOW")
        self.assertTrue(audit_record.audit_quality)
        self.assertTrue(audit_record.audit_responsibility)

    def test_response_body_contains_request_id_status_and_timestamp(self):
        response = self.post(self.valid_payload)
        body = response.json()

        trace = Trace.objects.get()
        self.assertEqual(body["request_id"], str(trace.request_id))
        self.assertEqual(body["session_id"], self.session_id)
        self.assertEqual(body["status"], "ALLOW")
        self.assertIn("message", body)
        self.assertIn("timestamp", body)
        # request_id must be a valid UUID v4 (Section 3 Step 1 Outputs).
        parsed = uuid.UUID(body["request_id"])
        self.assertEqual(parsed.version, 4)

    def test_client_metadata_defaults_to_empty_dict_when_omitted(self):
        payload = dict(self.valid_payload)
        del payload["client_metadata"]
        response = self.post(payload)

        self.assertEqual(response.status_code, 200)
        trace = Trace.objects.get()
        self.assertEqual(trace.client_metadata, {})

    # --- Malformed payload -> 503, per Section 3 Step 1 Failure row -------

    def test_missing_raw_prompt_returns_503(self):
        payload = dict(self.valid_payload)
        del payload["raw_prompt"]
        response = self.post(payload)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": SAFE_ERROR_MESSAGE})

    def test_blank_raw_prompt_returns_503(self):
        payload = dict(self.valid_payload)
        payload["raw_prompt"] = "   "
        response = self.post(payload)
        self.assertEqual(response.status_code, 503)

    def test_missing_user_id_returns_503(self):
        payload = dict(self.valid_payload)
        del payload["user_id"]
        response = self.post(payload)
        self.assertEqual(response.status_code, 503)

    def test_missing_session_id_returns_503(self):
        payload = dict(self.valid_payload)
        del payload["session_id"]
        response = self.post(payload)
        self.assertEqual(response.status_code, 503)

    def test_malformed_session_id_returns_503(self):
        payload = dict(self.valid_payload)
        payload["session_id"] = "not-a-uuid"
        response = self.post(payload)
        self.assertEqual(response.status_code, 503)

    def test_client_metadata_wrong_type_returns_503(self):
        payload = dict(self.valid_payload)
        payload["client_metadata"] = "not-a-dict"
        response = self.post(payload)
        self.assertEqual(response.status_code, 503)

    def test_invalid_json_body_returns_503(self):
        response = self.post("{not valid json")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": SAFE_ERROR_MESSAGE})

    def test_json_array_body_returns_503(self):
        response = self.post([1, 2, 3])
        self.assertEqual(response.status_code, 503)

    def test_get_method_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    # --- "the trace is never lost" -----------------------------------------

    def test_no_trace_row_created_for_any_malformed_payload(self):
        bad_payloads = [
            {},
            {"raw_prompt": "hi"},
            {**self.valid_payload, "session_id": "bad"},
        ]
        for payload in bad_payloads:
            self.post(payload)
        self.assertEqual(Trace.objects.count(), 0)

    def test_internal_failure_during_trace_creation_returns_503_and_leaves_no_partial_trace(self):
        """Simulates an unexpected system-level failure (e.g. a dropped DB
        connection) during trace creation. Per spec this must still return a
        503 with the safe generic message, and must not leave behind a
        partial/corrupt trace row."""
        with patch(
            "core.views.Trace.objects.create",
            side_effect=RuntimeError("simulated connection loss"),
        ):
            response = self.post(self.valid_payload)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": SAFE_ERROR_MESSAGE})
        # The error message must not leak internal exception details.
        self.assertNotIn("simulated connection loss", response.content.decode())
        self.assertEqual(Trace.objects.count(), 0)


class PIIDetectionAndPseudonymizationTests(TestCase):
    """Section 3 Step 2, 2A — PII & Sensitive Content Scan. Feeds known PII
    strings and asserts correct pseudonymization and a reversible token
    map (Section 11.2 prototype scope: "the model receives [PERSON_1] and
    [EMAIL_1]")."""

    def test_person_and_email_are_pseudonymized_with_expected_placeholders(self):
        text = "My name is John Smith, contact me at john.smith@example.com."
        result = pra.detect_and_pseudonymize_pii(text)

        self.assertTrue(result["pii_detected"])
        self.assertIn("PERSON", result["pii_categories"])
        self.assertIn("EMAIL", result["pii_categories"])
        self.assertIn("[PERSON_1]", result["pseudonymized_text"])
        self.assertIn("[EMAIL_1]", result["pseudonymized_text"])
        self.assertNotIn("John Smith", result["pseudonymized_text"])
        self.assertNotIn("john.smith@example.com", result["pseudonymized_text"])

    def test_token_map_is_reversible(self):
        text = "My name is John Smith, contact me at john.smith@example.com."
        result = pra.detect_and_pseudonymize_pii(text)

        self.assertEqual(result["token_map"]["[PERSON_1]"], "John Smith")
        self.assertEqual(result["token_map"]["[EMAIL_1]"], "john.smith@example.com")

        restored = pra.depseudonymize(result["pseudonymized_text"], result["token_map"])
        self.assertEqual(restored, text)

    def test_multiple_same_category_entities_are_numbered_in_order(self):
        text = "Alice emailed Bob. Alice's email is alice@example.com and Bob's is bob@example.com."
        result = pra.detect_and_pseudonymize_pii(text)

        self.assertIn("[EMAIL_1]", result["pseudonymized_text"])
        self.assertIn("[EMAIL_2]", result["pseudonymized_text"])
        self.assertEqual(result["token_map"]["[EMAIL_1]"], "alice@example.com")
        self.assertEqual(result["token_map"]["[EMAIL_2]"], "bob@example.com")

        restored = pra.depseudonymize(result["pseudonymized_text"], result["token_map"])
        self.assertEqual(restored, text)

    def test_structured_pii_categories_detected(self):
        cases = {
            "EMAIL": "Reach me at test.user@company.com for details.",
            "PHONE_NUMBER": "Call me at 555-123-4567 tomorrow.",
            "CREDIT_CARD": "My card number is 4111 1111 1111 1111.",
            "NATIONAL_ID": "My SSN is 123-45-6789 on file.",
            "IP_ADDRESS": "The server IP address is 192.168.1.10 today.",
            "PASSPORT_NUMBER": "My passport number is A1234567 for the trip.",
        }
        for category, text in cases.items():
            with self.subTest(category=category):
                result = pra.detect_and_pseudonymize_pii(text)
                self.assertIn(category, result["pii_categories"], f"{category} not detected in: {text!r}")
                restored = pra.depseudonymize(result["pseudonymized_text"], result["token_map"])
                self.assertEqual(restored, text)

    def test_no_pii_detected_in_clean_text(self):
        text = "What is the boiling point of water at sea level?"
        result = pra.detect_and_pseudonymize_pii(text)
        self.assertFalse(result["pii_detected"])
        self.assertEqual(result["pii_categories"], [])
        self.assertEqual(result["token_map"], {})
        self.assertEqual(result["pseudonymized_text"], text)

    def test_empty_text_is_handled_safely(self):
        result = pra.detect_and_pseudonymize_pii("")
        self.assertFalse(result["pii_detected"])
        self.assertEqual(result["pseudonymized_text"], "")


class ComplexityScoreTests(TestCase):
    """Section 3 Step 2, 2B — Complexity Score (1-10). Feeds sample prompts
    of varying difficulty and asserts the score lands in the doc's band for
    that difficulty."""

    def test_simple_factual_prompt_scores_1_to_3(self):
        score = pra.complexity_score("What is the capital of France?")
        self.assertTrue(1 <= score <= 3)

    def test_moderate_summarisation_prompt_scores_4_to_6(self):
        score = pra.complexity_score("Please summarize this 10-page document for me.")
        self.assertTrue(4 <= score <= 6)

    def test_complex_financial_legal_analysis_prompt_scores_7_to_8(self):
        score = pra.complexity_score(
            "Perform a financial analysis of this merger and a legal analysis of the contracts."
        )
        self.assertTrue(7 <= score <= 8)

    def test_expert_regulatory_interpretation_prompt_scores_9_to_10(self):
        score = pra.complexity_score(
            "Provide a regulatory interpretation of this new tax law for our compliance team."
        )
        self.assertTrue(9 <= score <= 10)

    def test_conflicting_signals_score_at_the_higher_band(self):
        score = pra.complexity_score(
            "Please summarize this, then give a regulatory interpretation of the findings."
        )
        self.assertTrue(9 <= score <= 10)


class RiskScoreTests(TestCase):
    """Section 3 Step 2, 2C — Risk Score (1-10). Feeds sample prompts and
    asserts the score lands in the doc's band for that risk category."""

    def test_low_risk_entertainment_prompt_scores_1_to_3(self):
        score = pra.risk_score("Tell me an interesting fact for entertainment.")
        self.assertTrue(1 <= score <= 3)

    def test_medium_risk_customer_facing_prompt_scores_4_to_6(self):
        score = pra.risk_score("Draft a customer-facing response about a billing issue.")
        self.assertTrue(4 <= score <= 6)

    def test_high_risk_financial_and_legal_prompt_scores_7_to_8(self):
        score = pra.risk_score(
            "I need financial advice about my retirement and legal interpretation of this contract."
        )
        self.assertTrue(7 <= score <= 8)

    def test_critical_risk_regulated_safety_prompt_scores_9_to_10(self):
        score = pra.risk_score(
            "This is a regulated decision affecting a safety-critical hospital system."
        )
        self.assertTrue(9 <= score <= 10)

    def test_pii_context_floors_risk_at_high_band(self):
        score = pra.risk_score("Just say hi back to me.", pii_detected=True)
        self.assertTrue(score >= 7)

    def test_pii_context_does_not_lower_an_already_higher_score(self):
        score = pra.risk_score(
            "This is a regulated decision affecting a safety-critical hospital system.",
            pii_detected=True,
        )
        self.assertTrue(9 <= score <= 10)


class ModelRouterTests(TestCase):
    """Section 3 Step 3 — Model Router. Table-driven tests confirming the
    doc's example routing table (complexity 1-3/risk 1-4 -> cheap model,
    risk 9-10 -> pre-block, etc.)."""

    # (complexity, risk, expected_tier, expected_blocked)
    ROUTING_TABLE_CASES = [
        (1, 1, "low", False),
        (2, 3, "low", False),
        (3, 4, "low", False),
        (3, 6, "low", False),  # gap in the doc's literal table, resolved to low tier
        (4, 1, "mid", False),
        (5, 3, "mid", False),
        (6, 6, "mid", False),
        (7, 1, "high", False),  # complexity=7 boundary resolved to the higher tier
        (8, 3, "high", False),
        (10, 6, "high", False),
        (1, 7, "expert", False),  # "any complexity, risk 7-10" (minus 9-10) -> expert
        (5, 8, "expert", False),
        (10, 7, "expert", False),
        (1, 9, None, True),
        (5, 9, None, True),
        (10, 10, None, True),
    ]

    def test_routing_table(self):
        for complexity, risk, expected_tier, expected_blocked in self.ROUTING_TABLE_CASES:
            with self.subTest(complexity=complexity, risk=risk):
                result = mp.select_model(complexity, risk)
                self.assertEqual(result["blocked"], expected_blocked)
                self.assertEqual(result["tier"], expected_tier)
                if expected_blocked:
                    self.assertIsNone(result["model"])
                    self.assertEqual(result["candidate_models_evaluated"], [])
                else:
                    self.assertEqual(result["model"], mp.MODEL_REGISTRY[expected_tier])
                    self.assertIn(result["model"], result["candidate_models_evaluated"])
                self.assertTrue(result["selection_reason"])

    def test_mandatory_strict_audit_flag_only_on_expert_tier(self):
        self.assertTrue(mp.select_model(1, 7)["mandatory_strict_audit"])
        self.assertFalse(mp.select_model(1, 1)["mandatory_strict_audit"])
        self.assertFalse(mp.select_model(10, 6)["mandatory_strict_audit"])
        self.assertFalse(mp.select_model(10, 10)["mandatory_strict_audit"])

    def test_risk_9_or_10_blocks_regardless_of_complexity(self):
        for complexity in range(1, 11):
            with self.subTest(complexity=complexity):
                for risk in (9, 10):
                    result = mp.select_model(complexity, risk)
                    self.assertTrue(result["blocked"])


class ModelExecutionRetryTests(TestCase):
    """Section 3 Step 4 — AI Model Execution: timeout enforcement and
    exponential-backoff retry (max 2 retries), with the actual model call
    mocked so no real work happens."""

    def test_successful_call_returns_zero_retries(self):
        fixed_response = {
            "model": "claude-haiku-4-5",
            "text": "ok",
            "usage": {"input_tokens": 5, "output_tokens": 3},
            "finish_reason": "stop",
        }
        with patch("core.model_pipeline.call_generating_model", return_value=fixed_response):
            response, elapsed_ms, retry_count = mp.execute_with_retry(
                "claude-haiku-4-5", "hello", timeout_s=5.0, max_retries=2, backoff_base_s=0.01
            )
        self.assertEqual(response, fixed_response)
        self.assertEqual(retry_count, 0)
        self.assertGreaterEqual(elapsed_ms, 0)

    def test_transient_failure_then_success_records_one_retry(self):
        fixed_response = {
            "model": "claude-haiku-4-5",
            "text": "ok",
            "usage": {"input_tokens": 5, "output_tokens": 3},
            "finish_reason": "stop",
        }
        with patch(
            "core.model_pipeline.call_generating_model",
            side_effect=[RuntimeError("transient failure"), fixed_response],
        ):
            response, elapsed_ms, retry_count = mp.execute_with_retry(
                "claude-haiku-4-5", "hello", timeout_s=5.0, max_retries=2, backoff_base_s=0.01
            )
        self.assertEqual(response, fixed_response)
        self.assertEqual(retry_count, 1)

    def test_exhausted_retries_raises_after_max_retries_plus_one_attempts(self):
        with patch(
            "core.model_pipeline.call_generating_model",
            side_effect=RuntimeError("permanent failure"),
        ) as mocked_call:
            with self.assertRaises(mp.ModelExecutionError):
                mp.execute_with_retry(
                    "claude-haiku-4-5", "hello", timeout_s=5.0, max_retries=2, backoff_base_s=0.01
                )
        self.assertEqual(mocked_call.call_count, 3)  # initial attempt + 2 retries

    def test_slow_call_exceeding_timeout_is_treated_as_a_failure_and_retried(self):
        fast_response = {
            "model": "claude-haiku-4-5",
            "text": "ok",
            "usage": {"input_tokens": 5, "output_tokens": 3},
            "finish_reason": "stop",
        }

        call_count = {"n": 0}

        def slow_then_fast(model_id, prompt):
            call_count["n"] += 1
            if call_count["n"] == 1:
                time.sleep(0.05)
            return fast_response

        with patch("core.model_pipeline.call_generating_model", side_effect=slow_then_fast):
            response, elapsed_ms, retry_count = mp.execute_with_retry(
                "claude-haiku-4-5", "hello", timeout_s=0.01, max_retries=2, backoff_base_s=0.01
            )
        self.assertEqual(response, fast_response)
        self.assertEqual(retry_count, 1)
        self.assertEqual(call_count["n"], 2)


class MetricsCollectionTests(TestCase):
    """Section 3 Step 5 — Objective Metrics Collection: values must be read
    directly from the (mocked) model response, never independently
    estimated, and cost must come from the pricing config file."""

    def test_metrics_are_copied_verbatim_from_the_response_not_estimated(self):
        response = {
            "model": "claude-sonnet-4-6",
            "text": "a very short prompt should not imply these huge token counts",
            "usage": {"input_tokens": 920, "output_tokens": 480},
            "finish_reason": "stop",
        }
        metrics = mp.collect_metrics(response, elapsed_ms=1240.0, retry_count=0)

        self.assertEqual(metrics["model_used"], "claude-sonnet-4-6")
        self.assertEqual(metrics["input_tokens"], 920)
        self.assertEqual(metrics["output_tokens"], 480)
        self.assertEqual(metrics["total_tokens"], 1400)
        self.assertEqual(metrics["latency_ms"], 1240.0)
        self.assertEqual(metrics["retry_count"], 0)
        self.assertEqual(metrics["finish_reason"], "stop")
        self.assertIsNone(metrics["ttft_ms"])

    def test_token_counts_are_not_derived_from_prompt_or_response_text_length(self):
        """A one-word 'prompt' with deliberately huge, unrelated token
        counts in the mocked response proves collect_metrics passes
        through the response's own numbers rather than re-deriving them
        from text length."""
        response = {
            "model": "claude-haiku-4-5",
            "text": "ok",
            "usage": {"input_tokens": 999999, "output_tokens": 123456},
            "finish_reason": "stop",
        }
        metrics = mp.collect_metrics(response, elapsed_ms=5.0, retry_count=0)
        self.assertEqual(metrics["input_tokens"], 999999)
        self.assertEqual(metrics["output_tokens"], 123456)
        self.assertEqual(metrics["total_tokens"], 1123455)

    def test_cost_computed_from_pricing_config_per_model(self):
        pricing = mp._load_pricing_config()

        for model_id in ("claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus"):
            with self.subTest(model_id=model_id):
                response = {
                    "model": model_id,
                    "text": "x",
                    "usage": {"input_tokens": 1000, "output_tokens": 1000},
                    "finish_reason": "stop",
                }
                metrics = mp.collect_metrics(response, elapsed_ms=1.0, retry_count=0)
                expected = round(
                    pricing[model_id]["input_price_per_1k_usd"]
                    + pricing[model_id]["output_price_per_1k_usd"],
                    6,
                )
                self.assertEqual(metrics["cost_usd"], expected)

        # Different models with identical token counts must yield different
        # costs (proves per-model pricing lookup is actually used).
        haiku_cost = mp.collect_metrics(
            {"model": "claude-haiku-4-5", "text": "x", "usage": {"input_tokens": 1000, "output_tokens": 1000}, "finish_reason": "stop"},
            elapsed_ms=1.0, retry_count=0,
        )["cost_usd"]
        opus_cost = mp.collect_metrics(
            {"model": "claude-opus", "text": "x", "usage": {"input_tokens": 1000, "output_tokens": 1000}, "finish_reason": "stop"},
            elapsed_ms=1.0, retry_count=0,
        )["cost_usd"]
        self.assertNotEqual(haiku_cost, opus_cost)
        self.assertLess(haiku_cost, opus_cost)

    def test_unknown_model_falls_back_to_default_pricing(self):
        pricing = mp._load_pricing_config()
        response = {
            "model": "some-unlisted-model",
            "text": "x",
            "usage": {"input_tokens": 1000, "output_tokens": 1000},
            "finish_reason": "stop",
        }
        metrics = mp.collect_metrics(response, elapsed_ms=1.0, retry_count=0)
        expected = round(
            pricing["_default"]["input_price_per_1k_usd"]
            + pricing["_default"]["output_price_per_1k_usd"],
            6,
        )
        self.assertEqual(metrics["cost_usd"], expected)


def _valid_audit_payload(**overrides):
    """A complete, well-formed audit JSON payload matching every field
    Section 3 Step 7 requires; tests corrupt/remove specific keys from a
    deep-enough copy of this to exercise each validation rule."""
    payload = {}
    for dim in ae.ALL_DIMENSIONS:
        payload[f"{dim}_score"] = 5
        payload[f"{dim}_reason"] = f"Simulated reason for {dim}."
    payload["recommended_action"] = "ALLOW"
    payload.update(overrides)
    return payload


class AuditPromptStructureTests(TestCase):
    """Section 3 Step 6 — the structured audit prompt sent to a separate
    auditing model instance."""

    def test_build_audit_prompt_contains_the_five_named_fields(self):
        prompt = ae.build_audit_prompt(
            original_prompt="What is our refund policy?",
            ai_response="You can request a refund within 30 days.",
            conversation_history_summary="First turn.",
            pre_request_flags={"pii_detected_in_prompt": False},
        )
        self.assertIn("evaluate the following AI-generated response", prompt["system"])
        self.assertEqual(prompt["user"]["original_prompt"], "What is our refund policy?")
        self.assertEqual(prompt["user"]["ai_response"], "You can request a refund within 30 days.")
        self.assertEqual(prompt["user"]["conversation_history_summary"], "First turn.")
        self.assertEqual(prompt["user"]["pre_request_flags"], {"pii_detected_in_prompt": False})

    def test_pre_request_flags_defaults_to_empty_dict(self):
        prompt = ae.build_audit_prompt("p", "r")
        self.assertEqual(prompt["user"]["pre_request_flags"], {})

    def test_escalated_prompt_names_the_previous_failure_and_differs_from_base(self):
        base = ae.build_audit_prompt("p", "r")
        escalated = ae.build_escalated_audit_prompt(base, ["Missing required field: correctness_score"])
        self.assertIn("Missing required field: correctness_score", escalated["system"])
        self.assertNotEqual(escalated["system"], base["system"])
        # The user payload (original context) must be preserved unchanged.
        self.assertEqual(escalated["user"], base["user"])


class AuditResponseValidationTests(TestCase):
    """Section 3 Step 7 — JSON Construction & Validation."""

    def test_fully_valid_payload_passes(self):
        raw = json.dumps(_valid_audit_payload())
        is_valid, data, errors = ae.parse_and_validate_audit_response(raw)
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])
        self.assertEqual(data["recommended_action"], "ALLOW")

    def test_syntactically_invalid_json_fails(self):
        is_valid, data, errors = ae.parse_and_validate_audit_response("{not valid json")
        self.assertFalse(is_valid)
        self.assertIsNone(data)
        self.assertTrue(any("syntactically valid JSON" in e for e in errors))

    def test_json_array_instead_of_object_fails(self):
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps([1, 2, 3]))
        self.assertFalse(is_valid)
        self.assertTrue(any("JSON object" in e for e in errors))

    def test_missing_score_field_fails(self):
        payload = _valid_audit_payload()
        del payload["correctness_score"]
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("correctness_score" in e for e in errors))

    def test_missing_reason_field_fails(self):
        payload = _valid_audit_payload()
        del payload["bias_risk_reason"]
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("bias_risk_reason" in e for e in errors))

    def test_empty_reason_string_fails(self):
        payload = _valid_audit_payload(safety_risk_reason="   ")
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("safety_risk_reason" in e for e in errors))

    def test_out_of_range_score_low_fails(self):
        payload = _valid_audit_payload(toxicity_risk_score=0)
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("toxicity_risk_score" in e for e in errors))

    def test_out_of_range_score_high_fails(self):
        payload = _valid_audit_payload(toxicity_risk_score=11)
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("toxicity_risk_score" in e for e in errors))

    def test_non_integer_score_fails(self):
        payload = _valid_audit_payload(relevance_score=8.5)
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("relevance_score" in e for e in errors))

    def test_boolean_score_is_rejected_despite_bool_being_an_int_subclass(self):
        # json.dumps(True) -> "true" -> json.loads -> Python bool True;
        # isinstance(True, int) is True in Python, so this must be
        # explicitly excluded to honour "integers in [1,10]".
        payload = _valid_audit_payload(consistency_score=True)
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("consistency_score" in e for e in errors))

    def test_missing_recommended_action_fails(self):
        payload = _valid_audit_payload()
        del payload["recommended_action"]
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("recommended_action" in e for e in errors))

    def test_invalid_recommended_action_value_fails(self):
        payload = _valid_audit_payload(recommended_action="MAYBE")
        is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
        self.assertFalse(is_valid)
        self.assertTrue(any("recommended_action" in e for e in errors))

    def test_all_five_recommended_actions_are_accepted(self):
        for action in ("ALLOW", "VERIFY", "MODIFY", "HUMAN_REVIEW", "BLOCK"):
            with self.subTest(action=action):
                payload = _valid_audit_payload(recommended_action=action)
                is_valid, data, errors = ae.parse_and_validate_audit_response(json.dumps(payload))
                self.assertTrue(is_valid, errors)


class CompositeRiskScoreTests(TestCase):
    """Section 4.1 — Composite Risk Score formula."""

    def test_formula_matches_hand_calculation(self):
        data = _valid_audit_payload(
            safety_risk_score=1, data_leakage_risk_score=4, toxicity_risk_score=1,
            bias_risk_score=2, policy_violation_risk_score=1, prompt_injection_risk_score=1,
            correctness_score=8, hallucination_risk_score=3,
        )
        # max(1,4,1)*0.5 + mean(2,1,1)*0.3 + (10-mean(8,3))*0.2
        #  = 4*0.5 + 1.3333*0.3 + 4.5*0.2 = 2.0 + 0.4 + 0.9 = 3.3
        self.assertAlmostEqual(ae.compute_composite_risk_score(data), 3.3, places=4)

    def test_documented_discrepancy_with_appendix_sample_record(self):
        """The Section 14.1 Appendix's own worked example states
        composite_risk_score=2.8 for these exact inputs, but applying the
        Section 4.1 formula to them yields 3.3. This test locks in that
        the implementation follows the stated formula, not the
        inconsistent appendix figure."""
        data = _valid_audit_payload(
            safety_risk_score=1, data_leakage_risk_score=4, toxicity_risk_score=1,
            bias_risk_score=2, policy_violation_risk_score=1, prompt_injection_risk_score=1,
            correctness_score=8, hallucination_risk_score=3,
        )
        result = ae.compute_composite_risk_score(data)
        self.assertNotAlmostEqual(result, 2.8, places=4)
        self.assertAlmostEqual(result, 3.3, places=4)

    def test_higher_safety_and_leakage_risk_increases_composite_score(self):
        low = _valid_audit_payload(safety_risk_score=1, data_leakage_risk_score=1, toxicity_risk_score=1)
        high = _valid_audit_payload(safety_risk_score=9, data_leakage_risk_score=9, toxicity_risk_score=9)
        self.assertLess(ae.compute_composite_risk_score(low), ae.compute_composite_risk_score(high))


class AuditingEngineOrchestrationTests(TestCase):
    """Section 3 Steps 6-7 end to end: mock auditor responses — valid JSON
    passes validation; missing field/out-of-range score triggers retry;
    two consecutive failures default to HUMAN_REVIEW."""

    def _run(self, **kwargs):
        return ae.run_auditing_engine(
            original_prompt="What is our refund policy?",
            ai_response="You can request a refund within 30 days.",
            **kwargs,
        )

    def test_valid_json_on_first_attempt_passes_without_retry(self):
        valid_raw = json.dumps(_valid_audit_payload(recommended_action="ALLOW"))
        with patch("core.auditing_engine.call_auditor_model", return_value=valid_raw) as mocked:
            result = self._run()
        self.assertTrue(result["validation_passed"])
        self.assertEqual(result["attempt_count"], 1)
        self.assertEqual(result["recommended_action"], "ALLOW")
        self.assertIsNotNone(result["composite_risk_score"])
        self.assertEqual(mocked.call_count, 1)

    def test_missing_field_triggers_one_retry_then_succeeds(self):
        bad_payload = _valid_audit_payload()
        del bad_payload["correctness_score"]
        good_raw = json.dumps(_valid_audit_payload(recommended_action="VERIFY"))

        with patch(
            "core.auditing_engine.call_auditor_model",
            side_effect=[json.dumps(bad_payload), good_raw],
        ) as mocked:
            result = self._run()

        self.assertTrue(result["validation_passed"])
        self.assertEqual(result["attempt_count"], 2)
        self.assertEqual(result["recommended_action"], "VERIFY")
        self.assertEqual(mocked.call_count, 2)

        # The second call must actually be escalated — not a blind identical retry.
        first_prompt = mocked.call_args_list[0].args[0]
        second_prompt = mocked.call_args_list[1].args[0]
        self.assertNotEqual(first_prompt["system"], second_prompt["system"])
        self.assertIn("correctness_score", second_prompt["system"])

    def test_out_of_range_score_triggers_one_retry_then_succeeds(self):
        bad_payload = _valid_audit_payload(safety_risk_score=99)
        good_raw = json.dumps(_valid_audit_payload())

        with patch(
            "core.auditing_engine.call_auditor_model",
            side_effect=[json.dumps(bad_payload), good_raw],
        ) as mocked:
            result = self._run()

        self.assertTrue(result["validation_passed"])
        self.assertEqual(result["attempt_count"], 2)
        self.assertEqual(mocked.call_count, 2)

    def test_two_consecutive_failures_default_to_human_review(self):
        bad_payload_1 = _valid_audit_payload()
        del bad_payload_1["correctness_score"]
        bad_payload_2 = _valid_audit_payload(safety_risk_score=0)

        with patch(
            "core.auditing_engine.call_auditor_model",
            side_effect=[json.dumps(bad_payload_1), json.dumps(bad_payload_2)],
        ) as mocked:
            result = self._run()

        self.assertFalse(result["validation_passed"])
        self.assertEqual(result["attempt_count"], 2)
        self.assertEqual(result["recommended_action"], "HUMAN_REVIEW")
        self.assertIsNone(result["scores"])
        self.assertIsNone(result["composite_risk_score"])
        self.assertTrue(result["errors"])
        # Exactly two attempts total — no unbounded retrying.
        self.assertEqual(mocked.call_count, 2)

    def test_two_consecutive_malformed_json_failures_default_to_human_review(self):
        with patch(
            "core.auditing_engine.call_auditor_model",
            side_effect=["not json at all", "{still not json"],
        ) as mocked:
            result = self._run()

        self.assertFalse(result["validation_passed"])
        self.assertEqual(result["recommended_action"], "HUMAN_REVIEW")
        self.assertEqual(mocked.call_count, 2)


def _safe_scores(**overrides):
    """All 12 dimensions at their safest possible value: quality
    dimensions (higher=better) at 10, risk dimensions (higher=worse,
    including hallucination_risk) at 1. Breaches no threshold in any of
    this step's three policy configs."""
    scores = {}
    for dim in ("correctness", "relevance", "completeness", "instruction_following", "consistency"):
        scores[f"{dim}_score"] = 10
    for dim in (
        "hallucination_risk", "safety_risk", "bias_risk", "toxicity_risk",
        "data_leakage_risk", "policy_violation_risk", "prompt_injection_risk",
    ):
        scores[f"{dim}_score"] = 1
    scores.update(overrides)
    return scores


class PolicyEngineYAMLLoadingTests(TestCase):
    """Section 5.1 / Section 3 Step 8 callout: thresholds are stored in a
    single, system-wide YAML policy file."""

    def test_policy_config_matches_the_documents_literal_example(self):
        config = pe.load_policy_config()
        # block/modify are byte-for-byte the document's own literal example
        # (Section 5.1) MINUS toxicity_risk (later relocated out of block —
        # see below); verify_warning/verify carry that same literal example
        # PLUS an explicit, later product extension wiring in the 6 audit
        # dimensions the document's example never mentions at all
        # (bias_risk/prompt_injection_risk, and the 4 non-hallucination
        # quality dimensions) — see DecisionSupport.yaml's own header note.
        self.assertEqual(
            config["thresholds"]["block"],
            {"data_leakage_risk": 8, "safety_risk": 8},
        )
        # Renamed from the document's own "human_review" (LATER product
        # decision: Human Review is now decided only by the prompt-time
        # company-policy audit, never by anything in this file — this
        # bucket is consulted only for non-gating Verify-warning labels;
        # see this file's own header note). toxicity_risk moved here from
        # `block` at the same threshold, per that same later decision.
        self.assertEqual(
            config["thresholds"]["verify_warning"],
            {
                "safety_risk": 7, "policy_violation_risk": 7, "hallucination_risk": 8,
                "bias_risk": 7, "prompt_injection_risk": 7, "toxicity_risk": 9,
            },
        )
        self.assertEqual(
            config["thresholds"]["modify"],
            {"data_leakage_risk": 5, "pii_detected": True},
        )
        self.assertEqual(
            config["thresholds"]["verify"],
            {
                "hallucination_risk": 6, "correctness": 5,
                "relevance": 5, "completeness": 5, "instruction_following": 5, "consistency": 5,
            },
        )
        self.assertEqual(config["max_retries"], 2)
        self.assertEqual(config["latency_budget_ms"], 8000)
        self.assertTrue(config["require_human_review_for_final_block"])


class PolicyEngineOrderingTests(TestCase):
    """Section 3 Step 8 — Policy Engine. Parametrized tests feeding audit
    score combos against DecisionSupport's (doc-literal) thresholds,
    asserting the correct rule fires in the right priority order: BLOCK
    before HUMAN_REVIEW before MODIFY before VERIFY before ALLOW."""

    def setUp(self):
        self.config = pe.load_policy_config()

    def evaluate(self, scores, context=None):
        return pe.evaluate_policy(self.config, scores, context)

    def test_baseline_safe_scores_allow(self):
        result = self.evaluate(_safe_scores())
        self.assertEqual(result["final_action"], "ALLOW")
        self.assertEqual(result["rules_triggered"], [])
        self.assertEqual(
            result["rules_evaluated"],
            ["BLOCK_CHECK", "MODIFY_CHECK", "VERIFY_CHECK"],
        )

    # (score overrides, context, expected_final_action) — each row is a
    # single-bucket breach in isolation, in priority order. Per product
    # decision, response-side evaluate_policy can never return
    # HUMAN_REVIEW any more (see RULE_ORDER's comment) — a score that used
    # to breach the old human_review bucket now either falls through to
    # ALLOW (if it doesn't independently breach anything else) or whatever
    # bucket, if any, it independently breaches (e.g. hallucination_risk
    # also sits in `verify`).
    SINGLE_BUCKET_CASES = [
        ({"safety_risk_score": 8}, None, "BLOCK"),
        ({"data_leakage_risk_score": 8}, None, "BLOCK"),
        # toxicity_risk moved out of `block` into `verify_warning` (warn-only,
        # not consulted for routing) — no longer block-capable at any score.
        ({"toxicity_risk_score": 9}, None, "ALLOW"),
        ({"safety_risk_score": 7}, None, "ALLOW"),
        ({"policy_violation_risk_score": 7}, None, "ALLOW"),
        # Still breaches `verify` independently (hallucination_risk: 6).
        ({"hallucination_risk_score": 8}, None, "VERIFY"),
        ({"data_leakage_risk_score": 5}, None, "MODIFY"),
        ({}, {"pii_detected": True}, "MODIFY"),
        ({"hallucination_risk_score": 6}, None, "VERIFY"),
        ({"correctness_score": 5}, None, "VERIFY"),
        ({"correctness_score": 4}, None, "VERIFY"),
        ({"correctness_score": 6}, None, "ALLOW"),
        ({"hallucination_risk_score": 5}, None, "ALLOW"),
        ({"data_leakage_risk_score": 4}, None, "ALLOW"),
        ({}, {"pii_detected": False}, "ALLOW"),
    ]

    def test_single_bucket_breaches(self):
        for overrides, context, expected_action in self.SINGLE_BUCKET_CASES:
            with self.subTest(overrides=overrides, context=context):
                result = self.evaluate(_safe_scores(**overrides), context)
                self.assertEqual(result["final_action"], expected_action)

    # (score overrides, context, expected_winner) — each row breaches
    # MULTIPLE buckets at once; the earlier bucket in BLOCK > MODIFY >
    # VERIFY (RULE_ORDER; human_review no longer participates in this
    # priority chain at all — see its comment) must always win.
    PRIORITY_CLASH_CASES = [
        # block + modify + verify all breached at once -> BLOCK wins
        (
            {
                "safety_risk_score": 8, "data_leakage_risk_score": 8,
                "policy_violation_risk_score": 7, "hallucination_risk_score": 8,
                "correctness_score": 4,
            },
            None, "BLOCK",
        ),
        # safety_risk=7 breaches only the now-inert-for-routing
        # verify_warning bucket (no longer a HUMAN_REVIEW win); modify +
        # verify are independently breached, and modify precedes verify.
        (
            {
                "safety_risk_score": 7, "data_leakage_risk_score": 5,
                "hallucination_risk_score": 6,
            },
            None, "MODIFY",
        ),
        # modify + verify breached, block not -> MODIFY wins
        (
            {"data_leakage_risk_score": 5, "hallucination_risk_score": 6},
            None, "MODIFY",
        ),
        # pii_detected (modify) + verify breached -> MODIFY wins
        (
            {"hallucination_risk_score": 6},
            {"pii_detected": True}, "MODIFY",
        ),
    ]

    def test_priority_order_when_multiple_buckets_breached_simultaneously(self):
        for overrides, context, expected_winner in self.PRIORITY_CLASH_CASES:
            with self.subTest(overrides=overrides, context=context):
                result = self.evaluate(_safe_scores(**overrides), context)
                self.assertEqual(result["final_action"], expected_winner)

    def test_rules_evaluated_short_circuits_on_first_match(self):
        result = self.evaluate(_safe_scores(safety_risk_score=8))
        self.assertEqual(result["final_action"], "BLOCK")
        self.assertEqual(result["rules_evaluated"], ["BLOCK_CHECK"])
        self.assertEqual(result["rules_triggered"], ["BLOCK_CHECK:safety_risk"])

    def test_rules_evaluated_checks_all_three_when_none_fire(self):
        result = self.evaluate(_safe_scores())
        self.assertEqual(len(result["rules_evaluated"]), 3)


class PolicyEnginePiiFlagTests(TestCase):
    """Section 5.1's modify bucket: { data_leakage_risk: 5, pii_detected:
    true } — a non-numeric, boolean-flag threshold condition."""

    def setUp(self):
        self.config = pe.load_policy_config()

    def test_pii_detected_true_triggers_modify_even_with_safe_scores(self):
        result = pe.evaluate_policy(self.config, _safe_scores(), context={"pii_detected": True})
        self.assertEqual(result["final_action"], "MODIFY")
        self.assertEqual(result["rules_triggered"], ["MODIFY_CHECK:pii_detected"])

    def test_pii_detected_false_does_not_trigger_modify(self):
        result = pe.evaluate_policy(self.config, _safe_scores(), context={"pii_detected": False})
        self.assertEqual(result["final_action"], "ALLOW")

    def test_missing_context_defaults_to_no_pii(self):
        result = pe.evaluate_policy(self.config, _safe_scores(), context=None)
        self.assertEqual(result["final_action"], "ALLOW")


class CompositeRiskScoreNeverAffectsPolicyDecisionTests(TestCase):
    """Section 4.1: "Policy decisions are always made on individual
    dimension scores — not the composite — to prevent gaming." Composite
    risk score calculation exists for dashboards/monitoring only
    (core.auditing_engine.compute_composite_risk_score), never as a
    policy-engine decision input."""

    def setUp(self):
        self.config = pe.load_policy_config()

    def test_extreme_composite_risk_score_does_not_change_the_decision(self):
        scores_without = _safe_scores()
        scores_with_extreme_composite = _safe_scores(composite_risk_score=9.9)

        result_without = pe.evaluate_policy(self.config, scores_without)
        result_with = pe.evaluate_policy(self.config, scores_with_extreme_composite)

        self.assertEqual(result_without, result_with)
        self.assertEqual(result_with["final_action"], "ALLOW")

    def test_composite_risk_score_computed_separately_is_unaffected_by_policy_engine(self):
        """Demonstrates the two functions are independent: the auditing
        engine's composite score (dashboards) and the policy engine's
        final_action (decisions) are computed from the same dimension
        scores but never influence each other."""
        # _valid_audit_payload's un-overridden dimensions default to a
        # deliberately ambiguous 5 (fine for the JSON-validation tests it
        # exists for), which now sits exactly on DecisionSupport's verify
        # threshold for the 4 non-hallucination quality dimensions —
        # explicitly overridden safe here since this test's whole point is
        # an ALLOW outcome, not a borderline VERIFY one.
        payload = _valid_audit_payload(
            safety_risk_score=1, data_leakage_risk_score=4, toxicity_risk_score=1,
            bias_risk_score=2, policy_violation_risk_score=1, prompt_injection_risk_score=1,
            correctness_score=8, hallucination_risk_score=3,
            relevance_score=8, completeness_score=8, instruction_following_score=8, consistency_score=8,
        )
        composite = ae.compute_composite_risk_score(payload)
        policy_result = pe.evaluate_policy(self.config, payload)

        self.assertAlmostEqual(composite, 3.3, places=4)
        self.assertEqual(policy_result["final_action"], "ALLOW")


class AllowPathTests(TestCase):
    """Section 3 Step 9 ALLOW."""

    def test_response_returned_unchanged_without_token_map(self):
        result = de.execute_allow("The refund window is 30 days.")
        self.assertEqual(result["final_decision"], "ALLOW")
        self.assertEqual(result["user_response"], "The refund window is 30 days.")

    def test_response_de_pseudonymized_when_token_map_present(self):
        pseudonymized = "Contact [PERSON_1] at [EMAIL_1] for details."
        token_map = {"[PERSON_1]": "John Smith", "[EMAIL_1]": "john@example.com"}
        result = de.execute_allow(pseudonymized, token_map=token_map)
        self.assertEqual(result["final_decision"], "ALLOW")
        self.assertEqual(result["user_response"], "Contact John Smith at john@example.com for details.")


class ModifyPathTests(TestCase):
    """Section 3 Step 9 MODIFY."""

    def test_pii_in_llm_reply_is_never_redacted(self):
        """Per explicit product decision: an LLM-generated reply is
        delivered to the user exactly as generated — PII appearing in it
        is audited (see test_modification_log_records_categories_detected
        below) but never masked/altered. This only concerns the
        RESPONSE; PII the user types into their own prompt is still
        pseudonymized before the model ever sees it (Section 3 Step 2,
        2A, core.pre_request_analysis), unaffected by this."""
        text = "Contact John Smith at john.smith@example.com for details."
        result = de.execute_modify(text)

        self.assertEqual(result["final_decision"], "MODIFY")
        self.assertEqual(result["user_response"], text)
        self.assertIn("John Smith", result["user_response"])
        self.assertIn("john.smith@example.com", result["user_response"])

    def test_disclosure_notice_included_by_default(self):
        result = de.execute_modify("Contact John Smith for details.")
        self.assertIsNotNone(result["disclosure_notice"])

    def test_disclosure_notice_can_be_suppressed(self):
        result = de.execute_modify("Contact John Smith for details.", disclosure_notice=None)
        self.assertIsNone(result["disclosure_notice"])

    def test_encrypt_and_decrypt_original_content_round_trips(self):
        """execute_modify no longer calls this (nothing is redacted, so
        there's no separate "original" to protect) — encrypt_original_
        content/decrypt_original_content are tested directly here as the
        still-functional utilities they are, kept for any future
        compliance-logging need."""
        original = "Contact John Smith at john.smith@example.com for details."
        encrypted = de.encrypt_original_content(original)
        self.assertNotEqual(encrypted, original)
        self.assertNotIn("John Smith", encrypted)
        self.assertEqual(de.decrypt_original_content(encrypted), original)

    def test_modification_log_records_categories_detected(self):
        result = de.execute_modify("Contact John Smith at john.smith@example.com for details.")
        log = result["modification_log"]
        self.assertIn("PERSON", log["categories_detected"])
        self.assertIn("EMAIL", log["categories_detected"])

    def test_text_with_no_pii_is_returned_unchanged(self):
        text = "The refund window is 30 days."
        result = de.execute_modify(text)
        self.assertEqual(result["user_response"], text)


class HumanReviewPathTests(TestCase):
    """Section 3 Step 9 HUMAN_REVIEW, prompt-time variant: queued BEFORE
    any generation call (core.auditing_engine.run_prompt_policy_audit +
    core.policy_engine.evaluate_prompt_policy decided this prompt matches
    a company-policy category), so there is never a response to show yet
    — only APPROVE/REJECT (no MODIFY: nothing exists yet for a reviewer
    to hand-edit, unlike the old response-stage flow this replaced)."""

    def setUp(self):
        self.violated_policies = ["medical_and_health"]
        self.result = de.execute_prompt_human_review(
            reason="The prompt requests personalized medical treatment advice.",
            violated_policies=self.violated_policies,
        )

    def test_queued_case_contains_everything_the_reviewer_needs(self):
        case = self.result["queued_case"]
        self.assertEqual(case["status"], "PENDING")
        self.assertEqual(case["violated_policies"], self.violated_policies)
        self.assertEqual(
            case["policy_trigger_reason"], "The prompt requests personalized medical treatment advice.",
        )
        self.assertIsNone(case["reviewer_id"])
        self.assertIsNone(case["decision"])
        self.assertIsNone(case["decided_at"])
        self.assertIsNone(case["final_user_response"])

    def test_user_is_told_to_wait_for_approval(self):
        self.assertIn("approval", self.result["user_response"].lower())

    def test_reviewer_approve_marks_decided_with_no_response_yet(self):
        decided = de.apply_prompt_review_decision(
            self.result["queued_case"], decision="APPROVE", reviewer_id="reviewer-1",
        )
        self.assertEqual(decided["status"], "DECIDED")
        self.assertEqual(decided["decision"], "APPROVE")
        self.assertEqual(decided["reviewer_id"], "reviewer-1")
        self.assertIsNotNone(decided["decided_at"])
        # Nothing has been generated yet — that's core.pipeline.
        # resume_after_prompt_review's job, not this pure function's.
        self.assertIsNone(decided["final_user_response"])

    def test_reviewer_reject_returns_safe_message_and_leaks_nothing(self):
        decided = de.apply_prompt_review_decision(
            self.result["queued_case"], decision="REJECT", reviewer_id="reviewer-1",
        )
        self.assertEqual(decided["decision"], "REJECT")
        self.assertEqual(decided["final_user_response"], de.SAFE_BLOCK_MESSAGE)
        self.assertNotIn("medical_and_health", decided["final_user_response"])

    def test_invalid_decision_value_raises(self):
        # MODIFY specifically: it was a valid response-stage decision
        # before this flow moved to the prompt stage, and must now be
        # rejected just like any other unrecognised value.
        with self.assertRaises(ValueError):
            de.apply_prompt_review_decision(
                self.result["queued_case"], decision="MODIFY", reviewer_id="reviewer-1",
            )

    def test_decided_at_can_be_supplied_explicitly_for_deterministic_tests(self):
        import datetime
        fixed_time = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        decided = de.apply_prompt_review_decision(
            self.result["queued_case"], decision="APPROVE", reviewer_id="reviewer-1",
            decided_at=fixed_time,
        )
        self.assertEqual(decided["decided_at"], fixed_time)


class BlockPathTests(TestCase):
    """Section 3 Step 9 BLOCK. Test: assert user-facing output never
    leaks internal thresholds on BLOCK."""

    def test_user_response_matches_the_documents_exact_generic_message(self):
        result = de.execute_block("data_leakage_risk score 9 exceeded threshold 8")
        self.assertEqual(
            result["user_response"],
            "This response cannot be provided as it may contain sensitive information.",
        )

    def test_admin_log_contains_the_full_internal_reason(self):
        result = de.execute_block("data_leakage_risk score 9 exceeded threshold 8")
        self.assertEqual(result["admin_log"]["internal_reason"], "data_leakage_risk score 9 exceeded threshold 8")

    def test_user_facing_message_never_leaks_internal_details_across_many_reasons(self):
        crafted_internal_reasons = [
            "data_leakage_risk score 9 exceeded threshold 8",
            "safety_risk breach: score=10, threshold=8, use_case=DecisionSupport",
            "BLOCK_CHECK:toxicity_risk fired because toxicity_risk_score=9 >= 9",
            "policy_violation_risk_score=10 triggered CRITICAL BLOCK rule per DecisionSupport-v1.2",
        ]
        leak_indicators = [
            "data_leakage_risk", "safety_risk", "toxicity_risk", "policy_violation_risk",
            "threshold", "score", "9", "8", "10", "DecisionSupport", "BLOCK_CHECK", "CRITICAL",
        ]
        for internal_reason in crafted_internal_reasons:
            with self.subTest(internal_reason=internal_reason):
                result = de.execute_block(internal_reason)
                for indicator in leak_indicators:
                    self.assertNotIn(
                        indicator, result["user_response"],
                        f"BLOCK user_response leaked {indicator!r} from internal reason {internal_reason!r}",
                    )
                # But the admin log must retain the full, unredacted reason.
                self.assertEqual(result["admin_log"]["internal_reason"], internal_reason)

    def test_user_response_is_identical_regardless_of_internal_reason(self):
        """No two different internal reasons should ever produce two
        different user-facing messages — a single fixed message prevents
        any indirect leakage through message variation."""
        result_a = de.execute_block("reason A: safety_risk=10")
        result_b = de.execute_block("reason B: totally different, data_leakage_risk=9")
        self.assertEqual(result_a["user_response"], result_b["user_response"])


class VerifyRetryPathTests(TestCase):
    """Section 3 Step 9 VERIFY/RETRY: re-generate with escalation on 2nd
    failure."""

    def test_first_retry_uses_same_model_with_enhanced_prompt(self):
        calls = []

        def attempt_fn(model_id, enhanced_prompt):
            calls.append((model_id, enhanced_prompt))
            return {"final_action": "ALLOW", "response_text": "ok now"}

        result = de.execute_verify_retry(attempt_fn, initial_model_id="claude-haiku-4-5", max_retries=2)
        self.assertEqual(calls, [("claude-haiku-4-5", True)])
        self.assertEqual(result["final_decision"], "ALLOW")
        self.assertEqual(result["user_response"], "ok now")
        self.assertEqual(len(result["retry_attempts"]), 1)

    def test_second_retry_escalates_to_next_tier_up_without_enhanced_flag(self):
        calls = []

        def attempt_fn(model_id, enhanced_prompt):
            calls.append((model_id, enhanced_prompt))
            if len(calls) < 2:
                return {"final_action": "VERIFY", "response_text": "still bad"}
            return {"final_action": "ALLOW", "response_text": "ok now"}

        result = de.execute_verify_retry(attempt_fn, initial_model_id="claude-haiku-4-5", max_retries=2)
        self.assertEqual(calls, [("claude-haiku-4-5", True), ("claude-sonnet-4-6", False)])
        self.assertEqual(result["final_decision"], "ALLOW")

    def test_tier_escalation_order_low_mid_high_expert(self):
        self.assertEqual(de._next_tier_up_model("claude-haiku-4-5"), "claude-sonnet-4-6")
        self.assertEqual(de._next_tier_up_model("claude-sonnet-4-6"), "claude-opus")
        # claude-opus is registered for both "high" and "expert" tiers; already at the top.
        self.assertEqual(de._next_tier_up_model("claude-opus"), "claude-opus")

    def test_exhausting_both_retries_delivers_the_last_attempt_with_a_warning(self):
        calls = []

        def attempt_fn(model_id, enhanced_prompt):
            calls.append((model_id, enhanced_prompt))
            return {"final_action": "VERIFY", "response_text": "still bad", "audit_json": {"x": 1}}

        result = de.execute_verify_retry(attempt_fn, initial_model_id="claude-haiku-4-5", max_retries=2)
        self.assertEqual(len(calls), 2)  # exactly max_retries attempts, no more
        # Per product decision, response-side auditing can never escalate
        # to HUMAN_REVIEW any more (see core.policy_engine's RULE_ORDER
        # comment) — the last attempt is delivered as-is, flagged with a
        # Verify warning instead of being withheld.
        self.assertEqual(result["final_decision"], "ALLOW")
        self.assertEqual(result["user_response"], "still bad")
        self.assertEqual(len(result["retry_attempts"]), 2)
        self.assertTrue(any(w["dimension"] == "retry_exhausted" for w in result["verify_warnings"]))

    def test_resolved_outcome_of_modify_is_correctly_dispatched(self):
        def attempt_fn(model_id, enhanced_prompt):
            return {"final_action": "MODIFY", "response_text": "Contact John Smith for details."}

        result = de.execute_verify_retry(attempt_fn, initial_model_id="claude-haiku-4-5", max_retries=2)
        self.assertEqual(result["final_decision"], "MODIFY")
        # Reply content is never redacted — see decision_executor.execute_modify.
        self.assertEqual(result["user_response"], "Contact John Smith for details.")

    def test_resolved_outcome_of_block_is_correctly_dispatched_and_still_leaks_nothing(self):
        def attempt_fn(model_id, enhanced_prompt):
            return {
                "final_action": "BLOCK",
                "response_text": "bad content",
                "policy_trigger_reason": "safety_risk=10 exceeded threshold=8",
            }

        result = de.execute_verify_retry(attempt_fn, initial_model_id="claude-haiku-4-5", max_retries=2)
        self.assertEqual(result["final_decision"], "BLOCK")
        self.assertEqual(result["user_response"], de.SAFE_BLOCK_MESSAGE)
        self.assertNotIn("safety_risk", result["user_response"])


class EndToEndDecisionPathIntegrationTests(TestCase):
    """One integration test per path: crafted audit score combos are run
    through the already-built Section 3 Step 8 policy engine to
    deterministically produce each final_action, which is then executed
    by the Section 3 Step 9 decision executor — proving the two modules
    compose correctly end to end."""

    def setUp(self):
        self.policy_config = pe.load_policy_config()

    def test_allow_path(self):
        scores = _safe_scores()
        policy_result = pe.evaluate_policy(self.policy_config, scores)
        self.assertEqual(policy_result["final_action"], "ALLOW")

        result = de.execute_allow("The refund window is 30 days.")
        self.assertEqual(result["final_decision"], "ALLOW")
        self.assertEqual(result["user_response"], "The refund window is 30 days.")

    def test_verify_path_exhausts_to_allow_with_a_warning(self):
        scores = _safe_scores(hallucination_risk_score=6)  # breaches DecisionSupport's verify threshold
        policy_result = pe.evaluate_policy(self.policy_config, scores)
        self.assertEqual(policy_result["final_action"], "VERIFY")

        def always_still_verify(model_id, enhanced_prompt):
            return {
                "final_action": "VERIFY",
                "response_text": "still not good enough",
                "audit_json": scores,
            }

        result = de.execute_verify_retry(always_still_verify, initial_model_id="claude-haiku-4-5", max_retries=2)
        # Per product decision, response-side auditing can never escalate
        # to HUMAN_REVIEW any more (see core.policy_engine's RULE_ORDER
        # comment) — exhausted retries deliver the last attempt instead.
        self.assertEqual(result["final_decision"], "ALLOW")
        self.assertEqual(len(result["retry_attempts"]), 2)

    def test_modify_path(self):
        scores = _safe_scores(data_leakage_risk_score=5)  # breaches DecisionSupport's modify threshold
        policy_result = pe.evaluate_policy(self.policy_config, scores)
        self.assertEqual(policy_result["final_action"], "MODIFY")

        result = de.execute_modify("Contact John Smith at john@example.com for details.")
        self.assertEqual(result["final_decision"], "MODIFY")
        # Reply content is never redacted — see decision_executor.execute_modify.
        self.assertEqual(result["user_response"], "Contact John Smith at john@example.com for details.")

    def test_human_review_path(self):
        # Human Review is now decided at the PROMPT stage (core.
        # auditing_engine.run_prompt_policy_audit + core.policy_engine.
        # evaluate_prompt_policy) — never by this class's response-side
        # policy_config, which can no longer produce HUMAN_REVIEW at all.
        # This proves the prompt-time pairing composes correctly instead.
        company_policy = pe.load_company_policy()
        violated_policies = ["medical_and_health"]
        decision = pe.evaluate_prompt_policy(company_policy, violated_policies)
        self.assertEqual(decision, "HUMAN_REVIEW")

        result = de.execute_prompt_human_review(
            reason="The prompt requests personalized medical treatment advice.",
            violated_policies=violated_policies,
        )
        self.assertEqual(result["final_decision"], "HUMAN_REVIEW")
        self.assertEqual(result["queued_case"]["status"], "PENDING")
        self.assertEqual(result["queued_case"]["violated_policies"], violated_policies)

    def test_block_path(self):
        scores = _safe_scores(data_leakage_risk_score=8)  # breaches DecisionSupport's block threshold
        policy_result = pe.evaluate_policy(self.policy_config, scores)
        self.assertEqual(policy_result["final_action"], "BLOCK")

        result = de.execute_block(internal_reason=policy_result["reason"])
        self.assertEqual(result["final_decision"], "BLOCK")
        self.assertEqual(result["user_response"], de.SAFE_BLOCK_MESSAGE)
        self.assertIn("data_leakage_risk", result["admin_log"]["internal_reason"])
        self.assertNotIn("data_leakage_risk", result["user_response"])
        self.assertNotIn("8", result["user_response"])


def _fresh_session_state():
    return {
        "turn_number": 0,
        "session_risk_accumulator": 0.0,
        "recent_risk_scores": [],
        "verify_count": 0,
        "modify_count": 0,
        "human_review_count": 0,
        "was_blocked": False,
        "previous_decisions": [],
    }


class SessionRiskAccumulatorTests(TestCase):
    """Section 6.1 — Compounding Risk Tracking."""

    def test_rolling_average_within_window(self):
        state = _fresh_session_state()
        for risk in (2, 4, 6):
            state = sr.update_session_risk_accumulator(state, risk, "ALLOW")
        self.assertAlmostEqual(state["session_risk_accumulator"], (2 + 4 + 6) / 3)
        self.assertEqual(state["recent_risk_scores"], [2, 4, 6])

    def test_window_drops_oldest_scores_beyond_n(self):
        state = _fresh_session_state()
        for risk in (1, 2, 3, 4, 5, 6):  # 6 turns, window=5
            state = sr.update_session_risk_accumulator(state, risk, "ALLOW", window_size=5)
        # oldest score (1) must have been dropped
        self.assertEqual(state["recent_risk_scores"], [2, 3, 4, 5, 6])
        self.assertAlmostEqual(state["session_risk_accumulator"], (2 + 3 + 4 + 5 + 6) / 5)

    def test_default_window_size_is_5(self):
        self.assertEqual(sr.DEFAULT_SESSION_RISK_WINDOW, 5)

    def test_turn_number_increments_each_call(self):
        state = _fresh_session_state()
        state = sr.update_session_risk_accumulator(state, 3, "ALLOW")
        state = sr.update_session_risk_accumulator(state, 3, "ALLOW")
        self.assertEqual(state["turn_number"], 2)

    def test_decision_counts_tracked_independently(self):
        state = _fresh_session_state()
        state = sr.update_session_risk_accumulator(state, 3, "VERIFY")
        state = sr.update_session_risk_accumulator(state, 3, "VERIFY")
        state = sr.update_session_risk_accumulator(state, 3, "MODIFY")
        state = sr.update_session_risk_accumulator(state, 3, "HUMAN_REVIEW")
        state = sr.update_session_risk_accumulator(state, 3, "ALLOW")
        self.assertEqual(state["verify_count"], 2)
        self.assertEqual(state["modify_count"], 1)
        self.assertEqual(state["human_review_count"], 1)

    def test_block_sets_was_blocked_flag_permanently(self):
        state = _fresh_session_state()
        state = sr.update_session_risk_accumulator(state, 9, "BLOCK")
        self.assertTrue(state["was_blocked"])
        # A later ALLOW turn must not clear the flag.
        state = sr.update_session_risk_accumulator(state, 1, "ALLOW")
        self.assertTrue(state["was_blocked"])

    def test_previous_decisions_appended_in_order(self):
        state = _fresh_session_state()
        state = sr.update_session_risk_accumulator(state, 1, "ALLOW")
        state = sr.update_session_risk_accumulator(state, 2, "VERIFY")
        self.assertEqual(state["previous_decisions"], ["ALLOW", "VERIFY"])

    def test_update_does_not_mutate_input_state(self):
        state = _fresh_session_state()
        sr.update_session_risk_accumulator(state, 5, "ALLOW")
        self.assertEqual(state["turn_number"], 0)
        self.assertEqual(state["recent_risk_scores"], [])


class PolicyEscalationTests(TestCase):
    """Section 6.1 — escalating policy strictness once the accumulator
    crosses threshold."""

    def setUp(self):
        self.config = pe.load_policy_config()

    def test_is_escalated_false_below_threshold(self):
        state = {"session_risk_accumulator": 4.9}
        self.assertFalse(sr.is_escalated(state, session_risk_threshold=5.0))

    def test_is_escalated_true_when_crossing_threshold(self):
        state = {"session_risk_accumulator": 5.0}
        self.assertTrue(sr.is_escalated(state, session_risk_threshold=5.0))

    def test_is_escalated_true_above_threshold(self):
        state = {"session_risk_accumulator": 7.2}
        self.assertTrue(sr.is_escalated(state, session_risk_threshold=5.0))

    def test_escalation_lowers_higher_is_worse_thresholds(self):
        escalated = sr.escalate_policy_config(self.config, escalation_step=1)
        self.assertEqual(escalated["thresholds"]["block"]["safety_risk"], 7)  # was 8
        self.assertEqual(escalated["thresholds"]["verify_warning"]["hallucination_risk"], 7)  # was 8

    def test_escalation_raises_higher_is_better_thresholds(self):
        escalated = sr.escalate_policy_config(self.config, escalation_step=1)
        self.assertEqual(escalated["thresholds"]["verify"]["correctness"], 6)  # was 5

    def test_escalation_leaves_boolean_flags_unchanged(self):
        escalated = sr.escalate_policy_config(self.config, escalation_step=1)
        self.assertIs(escalated["thresholds"]["modify"]["pii_detected"], True)

    def test_escalation_clamps_to_valid_score_range(self):
        config = {"thresholds": {"block": {"safety_risk": 1, "correctness": 10}}}
        escalated = sr.escalate_policy_config(config, escalation_step=5)
        self.assertEqual(escalated["thresholds"]["block"]["safety_risk"], 1)  # floor at 1
        self.assertEqual(escalated["thresholds"]["block"]["correctness"], 10)  # ceiling at 10

    def test_escalation_does_not_mutate_original_config(self):
        original_value = self.config["thresholds"]["block"]["safety_risk"]
        sr.escalate_policy_config(self.config, escalation_step=1)
        self.assertEqual(self.config["thresholds"]["block"]["safety_risk"], original_value)

    def test_get_effective_policy_config_returns_original_when_not_escalated(self):
        state = {"session_risk_accumulator": 1.0}
        effective = sr.get_effective_policy_config(self.config, state, session_risk_threshold=5.0)
        self.assertEqual(effective, self.config)

    def test_get_effective_policy_config_returns_escalated_when_crossed(self):
        state = {"session_risk_accumulator": 5.0}
        effective = sr.get_effective_policy_config(self.config, state, session_risk_threshold=5.0)
        self.assertEqual(effective["thresholds"]["block"]["safety_risk"], 7)


class BorderlineSessionEscalationIntegrationTests(TestCase):
    """Test: simulate a session of borderline turns, assert accumulator
    crosses threshold and subsequent turns get stricter thresholds
    applied. Wires Section 6.1 (this step) together with the already-
    built Section 3 Step 8 policy engine (core.policy_engine)."""

    def test_borderline_turns_escalate_and_change_the_outcome_of_a_later_turn(self):
        config = pe.load_policy_config()
        session_risk_threshold = config["session_risk_threshold"]  # 5.0
        state = _fresh_session_state()

        # A sequence of individually-borderline turns: correctness=6 never
        # breaches DecisionSupport's own verify threshold (<= 5) on any
        # single turn, so each turn on its own would ALLOW. Section 6.1's
        # own callout: "A series of individually borderline responses can
        # collectively establish a harmful pattern." (Uses a `verify`-
        # bucket dimension rather than the old human_review one: per
        # product decision, evaluate_policy can never produce HUMAN_REVIEW
        # any more, so escalation can only ever be demonstrated moving a
        # turn between the buckets that still participate in routing —
        # here, ALLOW -> VERIFY.)
        borderline_scores = _safe_scores(correctness_score=6)
        for _ in range(5):
            policy_result = pe.evaluate_policy(config, borderline_scores)
            self.assertEqual(policy_result["final_action"], "ALLOW")  # each turn alone is fine
            state = sr.update_session_risk_accumulator(
                state, turn_risk_score=6, turn_decision=policy_result["final_action"],
                window_size=config["session_risk_window"],
            )

        # After 5 turns of risk_score=6, the rolling average is exactly 6.0.
        self.assertAlmostEqual(state["session_risk_accumulator"], 6.0)
        self.assertTrue(sr.is_escalated(state, session_risk_threshold))

        # Apply escalation for the next ("subsequent") turn.
        effective_config = sr.get_effective_policy_config(config, state, session_risk_threshold)
        self.assertNotEqual(effective_config, config)

        # The SAME correctness=6 turn that always ALLOWed under the
        # original config now breaches the escalated verify threshold
        # (5 + 1 = 6, higher-is-better raised, not lowered), proving
        # stricter thresholds are applied.
        next_turn_result_original = pe.evaluate_policy(config, borderline_scores)
        next_turn_result_escalated = pe.evaluate_policy(effective_config, borderline_scores)
        self.assertEqual(next_turn_result_original["final_action"], "ALLOW")
        self.assertEqual(next_turn_result_escalated["final_action"], "VERIFY")


class AgenticPreActionGateTests(TestCase):
    """Section 6.2 — Agentic Pipeline Protection. Test: simulate an agent
    action with high safety_risk, assert it's held for confirmation."""

    def test_high_safety_risk_action_is_held_for_confirmation(self):
        payload = _valid_audit_payload(safety_risk_score=9)
        with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(payload)):
            result = ag.gate_agent_action("Transfer $50,000 to an external account.")
        self.assertTrue(result["held_for_confirmation"])
        self.assertIn("safety_risk", result["reason"])

    def test_high_policy_violation_risk_action_is_held_for_confirmation(self):
        payload = _valid_audit_payload(policy_violation_risk_score=8)
        with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(payload)):
            result = ag.gate_agent_action("Delete all customer records.")
        self.assertTrue(result["held_for_confirmation"])
        self.assertIn("policy_violation_risk", result["reason"])

    def test_low_risk_action_proceeds_without_hold(self):
        payload = _valid_audit_payload(safety_risk_score=1, policy_violation_risk_score=1)
        with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(payload)):
            result = ag.gate_agent_action("Look up the customer's order status.")
        self.assertFalse(result["held_for_confirmation"])

    def test_safety_risk_boundary_at_exactly_7_is_held(self):
        payload = _valid_audit_payload(safety_risk_score=7)
        with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(payload)):
            result = ag.gate_agent_action("Some action.")
        self.assertTrue(result["held_for_confirmation"])

    def test_safety_risk_just_below_boundary_is_not_held_on_its_own(self):
        payload = _valid_audit_payload(safety_risk_score=6, policy_violation_risk_score=1)
        with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(payload)):
            result = ag.gate_agent_action("Some action.")
        self.assertFalse(result["held_for_confirmation"])

    def test_auditor_failure_defaults_to_held_not_auto_approved(self):
        with patch("core.auditing_engine.call_auditor_model", return_value="not valid json"):
            result = ag.gate_agent_action("Some action.")
        self.assertTrue(result["held_for_confirmation"])

    def test_action_log_entry_contains_audit_score(self):
        payload = _valid_audit_payload(safety_risk_score=9)
        with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(payload)):
            result = ag.gate_agent_action("Transfer funds.")
        self.assertIsNotNone(result["action_log_entry"]["audit_score"])
        self.assertEqual(result["action_log_entry"]["held_for_confirmation"], True)
        self.assertFalse(result["action_log_entry"]["rollback_recommended"])

    def test_rollback_tagging_sets_flag_and_reason(self):
        payload = _valid_audit_payload(safety_risk_score=1, policy_violation_risk_score=1)
        with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(payload)):
            result = ag.gate_agent_action("Send a routine notification.")
        entry = result["action_log_entry"]
        self.assertFalse(entry["rollback_recommended"])

        rolled_back = ag.tag_for_rollback(
            entry, reason="Triggered by a hallucinated claim discovered after the fact."
        )
        self.assertTrue(rolled_back["rollback_recommended"])
        self.assertEqual(
            rolled_back["rollback_reason"],
            "Triggered by a hallucinated claim discovered after the fact.",
        )
        # tag_for_rollback must not mutate the original entry.
        self.assertFalse(entry["rollback_recommended"])


def _seed_dashboard_records():
    """5 AuditRecords with hand-computable aggregates, used across the
    dashboard aggregation and view tests below.

    (final_action, latency_ms, cost_usd, model, retry_count,
     hallucination_risk, safety_risk, bias_risk, data_leakage_risk,
     rules_triggered)
    """
    specs = [
        ("ALLOW", 100, 0.01, "claude-haiku-4-5", 0, 2, 1, 1, 1, []),
        ("ALLOW", 200, 0.02, "claude-sonnet-4-6", 1, 3, 2, 2, 2, []),
        ("VERIFY", 150, 0.015, "claude-haiku-4-5", 1, 7, 3, 1, 1, ["VERIFY_CHECK:hallucination_risk"]),
        # HUMAN_REVIEW is now decided at the prompt stage (see core.
        # pipeline's module docstring), so its rules_triggered/policy_
        # trigger_reason wording matches that stage now, not a response-
        # side dimension breach.
        ("HUMAN_REVIEW", 300, 0.03, "claude-opus", 0, 4, 8, 2, 3, ["PROMPT_POLICY_CHECK:medical_and_health"]),
        ("BLOCK", 50, 0.005, "claude-haiku-4-5", 0, 2, 9, 1, 9, ["BLOCK_CHECK:data_leakage_risk"]),
    ]
    records = []
    for final_action, latency, cost, model, retries, halluc, safety, bias, leakage, triggered in specs:
        trace = Trace.objects.create(user_id="u1", raw_prompt="hi")
        human_review = None
        human_review_status = None
        if final_action == "HUMAN_REVIEW":
            human_review_status = "PENDING"
            human_review = {
                "status": "PENDING",
                "violated_policies": ["medical_and_health"],
                "policy_trigger_reason": "The prompt requests personalized medical treatment advice.",
                "reviewer_id": None,
                "decision": None,
                "decided_at": None,
                "final_user_response": None,
            }
        record = AuditRecord.objects.create(
            trace=trace,
            response_metrics={
                "latency_ms": latency, "cost_usd": cost, "model_used": model,
                "retry_count": retries, "input_tokens": 10, "output_tokens": 5,
                "total_tokens": 15, "finish_reason": "stop",
            },
            audit_quality={
                "hallucination_risk_score": halluc, "correctness_score": 8,
                "relevance_score": 8, "completeness_score": 8,
                "instruction_following_score": 8, "consistency_score": 8,
            },
            audit_responsibility={
                "safety_risk_score": safety, "bias_risk_score": bias,
                "data_leakage_risk_score": leakage, "toxicity_risk_score": 1,
                "policy_violation_risk_score": 1, "prompt_injection_risk_score": 1,
            },
            final_action=final_action,
            policy_rules_triggered=triggered,
            human_review_status=human_review_status,
            human_review=human_review,
        )
        records.append(record)
    return records


class DashboardAggregationTests(TestCase):
    """Section 10.1/10.2 — pure aggregation logic, tested directly against
    hand-computed expectations from _seed_dashboard_records' fixture."""

    def setUp(self):
        self.records = _seed_dashboard_records()

    def test_total_requests(self):
        since = timezone_now_minus_hours(24)
        self.assertEqual(dashboard.total_requests(since=since), 5)

    def test_decision_distribution(self):
        result = dashboard.decision_distribution()
        self.assertEqual(result["total"], 5)
        self.assertEqual(result["counts"], {"ALLOW": 2, "VERIFY": 1, "MODIFY": 0, "HUMAN_REVIEW": 1, "BLOCK": 1})
        self.assertEqual(result["percentages"]["ALLOW"], 40.0)
        self.assertEqual(result["percentages"]["VERIFY"], 20.0)
        self.assertEqual(result["percentages"]["HUMAN_REVIEW"], 20.0)
        self.assertEqual(result["percentages"]["BLOCK"], 20.0)

    def test_latency_percentiles(self):
        # sorted latencies: [50, 100, 150, 200, 300]
        result = dashboard.latency_percentiles()
        self.assertEqual(result["p50"], 150)
        self.assertAlmostEqual(result["p90"], 260.0, places=2)
        self.assertAlmostEqual(result["p99"], 296.0, places=2)

    def test_total_cost_today(self):
        self.assertAlmostEqual(dashboard.total_cost_today(), 0.08, places=6)

    def test_cost_per_model(self):
        result = dashboard.cost_per_model()
        self.assertAlmostEqual(result["claude-haiku-4-5"], 0.03, places=6)
        self.assertAlmostEqual(result["claude-sonnet-4-6"], 0.02, places=6)
        self.assertAlmostEqual(result["claude-opus"], 0.03, places=6)

    def test_active_human_review_queue_count(self):
        self.assertEqual(dashboard.active_human_review_queue_count(), 1)

    def test_hallucination_rate(self):
        # mean(2, 3, 7, 4, 2) = 3.6
        self.assertAlmostEqual(dashboard.hallucination_rate(days=7), 3.6, places=4)

    def test_safety_violation_rate(self):
        # safety_risk scores [1,2,3,8,9]; >=7: 2/5 = 40%
        self.assertAlmostEqual(dashboard.safety_violation_rate(days=7), 40.0, places=2)

    def test_data_leakage_attempts(self):
        # data_leakage_risk scores [1,2,1,3,9]; >=7: only the last -> 1
        self.assertEqual(dashboard.data_leakage_attempts(days=7), 1)

    def test_data_leakage_attempts_also_counts_prompt_pii_that_was_modified(self):
        # Putting PII into the PROMPT (Section 3 Step 2 2A) and getting
        # MODIFYed as a result counts as a leakage attempt too, even
        # though the auditor's own data_leakage_risk_score for the
        # (merely echoed-back) response is low.
        trace = Trace.objects.create(
            user_id="u1", raw_prompt="my number is 555-123-4567",
        )
        AuditRecord.objects.create(
            trace=trace,
            pre_request={"pii_detected_in_prompt": True, "pii_categories": ["PHONE_NUMBER"]},
            audit_responsibility={"data_leakage_risk_score": 1, "safety_risk_score": 1},
            final_action="MODIFY",
        )
        # +1 over the fixture's existing count of 1 (the BLOCK record with leakage_risk=9).
        self.assertEqual(dashboard.data_leakage_attempts(days=7), 2)

    def test_data_leakage_attempts_ignores_prompt_pii_that_was_not_modified(self):
        # PII detected in the prompt but the request wasn't actually
        # MODIFYed (e.g. some other rule fired first) shouldn't count.
        trace = Trace.objects.create(
            user_id="u1", raw_prompt="my number is 555-123-4567",
        )
        AuditRecord.objects.create(
            trace=trace,
            pre_request={"pii_detected_in_prompt": True},
            audit_responsibility={"data_leakage_risk_score": 1, "safety_risk_score": 1},
            final_action="ALLOW",
        )
        self.assertEqual(dashboard.data_leakage_attempts(days=7), 1)  # unchanged from the fixture baseline

    def test_bias_detection_rate(self):
        # bias_risk scores [1,2,1,2,1]; none >= 7 -> 0%
        self.assertAlmostEqual(dashboard.bias_detection_rate(days=7), 0.0, places=2)

    def test_blocked_request_rate(self):
        result = dashboard.blocked_request_rate(days=7)
        self.assertAlmostEqual(result["rate"], 20.0, places=2)
        self.assertEqual(result["blocked_count"], 1)
        self.assertEqual(result["total"], 5)
        self.assertEqual(result["by_reason"], {"BLOCK_CHECK:data_leakage_risk": 1})

    def test_retry_verify_rate(self):
        # retry_count >= 1 for 2 of 5 records -> 40%
        self.assertAlmostEqual(dashboard.retry_verify_rate(days=7), 40.0, places=2)

    def test_human_review_rate(self):
        self.assertAlmostEqual(dashboard.human_review_rate(days=7), 20.0, places=2)


def timezone_now_minus_hours(hours):
    from django.utils import timezone
    return timezone.now() - timezone.timedelta(hours=hours)


class DashboardViewTests(TestCase):
    """Test: seed the DB with sample AuditRecord/Trace rows, load each
    dashboard page, assert the rendered aggregation numbers match a
    hand-computed expectation."""

    def setUp(self):
        self.records = _seed_dashboard_records()
        # _seed_dashboard_records stamps every Trace with user_id="u1" —
        # logging in as a manager whose own username is "u1" makes their
        # team (core.authz.team_user_ids: themselves + reports) exactly
        # match the fixture, so the hand-computed assertions below are
        # unaffected by the new team-scoping.
        self.manager = _make_manager("u1")
        self.client.force_login(self.manager)

    def test_dashboard_home_renders_correct_numbers(self):
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_requests_24h"], 5)
        self.assertEqual(response.context["decision_distribution"]["counts"]["ALLOW"], 2)
        self.assertEqual(response.context["active_human_review_queue_count"], 1)
        self.assertAlmostEqual(response.context["total_cost_today"], 0.08, places=6)

        body = response.content.decode()
        self.assertIn(">5<", body.replace(" ", ""))  # total requests rendered
        self.assertIn("HUMAN_REVIEW", body)

    def test_dashboard_trends_renders_correct_numbers(self):
        response = self.client.get("/dashboard/trends/")
        self.assertEqual(response.status_code, 200)
        self.assertAlmostEqual(response.context["hallucination_rate"], 3.6, places=4)
        self.assertAlmostEqual(response.context["safety_violation_rate"], 40.0, places=2)
        self.assertEqual(response.context["data_leakage_attempts"], 1)
        self.assertAlmostEqual(response.context["human_review_rate"], 20.0, places=2)

    def test_human_review_queue_lists_pending_case(self):
        response = self.client.get("/dashboard/human-review/")
        self.assertEqual(response.status_code, 200)
        pending = response.context["pending_cases"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].final_action, "HUMAN_REVIEW")
        self.assertIn(str(pending[0].trace_id), response.content.decode())

    def test_fpr_tuning_page_loads(self):
        response = self.client.get("/dashboard/fpr-tuning/")
        self.assertEqual(response.status_code, 200)

    def test_anonymous_visitor_is_redirected_to_login(self):
        self.client.logout()
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response.url)

    def test_employee_gets_403_on_every_manager_only_page(self):
        employee = _make_employee("employee-1", self.manager)
        self.client.force_login(employee)
        for path in ("/dashboard/", "/dashboard/trends/", "/dashboard/human-review/", "/dashboard/fpr-tuning/"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 403, path)

    def test_manager_only_sees_their_own_teams_numbers(self):
        # A second manager's own, unrelated data must not leak into this
        # team's Overview/Trends numbers (core.authz.team_user_ids).
        other_manager = _make_manager("other-manager")
        for _ in range(3):
            trace = Trace.objects.create(user_id="other-manager", raw_prompt="hi")
            AuditRecord.objects.create(trace=trace, final_action="ALLOW")

        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["decision_distribution"]["total"], 5)  # unchanged by the other team

        self.client.force_login(other_manager)
        response = self.client.get("/dashboard/")
        self.assertEqual(response.context["decision_distribution"]["total"], 3)
        self.assertEqual(response.context["decision_distribution"]["counts"]["ALLOW"], 3)


class HumanReviewDecisionViewTests(TestCase):
    """Test: submit a reviewer decision through the UI/API and assert
    it's persisted as a gold-standard label tied to the original audit
    record. APPROVE now actually triggers generation for the first time
    (core.pipeline.resume_after_prompt_review) — under settings.TESTING
    this resolves deterministically via model_pipeline's own simulated
    response, so no mocking is needed to exercise that path. There is no
    MODIFY option any more — nothing exists yet, pre-approval, for a
    reviewer to hand-edit."""

    def setUp(self):
        self.records = _seed_dashboard_records()
        self.pending_record = next(r for r in self.records if r.final_action == "HUMAN_REVIEW")
        self.manager = _make_manager("u1")
        self.client.force_login(self.manager)

    def test_approve_decision_persists_as_gold_standard_label(self):
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "decision": "APPROVE",
            "decision_reason": "Looks correct on review.",
        })
        self.assertEqual(response.status_code, 200)

        self.pending_record.refresh_from_db()
        self.assertEqual(self.pending_record.human_review_status, "DECIDED")
        self.assertEqual(self.pending_record.human_review["decision"], "APPROVE")
        # APPROVE actually generates a response now — there was never one
        # before approval; settings.TESTING resolves this deterministically.
        self.assertEqual(
            self.pending_record.human_review["final_user_response"],
            "[simulated response from claude-haiku-4-5]",
        )
        self.assertEqual(
            self.pending_record.user_response["content"],
            "[simulated response from claude-haiku-4-5]",
        )
        # final_action stays HUMAN_REVIEW permanently — the honest record
        # of which gate this request actually went through — even though
        # a response now exists (see resume_after_prompt_review's own
        # docstring on why this is deliberate).
        self.assertEqual(self.pending_record.final_action, "HUMAN_REVIEW")

        actions = ReviewerAction.objects.filter(audit_record=self.pending_record)
        self.assertEqual(actions.count(), 1)
        action = actions.first()
        # reviewer_id is always the logged-in manager's own username now —
        # never a client-supplied field (see core.dashboard_views.human_review_queue).
        self.assertEqual(action.reviewer_id, "u1")
        self.assertEqual(action.decision, "APPROVE")
        self.assertEqual(action.decision_reason, "Looks correct on review.")

    def test_reject_decision_recorded_and_leaks_nothing(self):
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "decision": "REJECT",
        })
        self.assertEqual(response.status_code, 200)
        self.pending_record.refresh_from_db()
        self.assertEqual(self.pending_record.human_review["final_user_response"], de.SAFE_BLOCK_MESSAGE)
        self.assertEqual(self.pending_record.user_response["content"], de.SAFE_BLOCK_MESSAGE)
        self.assertNotIn("medical_and_health", self.pending_record.human_review["final_user_response"])

    def test_invalid_decision_value_does_not_persist_and_returns_error(self):
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "decision": "MAYBE",
        })
        self.assertEqual(response.status_code, 400)
        self.pending_record.refresh_from_db()
        self.assertEqual(self.pending_record.human_review_status, "PENDING")
        self.assertEqual(ReviewerAction.objects.filter(audit_record=self.pending_record).count(), 0)

    def test_after_decision_case_no_longer_appears_in_pending_queue(self):
        self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "decision": "APPROVE",
        })
        response = self.client.get("/dashboard/human-review/")
        self.assertEqual(len(response.context["pending_cases"]), 0)

    def test_cannot_re_decide_an_already_decided_case(self):
        self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "decision": "APPROVE",
        })
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "decision": "REJECT",
        })
        self.assertEqual(response.status_code, 400)
        self.pending_record.refresh_from_db()
        # The original APPROVE decision must survive untouched.
        self.assertEqual(self.pending_record.human_review["decision"], "APPROVE")
        self.assertEqual(ReviewerAction.objects.filter(audit_record=self.pending_record).count(), 1)

    def test_approve_when_generation_fails_marks_the_case_and_notifies_the_manager(self):
        with patch("core.pipeline.resume_after_prompt_review", side_effect=Exception("simulated API failure")):
            response = self.client.post("/dashboard/human-review/", {
                "trace_id": str(self.pending_record.trace_id),
                "decision": "APPROVE",
                "decision_reason": "Looks correct on review.",
            })
        self.assertEqual(response.status_code, 502)
        self.assertIn(de.SAFE_GENERATION_UNAVAILABLE_MESSAGE, response.context["generation_failed_notice"])

        self.pending_record.refresh_from_db()
        # The reviewer's own decision still stands — only generation failed.
        self.assertEqual(self.pending_record.human_review_status, "DECIDED")
        self.assertEqual(self.pending_record.human_review["decision"], "APPROVE")
        self.assertTrue(self.pending_record.human_review["generation_failed"])
        self.assertIsNone(self.pending_record.human_review["final_user_response"])
        self.pending_record.trace.refresh_from_db()
        self.assertEqual(self.pending_record.trace.status, Trace.STATUS_CLOSED)

        # A case that already failed can't be silently re-approved into a
        # second, contradictory ReviewerAction either — same guard as any
        # other already-DECIDED case.
        retry_response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "decision": "APPROVE",
        })
        self.assertEqual(retry_response.status_code, 400)

    def test_manager_cannot_decide_a_case_outside_their_team(self):
        other_manager = _make_manager("other-manager")
        self.client.force_login(other_manager)
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "decision": "APPROVE",
        })
        self.assertEqual(response.status_code, 403)
        self.pending_record.refresh_from_db()
        self.assertEqual(self.pending_record.human_review_status, "PENDING")

    def test_employee_cannot_reach_human_review_queue(self):
        employee = _make_employee("employee-1", self.manager)
        self.client.force_login(employee)
        response = self.client.get("/dashboard/human-review/")
        self.assertEqual(response.status_code, 403)


class FprTuningViewTests(TestCase):
    """Section 9.3 — Operator Dashboard Alert Tuning View."""

    def setUp(self):
        self.manager = _make_manager("u1")
        self.client.force_login(self.manager)

    def _make_record(self, hallucination_risk_score, rules_triggered):
        trace = Trace.objects.create(user_id="u1", raw_prompt="hi")
        return AuditRecord.objects.create(
            trace=trace,
            audit_quality={"hallucination_risk_score": hallucination_risk_score, "correctness_score": 8},
            audit_responsibility={"safety_risk_score": 1},
            final_action="VERIFY",
            policy_rules_triggered=rules_triggered,
        )

    def test_check_fpr_computes_correct_rate(self):
        flagged_1 = self._make_record(7, ["VERIFY_CHECK:hallucination_risk"])
        flagged_2 = self._make_record(8, ["VERIFY_CHECK:hallucination_risk"])
        flagged_3 = self._make_record(9, ["HUMAN_REVIEW_CHECK:hallucination_risk"])
        self._make_record(1, [])  # not flagged, should not count

        FalsePositiveReport.objects.create(
            audit_record=flagged_1, dimension="hallucination_risk", reported_by="op-1",
        )

        response = self.client.post("/dashboard/fpr-tuning/", {
            "action": "check_fpr",
            "dimension": "hallucination_risk",
            "days": "7",
        })
        self.assertEqual(response.status_code, 200)
        result = response.context["result"]
        self.assertEqual(result["flagged_count"], 3)
        self.assertEqual(result["false_positive_count"], 1)
        self.assertAlmostEqual(result["fpr"], 1 / 3, places=4)

    def test_simulate_threshold_change(self):
        # DecisionSupport's verify.hallucination_risk threshold is 6.
        record_6 = self._make_record(6, ["VERIFY_CHECK:hallucination_risk"])
        record_7 = self._make_record(7, ["VERIFY_CHECK:hallucination_risk"])
        self._make_record(8, ["VERIFY_CHECK:hallucination_risk"])

        # record_6 is reported as a false positive; record_7 is not, so it
        # is presumed a confirmed issue that raising the threshold would miss.
        FalsePositiveReport.objects.create(
            audit_record=record_6, dimension="hallucination_risk", reported_by="op-1",
        )

        response = self.client.post("/dashboard/fpr-tuning/", {
            "action": "simulate_threshold_change",
            "bucket": "verify",
            "dimension": "hallucination_risk",
            "new_threshold": "8",
            "days": "7",
        })
        self.assertEqual(response.status_code, 200)
        sim = response.context["simulation"]
        self.assertEqual(sim["current_threshold"], 6)
        self.assertEqual(sim["proposed_threshold"], 8.0)
        self.assertEqual(sim["flags_before"], 3)
        self.assertEqual(sim["flags_after"], 1)
        self.assertAlmostEqual(sim["reduction_pct"], (3 - 1) / 3 * 100, places=2)
        self.assertEqual(sim["missed_confirmed_issues"], 1)  # record_7 only

    def test_propose_threshold_creates_pending_proposal(self):
        response = self.client.post("/dashboard/fpr-tuning/", {
            "action": "propose_threshold",
            "bucket": "verify",
            "dimension": "hallucination_risk",
            "current_threshold": "6",
            "proposed_threshold": "8",
            "rationale": "High FPR observed over the last week.",
        })
        self.assertEqual(response.status_code, 200)
        proposal = ThresholdChangeProposal.objects.get()
        self.assertEqual(proposal.status, "PENDING")
        self.assertEqual(proposal.proposed_threshold, 8.0)

    def test_report_false_positive_creates_report(self):
        record = self._make_record(7, ["VERIFY_CHECK:hallucination_risk"])
        response = self.client.post("/dashboard/fpr-tuning/", {
            "action": "report_false_positive",
            "trace_id": str(record.trace_id),
            "dimension": "hallucination_risk",
            "reason": "Manually verified as correct.",
        })
        self.assertEqual(response.status_code, 200)
        report = FalsePositiveReport.objects.get()
        self.assertEqual(report.audit_record_id, record.trace_id)
        self.assertEqual(report.dimension, "hallucination_risk")
        # reported_by is always the logged-in manager's own username now —
        # never a client-supplied field (see core.dashboard_views.fpr_tuning).
        self.assertEqual(report.reported_by, "u1")

    def test_manager_cannot_report_false_positive_outside_their_team(self):
        record = self._make_record(7, ["VERIFY_CHECK:hallucination_risk"])
        other_manager = _make_manager("other-manager")
        self.client.force_login(other_manager)
        response = self.client.post("/dashboard/fpr-tuning/", {
            "action": "report_false_positive",
            "trace_id": str(record.trace_id),
            "dimension": "hallucination_risk",
            "reason": "Not my team's case.",
        })
        self.assertEqual(response.status_code, 403)
        self.assertEqual(FalsePositiveReport.objects.count(), 0)

    def test_employee_cannot_reach_fpr_tuning(self):
        employee = _make_employee("employee-1", self.manager)
        self.client.force_login(employee)
        response = self.client.get("/dashboard/fpr-tuning/")
        self.assertEqual(response.status_code, 403)


class ThumbsDownViewTests(TestCase):
    """Section 7.1 User Thumbs-Down."""

    def setUp(self):
        self.trace = Trace.objects.create(user_id="u1", raw_prompt="hi")

    def test_thumbs_down_creates_feedback_row(self):
        response = self.client.post(
            f"/api/feedback/{self.trace.request_id}/thumbs-down/",
            data=json.dumps({"comment": "This answer was unhelpful."}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        feedback = UserFeedback.objects.get(trace=self.trace)
        self.assertEqual(feedback.comment, "This answer was unhelpful.")
        self.assertFalse(feedback.reviewed)

    def test_thumbs_down_without_body_still_works(self):
        response = self.client.post(f"/api/feedback/{self.trace.request_id}/thumbs-down/")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(UserFeedback.objects.filter(trace=self.trace).count(), 1)

    def test_thumbs_down_for_unknown_trace_returns_404(self):
        response = self.client.post(f"/api/feedback/{uuid.uuid4()}/thumbs-down/")
        self.assertEqual(response.status_code, 404)

    def test_thumbs_down_works_without_a_csrf_token_like_a_real_external_caller(self):
        """Regression test: this endpoint is documented (Section 7.1,
        and its own docstring) as an external-API endpoint like
        core.views.create_request, meant to be called by a client with no
        Django session/CSRF cookie. The default Django test Client does
        not enforce CSRF, which is exactly how a prior version of this
        view silently shipped without @csrf_exempt and 403'd on every
        real curl request — this test uses enforce_csrf_checks=True so
        that regression cannot return unnoticed."""
        from django.test import Client
        strict_client = Client(enforce_csrf_checks=True)
        response = strict_client.post(
            f"/api/feedback/{self.trace.request_id}/thumbs-down/",
            data=json.dumps({"comment": "No CSRF cookie presented."}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)


class RegistrationAndLoginTests(TestCase):
    """Registration/login (core/auth_views.py) and the role+manager
    mapping it creates (core/models.py UserProfile)."""

    def setUp(self):
        self.manager = _make_manager("manager-1")

    def test_manager_can_register(self):
        response = self.client.post("/accounts/register/", {
            "name": "Alice Manager",
            "email": "alice-manager@example.com",
            "role": "manager",
            "password": "a-strong-password-1",
            "confirm_password": "a-strong-password-1",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/dashboard/")
        user = User.objects.get(email="alice-manager@example.com")
        self.assertEqual(user.profile.role, UserProfile.ROLE_MANAGER)
        self.assertIsNone(user.profile.manager)

    def test_employee_registration_maps_to_manager_by_email(self):
        response = self.client.post("/accounts/register/", {
            "name": "Bob Employee",
            "email": "bob-employee@example.com",
            "role": "employee",
            "manager_email": "manager-1@example.com",
            "password": "a-strong-password-1",
            "confirm_password": "a-strong-password-1",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/dashboard/playground/")
        user = User.objects.get(email="bob-employee@example.com")
        self.assertEqual(user.profile.role, UserProfile.ROLE_EMPLOYEE)
        self.assertEqual(user.profile.manager, self.manager.profile)

    def test_employee_registration_requires_a_real_manager_email(self):
        response = self.client.post("/accounts/register/", {
            "name": "Bob Employee",
            "email": "bob-employee@example.com",
            "role": "employee",
            "manager_email": "no-such-manager@example.com",
            "password": "a-strong-password-1",
            "confirm_password": "a-strong-password-1",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("No manager account was found with that email.", response.context["errors"])
        self.assertFalse(User.objects.filter(email="bob-employee@example.com").exists())

    def test_employee_registration_rejects_an_employee_email_as_manager(self):
        _make_employee("existing-employee", self.manager)
        response = self.client.post("/accounts/register/", {
            "name": "Bob Employee",
            "email": "bob-employee@example.com",
            "role": "employee",
            "manager_email": "existing-employee@example.com",
            "password": "a-strong-password-1",
            "confirm_password": "a-strong-password-1",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("No manager account was found with that email.", response.context["errors"])

    def test_registration_rejects_mismatched_passwords(self):
        response = self.client.post("/accounts/register/", {
            "name": "Bob Employee",
            "email": "bob-employee@example.com",
            "role": "manager",
            "password": "a-strong-password-1",
            "confirm_password": "a-different-password-2",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("Password and confirmation do not match.", response.context["errors"])
        self.assertFalse(User.objects.filter(email="bob-employee@example.com").exists())

    def test_registration_rejects_a_duplicate_email(self):
        response = self.client.post("/accounts/register/", {
            "name": "Someone Else",
            "email": "manager-1@example.com",
            "role": "manager",
            "password": "a-strong-password-1",
            "confirm_password": "a-strong-password-1",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("An account with this email already exists.", response.context["errors"])

    def test_registration_rejects_an_overlong_email_instead_of_crashing(self):
        """Regression test: username=email is stored in auth_user.username
        (VARCHAR(150)); an email past that length used to reach
        User.objects.create_user() unvalidated and raise an unhandled
        MySQL DataError — a 500 that, under DEBUG=True, would dump this
        view's local variables (including the plaintext password) onto
        Django's technical error page. See core.auth_views.MAX_EMAIL_LENGTH."""
        overlong_email = ("a" * 245) + "@x.com"
        response = self.client.post("/accounts/register/", {
            "name": "Attacker",
            "email": overlong_email,
            "role": "manager",
            "password": "a-strong-password-1",
            "confirm_password": "a-strong-password-1",
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("fewer" in e for e in response.context["errors"]))
        self.assertFalse(User.objects.filter(email=overlong_email).exists())

    def test_registration_rejects_a_password_matching_the_registrants_own_email(self):
        """Regression test: validate_password() was previously called
        without user=, silently disabling AUTH_PASSWORD_VALIDATORS'
        UserAttributeSimilarityValidator."""
        response = self.client.post("/accounts/register/", {
            "name": "Jane Doe",
            "email": "jane.doe@example.com",
            "role": "manager",
            "password": "jane.doe@example.com",
            "confirm_password": "jane.doe@example.com",
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("similar" in e.lower() for e in response.context["errors"]))
        self.assertFalse(User.objects.filter(email="jane.doe@example.com").exists())

    def test_login_with_correct_credentials_succeeds(self):
        User.objects.create_user(username="carol@example.com", email="carol@example.com", password="a-strong-password-1")
        UserProfile.objects.create(user=User.objects.get(email="carol@example.com"), role=UserProfile.ROLE_MANAGER)
        response = self.client.post("/accounts/login/", {
            "email": "carol@example.com", "password": "a-strong-password-1",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/dashboard/")

    def test_login_with_wrong_password_fails(self):
        response = self.client.post("/accounts/login/", {
            "email": "manager-1@example.com", "password": "wrong-password",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["error"], "Invalid email or password.")

    def test_logout_requires_post(self):
        self.client.force_login(self.manager)
        response = self.client.get("/accounts/logout/")
        self.assertEqual(response.status_code, 405)
        response = self.client.post("/accounts/logout/")
        self.assertEqual(response.status_code, 302)


class PlaygroundOwnershipTests(TestCase):
    """Playground identity is always request.user.username (see
    core.dashboard_views.playground) — this closes the pre-auth IDOR
    where guessing/reusing another visitor's session_id (or user_id
    string) surfaced their chat history."""

    def setUp(self):
        self.manager = _make_manager("owner")
        self.other = _make_manager("other")
        self.session_id = uuid.uuid4()
        self.trace = Trace.objects.create(
            session_id=self.session_id, user_id="owner", raw_prompt="secret question",
        )

    def test_another_account_cannot_resume_someone_elses_session_by_guessing_the_uuid(self):
        self.client.force_login(self.other)
        response = self.client.get(f"/dashboard/playground/?session={self.session_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["turns"]), 0)
        self.assertNotIn("secret question", response.content.decode())

    def test_owner_sees_their_own_chat_in_sidebar_history(self):
        self.client.force_login(self.manager)
        response = self.client.get("/dashboard/playground/")
        titles = [c["title"] for c in response.context["chat_history"]]
        self.assertIn("secret question", titles)

    def test_other_account_does_not_see_owners_chat_in_sidebar_history(self):
        self.client.force_login(self.other)
        response = self.client.get("/dashboard/playground/")
        self.assertEqual(response.context["chat_history"], [])

    def test_another_account_cannot_post_into_someone_elses_session(self):
        """Regression test: a client-supplied session_id used to be
        trusted outright on POST, letting one account's turns write into
        (and, via the SessionState it shares with core.pipeline, mutate)
        another account's session-risk state — see core.dashboard_views.
        playground's ownership check."""
        self.client.force_login(self.other)
        response = self.client.post("/dashboard/playground/", {
            "session_id": str(self.session_id),
            "raw_prompt": "trying to attach to someone else's session",
        })
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Trace.objects.filter(session_id=self.session_id).count(), 1)  # unchanged

    def test_chat_history_title_is_never_taken_from_a_different_owners_trace(self):
        """Defense in depth for _chat_history: even if a session_id ends
        up with Trace rows from two different accounts (which the
        ownership check above now prevents via the Playground view
        itself, but this helper must not trust that on its own), the
        sidebar title must only ever be built from the current account's
        own Trace rows."""
        shared_session = uuid.uuid4()
        Trace.objects.create(
            session_id=shared_session, user_id="owner",
            raw_prompt="OWNER SECRET PROMPT",
        )
        Trace.objects.create(
            session_id=shared_session, user_id="other",
            raw_prompt="other's own prompt",
        )
        self.client.force_login(self.other)
        response = self.client.get("/dashboard/playground/")
        titles = [c["title"] for c in response.context["chat_history"]]
        self.assertIn("other's own prompt", titles)
        self.assertNotIn("OWNER SECRET PROMPT", titles)


class PlaygroundDuplicateSubmissionTests(TestCase):
    """Regression test: an employee unsure whether their message sent
    (no visible feedback while a prompt-time HUMAN_REVIEW case sits OPEN,
    possibly for a long time) used to be able to retype/resend the exact
    same text, silently creating a second (or third) pending case for the
    same request. See core.dashboard_views.playground's
    is_duplicate_pending guard."""

    def setUp(self):
        manager = _make_manager("mgr-dup")
        self.employee = _make_employee("emp-dup", manager)
        self.client.force_login(self.employee)
        self.session_id = uuid.uuid4()
        self.prompt = "What medication should I take for my chest pain?"

    def _post(self, raw_prompt=None):
        payload = json.dumps({"violated_policies": ["medical_and_health"], "reason": "test"})
        with patch("core.auditing_engine.call_prompt_auditor_model", return_value=payload):
            return self.client.post("/dashboard/playground/", {
                "session_id": str(self.session_id),
                "raw_prompt": raw_prompt if raw_prompt is not None else self.prompt,
            })

    def test_resending_the_identical_prompt_while_the_first_is_still_pending_is_refused(self):
        self._post()
        self.assertEqual(Trace.objects.filter(session_id=self.session_id).count(), 1)

        # Silently refused, per product decision — no visible message, just
        # no second trace created.
        response = self._post()
        self.assertEqual(Trace.objects.filter(session_id=self.session_id).count(), 1)  # no second trace
        self.assertIsNone(response.context["error"])

    def test_a_different_prompt_in_the_same_session_is_not_blocked(self):
        self._post()
        self._post(raw_prompt="A completely different question.")
        self.assertEqual(Trace.objects.filter(session_id=self.session_id).count(), 2)

    def test_resending_after_the_first_is_resolved_is_allowed(self):
        self._post()
        trace = Trace.objects.get(session_id=self.session_id)
        trace.status = Trace.STATUS_CLOSED
        trace.save(update_fields=["status"])

        self._post()
        self.assertEqual(Trace.objects.filter(session_id=self.session_id).count(), 2)


class PlaygroundGenerationFailureTests(TestCase):
    """Regression test: a live model failure (rate limit/timeout) during
    a direct, synchronous Playground submit used to leave the Trace OPEN
    with no AuditRecord at all, and dump the raw exception string as the
    error — surfacing once, on that render only, then rendering as a
    permanent blank, pill-less turn on every later reload. See
    core.dashboard_views.playground's POST handler."""

    def setUp(self):
        self.employee = _make_employee("emp-fail", _make_manager("mgr-fail"))
        self.client.force_login(self.employee)

    def _post(self):
        with patch("core.pipeline.process_request", side_effect=Exception("simulated API failure")):
            return self.client.post("/dashboard/playground/", {
                "session_id": str(uuid.uuid4()),
                "raw_prompt": "Hello there.",
            })

    def test_failure_shows_a_clean_message_not_the_raw_exception(self):
        response = self._post()
        self.assertEqual(response.context["error"], de.SAFE_GENERATION_UNAVAILABLE_MESSAGE)
        self.assertNotIn("simulated API failure", response.context["error"])

    def test_failed_trace_is_closed_with_a_minimal_audit_record(self):
        self._post()
        trace = Trace.objects.get(user_id="emp-fail")
        self.assertEqual(trace.status, Trace.STATUS_CLOSED)
        record = AuditRecord.objects.get(trace=trace)
        self.assertIsNone(record.final_action)
        self.assertEqual(record.user_response["content"], de.SAFE_GENERATION_UNAVAILABLE_MESSAGE)

    def test_failed_turn_renders_with_a_failed_pill_on_reload(self):
        self._post()
        trace = Trace.objects.get(user_id="emp-fail")
        response = self.client.get("/dashboard/playground/", {"session": str(trace.session_id)})
        [turn] = response.context["turns"]
        self.assertTrue(turn.generation_failed)
        self.assertEqual(turn.chat_response, de.SAFE_GENERATION_UNAVAILABLE_MESSAGE)
        self.assertEqual(turn.status_pill_label, "Failed")
        self.assertEqual(turn.status_pill_css, "failed")


class PlaygroundPendingStatusEndpointTests(TestCase):
    """core.dashboard_views.playground_pending_status — polled by
    playground.html so an approval/rejection reaches the employee's chat
    without a manual page refresh."""

    def setUp(self):
        self.owner = _make_manager("poll-owner")
        self.other = _make_manager("poll-other")
        self.trace = Trace.objects.create(user_id="poll-owner", raw_prompt="x")
        self.record = AuditRecord.objects.create(
            trace=self.trace, final_action="HUMAN_REVIEW", human_review_status="PENDING",
            human_review={
                "status": "PENDING", "violated_policies": [], "policy_trigger_reason": "x",
                "reviewer_id": None, "decision": None, "decided_at": None, "final_user_response": None,
            },
        )

    def test_still_pending_case_is_echoed_back(self):
        self.client.force_login(self.owner)
        response = self.client.get(f"/dashboard/playground/pending-status/?ids={self.trace.request_id}")
        self.assertEqual(response.json()["still_pending"], [str(self.trace.request_id)])

    def test_decided_case_drops_out(self):
        self.record.human_review_status = "DECIDED"
        self.record.save(update_fields=["human_review_status"])
        self.client.force_login(self.owner)
        response = self.client.get(f"/dashboard/playground/pending-status/?ids={self.trace.request_id}")
        self.assertEqual(response.json()["still_pending"], [])

    def test_another_accounts_pending_case_is_never_echoed(self):
        self.client.force_login(self.other)
        response = self.client.get(f"/dashboard/playground/pending-status/?ids={self.trace.request_id}")
        self.assertEqual(response.json()["still_pending"], [])

    def test_malformed_id_is_ignored_not_a_500(self):
        self.client.force_login(self.owner)
        response = self.client.get("/dashboard/playground/pending-status/?ids=not-a-uuid,,")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["still_pending"], [])

    def test_approved_but_not_yet_generated_still_counts_as_pending(self):
        """Regression test: core.dashboard_views.human_review_queue's POST
        handler flips human_review_status to DECIDED immediately on
        APPROVE, before core.pipeline.resume_after_prompt_review's live
        generation call finishes filling in final_user_response — a poll
        landing in that window must not tell the caller to reload, or the
        employee's page would show the "did not complete" fallback for a
        request that is actually still in flight, not failed."""
        self.record.human_review_status = "DECIDED"
        self.record.human_review.update({"decision": "APPROVE", "final_user_response": None})
        self.record.save(update_fields=["human_review_status", "human_review"])
        self.client.force_login(self.owner)
        response = self.client.get(f"/dashboard/playground/pending-status/?ids={self.trace.request_id}")
        self.assertEqual(response.json()["still_pending"], [str(self.trace.request_id)])

    def test_approved_and_generated_no_longer_pending(self):
        self.record.human_review_status = "DECIDED"
        self.record.human_review.update({"decision": "APPROVE", "final_user_response": "the reply"})
        self.record.save(update_fields=["human_review_status", "human_review"])
        self.client.force_login(self.owner)
        response = self.client.get(f"/dashboard/playground/pending-status/?ids={self.trace.request_id}")
        self.assertEqual(response.json()["still_pending"], [])

    def test_rejected_is_immediately_resolved_no_generation_window(self):
        # apply_prompt_review_decision fills in final_user_response
        # synchronously for REJECT, so there is no in-flight window like
        # APPROVE's to guard against here.
        self.record.human_review_status = "DECIDED"
        self.record.human_review.update({"decision": "REJECT", "final_user_response": de.SAFE_BLOCK_MESSAGE})
        self.record.save(update_fields=["human_review_status", "human_review"])
        self.client.force_login(self.owner)
        response = self.client.get(f"/dashboard/playground/pending-status/?ids={self.trace.request_id}")
        self.assertEqual(response.json()["still_pending"], [])

    def test_generation_failed_case_no_longer_counts_as_pending(self):
        # Regression test: without this, a resume_after_prompt_review
        # failure (rate limit/timeout) leaves the record in exactly the
        # same shape as the legitimate in-flight window above (DECIDED,
        # final_user_response=None) — the poll must stop waiting for this
        # one, not treat it identically to "still generating".
        self.record.human_review_status = "DECIDED"
        self.record.human_review.update({
            "decision": "APPROVE", "final_user_response": None, "generation_failed": True,
        })
        self.record.save(update_fields=["human_review_status", "human_review"])
        self.client.force_login(self.owner)
        response = self.client.get(f"/dashboard/playground/pending-status/?ids={self.trace.request_id}")
        self.assertEqual(response.json()["still_pending"], [])


class PlaygroundHumanReviewSidebarTests(TestCase):
    """The Playground's Requests sidebar tab (core.dashboard_views.
    _my_human_review_requests) and the chat thread's post-decision
    override (core.dashboard_views.playground's turns loop) — a
    HUMAN_REVIEW turn's "your request is being reviewed" placeholder and
    HUMAN_REVIEW status pill must flip to the reviewer's actual decision
    once one exists, and never before."""

    def setUp(self):
        self.owner = _make_manager("owner")
        self.other = _make_manager("other")
        self.session_id = uuid.uuid4()
        self.trace = Trace.objects.create(
            session_id=self.session_id, user_id="owner",
            raw_prompt="please review this", final_decision="HUMAN_REVIEW",
        )

    def _make_pending_record(self):
        # Prompt-time shape (core.decision_executor.execute_prompt_human_
        # review): no raw_response/redacted_response — nothing has been
        # generated yet at the pending stage.
        return AuditRecord.objects.create(
            trace=self.trace, final_action="HUMAN_REVIEW", human_review_status="PENDING",
            human_review={
                "status": "PENDING", "violated_policies": ["medical_and_health"],
                "policy_trigger_reason": "low confidence", "reviewer_id": None, "decision": None,
                "decided_at": None, "final_user_response": None,
            },
            user_response={
                "content": "Your request requires approval before it can be processed. You'll see the response here once it's reviewed.",
                "disclosure_notice": None,
            },
        )

    def test_pending_case_shows_pending_in_requests_sidebar_and_placeholder_in_thread(self):
        self._make_pending_record()
        self.client.force_login(self.owner)
        response = self.client.get("/dashboard/playground/", {"session": str(self.session_id)})

        [my_request] = response.context["my_requests"]
        self.assertEqual(my_request["status"], "PENDING")

        [turn] = response.context["turns"]
        self.assertIsNone(turn.review_status_label)
        self.assertIn("requires approval", turn.chat_response)

    def test_approved_case_replaces_placeholder_and_pill_in_thread_and_sidebar(self):
        record = self._make_pending_record()
        record.human_review_status = "DECIDED"
        record.human_review.update({
            "status": "DECIDED", "decision": "APPROVE", "reviewer_id": "owner-manager", "final_user_response": "the original reply",
        })
        record.save(update_fields=["human_review_status", "human_review"])

        self.client.force_login(self.owner)
        response = self.client.get("/dashboard/playground/", {"session": str(self.session_id)})

        [my_request] = response.context["my_requests"]
        self.assertEqual(my_request["status"], "APPROVED")

        [turn] = response.context["turns"]
        self.assertEqual(turn.review_status_label, "APPROVED")
        self.assertEqual(turn.chat_response, "the original reply")

    def test_rejected_case_shows_rejected_and_the_safe_message(self):
        record = self._make_pending_record()
        record.human_review_status = "DECIDED"
        record.human_review.update({
            "status": "DECIDED", "decision": "REJECT", "reviewer_id": "owner-manager",
            "final_user_response": de.SAFE_BLOCK_MESSAGE,
        })
        record.save(update_fields=["human_review_status", "human_review"])

        self.client.force_login(self.owner)
        response = self.client.get("/dashboard/playground/", {"session": str(self.session_id)})

        [my_request] = response.context["my_requests"]
        self.assertEqual(my_request["status"], "REJECTED")

        [turn] = response.context["turns"]
        self.assertEqual(turn.review_status_label, "REJECTED")
        self.assertEqual(turn.chat_response, de.SAFE_BLOCK_MESSAGE)

    def test_other_account_never_sees_owners_requests_in_their_own_sidebar(self):
        self._make_pending_record()
        self.client.force_login(self.other)
        response = self.client.get("/dashboard/playground/")
        self.assertEqual(response.context["my_requests"], [])

    def test_generation_failed_case_shows_failed_pill_and_message_in_thread_and_sidebar(self):
        # Regression test: a manager's APPROVE triggers core.pipeline.
        # resume_after_prompt_review's live generation call, which can
        # fail (rate limit/timeout) after human_review_status is already
        # "DECIDED" — core.dashboard_views.human_review_queue's POST
        # handler marks human_review["generation_failed"] in that case
        # (see PlaygroundPendingStatusEndpointTests /
        # HumanReviewDecisionViewTests for the other two surfaces of this
        # same fix). The employee must see a clear, fixed message here,
        # never a blank bubble or the stale "requires approval" placeholder.
        record = self._make_pending_record()
        record.human_review_status = "DECIDED"
        record.human_review.update({
            "status": "DECIDED", "decision": "APPROVE", "reviewer_id": "owner-manager",
            "final_user_response": None, "generation_failed": True,
        })
        record.save(update_fields=["human_review_status", "human_review"])

        self.client.force_login(self.owner)
        response = self.client.get("/dashboard/playground/", {"session": str(self.session_id)})

        [my_request] = response.context["my_requests"]
        self.assertEqual(my_request["status"], "FAILED")

        [turn] = response.context["turns"]
        self.assertTrue(turn.generation_failed)
        self.assertIsNone(turn.review_status_label)
        self.assertEqual(turn.chat_response, de.SAFE_GENERATION_UNAVAILABLE_MESSAGE)
        self.assertEqual(turn.status_pill_label, "Failed")
        self.assertEqual(turn.status_pill_css, "failed")


class RegulationLibraryTests(TestCase):
    """Section 8 — Regulatory & Geography-Aware Compliance Module."""

    def test_gdpr_and_dpdp_versions_match_the_appendix_example(self):
        # Section 14.1's own example: "regulation_versions": {"GDPR":
        # "2024-Q4", "DPDP": "2024-Q2"}.
        self.assertEqual(rl.load_regulation("GDPR")["version"], "2024-Q4")
        self.assertEqual(rl.load_regulation("DPDP")["version"], "2024-Q2")

    def test_all_five_named_regulations_load(self):
        for reg_id in ("GDPR", "DPDP", "CCPA", "EU_AI_Act", "HIPAA"):
            with self.subTest(regulation=reg_id):
                reg = rl.load_regulation(reg_id)
                self.assertEqual(reg["regulation_id"], reg_id)

    def test_gdpr_breach_notification_hours_is_72(self):
        # Section 5.2: "72h breach notification hook."
        self.assertEqual(rl.load_regulation("GDPR")["breach_notification_hours"], 72)

    def test_apply_regulations_aggregates_versions(self):
        result = rl.apply_regulations(["GDPR", "DPDP"])
        self.assertEqual(result["regulation_versions"], {"GDPR": "2024-Q4", "DPDP": "2024-Q2"})

    def test_apply_regulations_requires_pseudonymisation_if_any_regulation_does(self):
        # GDPR requires it, DPDP does not.
        result = rl.apply_regulations(["DPDP"])
        self.assertFalse(result["requires_pii_pseudonymisation"])
        result = rl.apply_regulations(["GDPR", "DPDP"])
        self.assertTrue(result["requires_pii_pseudonymisation"])

    def test_apply_regulations_data_residency_required_if_any_regulation_does(self):
        result = rl.apply_regulations(["GDPR"])
        self.assertFalse(result["data_residency_required"])
        result = rl.apply_regulations(["GDPR", "DPDP"])
        self.assertTrue(result["data_residency_required"])  # DPDP requires it

    def test_apply_regulations_breach_notification_takes_the_strictest_window(self):
        result = rl.apply_regulations(["GDPR"])
        self.assertEqual(result["breach_notification_hours"], 72)

    def test_apply_regulations_with_no_regulations_is_a_safe_no_op(self):
        result = rl.apply_regulations([])
        self.assertEqual(result["regulation_versions"], {})
        self.assertFalse(result["requires_pii_pseudonymisation"])
        self.assertIsNone(result["breach_notification_hours"])

    def test_build_compliance_metadata_for_non_high_risk_use_case(self):
        metadata = rl.build_compliance_metadata(["GDPR"], eu_ai_act_high_risk=False, base_audit_retention_days=90)
        self.assertEqual(metadata["effective_audit_retention_days"], 90)
        self.assertIsNone(metadata["conformity_log"])
        self.assertFalse(metadata["eu_ai_act_high_risk"])

    def test_build_compliance_metadata_extends_retention_for_high_risk_use_case(self):
        metadata = rl.build_compliance_metadata(["GDPR", "EU_AI_Act"], eu_ai_act_high_risk=True, base_audit_retention_days=90)
        # Section 10.3: "up to 7 years for regulated industries" = 2555 days.
        self.assertEqual(metadata["effective_audit_retention_days"], 2555)
        self.assertIsNotNone(metadata["conformity_log"])
        self.assertTrue(metadata["conformity_log"]["human_oversight_mandatory_for_human_review"])

    def test_build_compliance_metadata_does_not_extend_retention_if_already_longer(self):
        metadata = rl.build_compliance_metadata(["EU_AI_Act"], eu_ai_act_high_risk=True, base_audit_retention_days=3000)
        self.assertEqual(metadata["effective_audit_retention_days"], 3000)

    def test_high_risk_flag_extends_retention_even_when_eu_ai_act_not_in_regulations_list(self):
        """The eu_ai_act_high_risk flag governs its own consequence
        directly from the EU_AI_Act regulation file — it must not
        require "EU_AI_Act" to be separately listed in `regulations`."""
        metadata = rl.build_compliance_metadata(["GDPR", "DPDP"], eu_ai_act_high_risk=True, base_audit_retention_days=90)
        self.assertEqual(metadata["effective_audit_retention_days"], 2555)


def _trigger_values_for(config):
    """Computes, from a use-case's own loaded policy config, a
    hallucination_risk score that breaches the verify bucket (and only
    that bucket — nothing above it in RULE_ORDER references
    hallucination_risk for any use case) — used by the end-to-end
    scenario tests below so they adapt to whatever the actual YAML
    thresholds are, rather than relying on hand-copied magic numbers per
    use case."""
    return {"verify_hallucination_risk": config["thresholds"]["verify"]["hallucination_risk"]}


def _all_clear_audit_payload(**overrides):
    """Unlike _valid_audit_payload's uniform baseline of 5 (deliberately
    ambiguous for auditing_engine's own field-presence/range tests), this
    is a genuinely safe baseline for every dimension — quality dimensions
    at 9 (higher = better), risk dimensions at 1 (higher = worse) — so it
    never accidentally breaches any use case's policy thresholds. A
    uniform 5 does breach some real configs here, e.g. InternalKnowledge
    and DecisionSupport's modify.data_leakage_risk threshold of 5."""
    payload = {}
    for dim in pe.HIGHER_IS_BETTER:
        payload[f"{dim}_score"] = 9
        payload[f"{dim}_reason"] = f"Simulated: no issues with {dim}."
    for dim in pe.HIGHER_IS_WORSE:
        payload[f"{dim}_score"] = 1
        payload[f"{dim}_reason"] = f"Simulated: no issues with {dim}."
    payload["recommended_action"] = "ALLOW"
    payload.update(overrides)
    return payload


class EndToEndPipelineScenarioTests(TestCase):
    """Step 10 'Prove it works': sample scenarios covering all 5 decision
    paths, run through the real, now-wired /api/requests/ endpoint. Test:
    assert both the expected final decision and a complete,
    correctly-populated audit record."""

    def _post(self, raw_prompt):
        return self.client.post(
            "/api/requests/",
            data=json.dumps({
                "raw_prompt": raw_prompt,
                "user_id": "scenario-user",
                "session_id": str(uuid.uuid4()),
            }),
            content_type="application/json",
        )

    def _assert_complete_audit_record(self, request_id, expected_final_action):
        record = AuditRecord.objects.get(trace_id=request_id)
        self.assertEqual(record.final_action, expected_final_action)
        self.assertIn("complexity_score", record.pre_request)
        self.assertIn("risk_score", record.pre_request)
        self.assertTrue(record.policy_rules_evaluated)
        self.assertTrue(record.policy_profile_version)
        return record

    def test_allow_scenario(self):
        response = self._post("What are your business hours?")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ALLOW")
        record = self._assert_complete_audit_record(body["request_id"], "ALLOW")
        self.assertTrue(record.response_metrics)
        self.assertTrue(record.audit_quality)
        self.assertTrue(record.audit_responsibility)

    def test_block_via_router_pre_check(self):
        # Section 3 Step 2, 2C's own Critical-band example content, which
        # pre_request_analysis.risk_score scores at 9, triggering Section
        # 3 Step 3's router pre-check BLOCK before any model call.
        prompt = "This is a regulated decision affecting a safety-critical hospital system."
        response = self._post(prompt)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "BLOCK")
        self.assertEqual(body["message"], de.SAFE_BLOCK_MESSAGE)
        record = self._assert_complete_audit_record(body["request_id"], "BLOCK")
        self.assertEqual(record.policy_rules_triggered, ["ROUTER_PRE_CHECK:risk_score"])
        self.assertEqual(record.response_metrics, {})  # no model call was made

    def test_modify_via_pii_detection(self):
        # MODIFY no longer redacts the model's response — per explicit
        # product decision, an LLM-generated reply is audited only, never
        # altered (see decision_executor.execute_modify) — so this just
        # asserts the correct path fired and the audit log records which
        # PII categories (if any) were detected in the reply.
        prompt = "Please update my contact email to john.smith@example.com."
        response = self._post(prompt)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "MODIFY")
        record = self._assert_complete_audit_record(body["request_id"], "MODIFY")
        self.assertIn("categories_detected", record.modification)

    def test_human_review_via_prompt_policy_audit(self):
        # Human Review is now decided at the PROMPT stage, before any
        # generation call — mocking the prompt auditor's own model call,
        # not the response auditor's, is what actually exercises this
        # path now (core.auditing_engine.run_prompt_policy_audit, wired
        # in core.pipeline).
        auditor_payload = json.dumps({
            "violated_policies": ["medical_and_health"],
            "reason": "The prompt requests personalized medical treatment advice.",
        })
        with patch("core.auditing_engine.call_prompt_auditor_model", return_value=auditor_payload):
            response = self._post("What medication should I take for chest pain?")
        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "HUMAN_REVIEW")
        record = self._assert_complete_audit_record(body["request_id"], "HUMAN_REVIEW")
        self.assertEqual(record.human_review_status, "PENDING")
        self.assertIsNotNone(record.human_review)
        self.assertEqual(record.human_review["violated_policies"], ["medical_and_health"])
        # No generation call was made — nothing to audit yet.
        self.assertEqual(record.response_metrics, {})

    def test_verify_then_retry_succeeds_to_allow(self):
        config = pe.load_policy_config()
        trigger = _trigger_values_for(config)["verify_hallucination_risk"]
        bad_payload = _all_clear_audit_payload(hallucination_risk_score=trigger, recommended_action="VERIFY")
        good_payload = _all_clear_audit_payload(recommended_action="ALLOW")
        with patch(
            "core.auditing_engine.call_auditor_model",
            side_effect=[json.dumps(bad_payload), json.dumps(good_payload)],
        ):
            response = self._post("Summarise this document for me.")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ALLOW")
        record = self._assert_complete_audit_record(body["request_id"], "ALLOW")
        # The VERIFY/RETRY loop ran once before resolving to ALLOW — this
        # must be visible to core.dashboard.retry_verify_rate even though
        # final_action never persists as "VERIFY" itself.
        self.assertEqual(record.response_metrics["verify_retry_count"], 1)

    def test_verify_exhausted_delivers_allow_with_a_warning(self):
        config = pe.load_policy_config()
        trigger = _trigger_values_for(config)["verify_hallucination_risk"]
        bad_payload = _all_clear_audit_payload(hallucination_risk_score=trigger, recommended_action="VERIFY")
        with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(bad_payload)):
            response = self._post("Summarise this document for me.")
        # Per product decision, response-side auditing can never
        # escalate to HUMAN_REVIEW any more (see core.policy_
        # engine's RULE_ORDER comment) — exhausted retries deliver
        # the last attempt instead, flagged with a Verify warning.
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ALLOW")
        record = self._assert_complete_audit_record(body["request_id"], "ALLOW")
        self.assertTrue(any(w["dimension"] == "retry_exhausted" for w in record.verify_warnings))
        # All max_retries attempts ran (each one also came back VERIFY).
        self.assertEqual(record.response_metrics["verify_retry_count"], config["max_retries"])


class GeographyRegulationWiringTests(TestCase):
    """Step 10: geography/regulation metadata wired end to end through the
    real endpoint. Since "use case" was removed, these are now fixed,
    system-wide values (core.pipeline's _FIXED_* constants) rather than
    configurable per request — this verifies they flow through correctly,
    not that they vary."""

    def test_audit_record_carries_fixed_geography_and_regulation_metadata(self):
        response = self.client.post(
            "/api/requests/",
            data=json.dumps({
                "raw_prompt": "What are your business hours?",
                "user_id": "u1", "session_id": str(uuid.uuid4()),
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        record = AuditRecord.objects.get(trace_id=response.json()["request_id"])
        self.assertEqual(record.geography, [])
        self.assertEqual(record.regulation_versions, {})
        self.assertFalse(record.compliance_metadata["eu_ai_act_high_risk"])
        self.assertEqual(record.compliance_metadata["effective_audit_retention_days"], 90)
        self.assertIsNone(record.compliance_metadata["conformity_log"])


class SessionRiskEscalationLivePipelineTests(TestCase):
    """Step 10: session-risk escalation (Step 8) actually applied across
    real turns through the live endpoint, not just the standalone module
    test from Step 8."""

    def setUp(self):
        self.config = pe.load_policy_config()

    def _post(self, session_id, raw_prompt):
        return self.client.post(
            "/api/requests/",
            data=json.dumps({
                "raw_prompt": raw_prompt, "user_id": "u1", "session_id": session_id,
            }),
            content_type="application/json",
        )

    def test_session_state_persists_and_accumulates_across_turns(self):
        session_id = str(uuid.uuid4())
        self._post(session_id, "What are your business hours?")
        self._post(session_id, "What are your business hours?")

        session = SessionState.objects.get(session_id=session_id)
        self.assertEqual(session.turn_number, 2)
        self.assertEqual(len(session.recent_risk_scores), 2)
        self.assertEqual(session.previous_decisions, ["ALLOW", "ALLOW"])
