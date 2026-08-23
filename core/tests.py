import json
import time
import uuid
from unittest.mock import patch

from django.contrib import admin
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
    PolicyConfig,
    ReviewerAction,
    SessionState,
    ThresholdChangeProposal,
    Trace,
    UseCaseProfile,
    UserFeedback,
)
from .views import SAFE_ERROR_MESSAGE


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
        for model in (UseCaseProfile, PolicyConfig, Trace, SessionState, AuditRecord):
            self.assertIn(model, admin.site._registry, f"{model.__name__} not registered in admin")


class CoreModelsEmptyOnFreshMigrationTests(TestCase):
    """On a freshly migrated test database, every core table starts empty."""

    def test_tables_start_empty(self):
        self.assertEqual(UseCaseProfile.objects.count(), 0)
        self.assertEqual(PolicyConfig.objects.count(), 0)
        self.assertEqual(Trace.objects.count(), 0)
        self.assertEqual(SessionState.objects.count(), 0)
        self.assertEqual(AuditRecord.objects.count(), 0)


class CoreModelsRelationshipTests(TestCase):
    """Sanity-checks the relationships and fields declared on the core models
    against the architecture doc's schemas (Section 5.1, 6.1, 6.3, 14.1, 14.2)."""

    def setUp(self):
        self.use_case = UseCaseProfile.objects.create(
            use_case_id="DecisionSupport",
            name="Decision Support",
            geography=["IN", "EU"],
            regulations=["DPDP", "GDPR"],
            model_tier_preference="high",
            session_risk_window=5,
            audit_retention_days=90,
        )

    def test_policy_config_tied_to_use_case(self):
        policy = PolicyConfig.objects.create(
            use_case_profile=self.use_case,
            version="1.2",
            thresholds={
                "block": {"data_leakage_risk": 8, "safety_risk": 8},
                "human_review": {"safety_risk": 7},
                "modify": {"data_leakage_risk": 5},
                "verify": {"hallucination_risk": 6},
            },
            max_retries=2,
            latency_budget_ms=8000,
        )
        self.assertEqual(self.use_case.policy_configs.count(), 1)
        self.assertEqual(policy.thresholds["block"]["safety_risk"], 8)

    def test_trace_opens_with_uuid_and_open_status(self):
        trace = Trace.objects.create(
            user_id="user-1",
            use_case=self.use_case,
            raw_prompt="What is the loan approval policy?",
            client_metadata={"channel": "web"},
        )
        self.assertIsNotNone(trace.request_id)
        self.assertEqual(trace.status, Trace.STATUS_OPEN)
        self.assertIsNone(trace.final_decision)

    def test_session_state_tracks_accumulator_and_history(self):
        session = SessionState.objects.create(
            use_case=self.use_case,
            turn_number=3,
            session_risk_accumulator=1.9,
            previous_decisions=["ALLOW", "ALLOW"],
        )
        self.assertEqual(session.previous_decisions, ["ALLOW", "ALLOW"])
        self.assertFalse(session.was_blocked)

    def test_audit_record_one_to_one_with_trace(self):
        trace = Trace.objects.create(
            user_id="user-1",
            use_case=self.use_case,
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

    Inputs: raw_prompt, user_id, session_id, use_case_id, client_metadata
    Outputs: request_id (UUID), trace_object (open), timestamp
    Failure: all failures in this step result in a 503 with a safe error
    message; the trace is never lost.
    """

    url = "/api/requests/"

    def setUp(self):
        self.use_case = UseCaseProfile.objects.create(
            use_case_id="CustomerSupport",
            name="Customer Support",
            model_tier_preference="mid",
        )
        self.session_id = str(uuid.uuid4())
        self.valid_payload = {
            "raw_prompt": "What is your refund policy?",
            "user_id": "user-42",
            "session_id": self.session_id,
            "use_case_id": "CustomerSupport",
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
        self.assertEqual(trace.use_case, self.use_case)
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

    def test_missing_use_case_id_returns_503(self):
        payload = dict(self.valid_payload)
        del payload["use_case_id"]
        response = self.post(payload)
        self.assertEqual(response.status_code, 503)

    def test_unknown_use_case_id_returns_503(self):
        payload = dict(self.valid_payload)
        payload["use_case_id"] = "DoesNotExist"
        response = self.post(payload)
        self.assertEqual(response.status_code, 503)

    def test_inactive_use_case_profile_returns_503(self):
        self.use_case.is_active = False
        self.use_case.save()
        response = self.post(self.valid_payload)
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
            {**self.valid_payload, "use_case_id": "Nope"},
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


class UseCaseClassificationTests(TestCase):
    """Section 3 Step 2, 2D — Use-Case Classification into the 3 baseline
    profiles (CustomerSupport, InternalKnowledge, DecisionSupport)."""

    def test_customer_support_prompt_classified_correctly(self):
        result = pra.classify_use_case("I want a refund for my order, it never arrived.")
        self.assertEqual(result, "CustomerSupport")

    def test_internal_knowledge_prompt_classified_correctly(self):
        result = pra.classify_use_case("What is our internal HR policy on parental leave?")
        self.assertEqual(result, "InternalKnowledge")

    def test_decision_support_prompt_classified_correctly(self):
        result = pra.classify_use_case(
            "Should we approve this loan application given the applicant's credit history?"
        )
        self.assertEqual(result, "DecisionSupport")

    def test_ambiguous_prompt_returns_none_rather_than_guessing(self):
        result = pra.classify_use_case("What's the weather like today?")
        self.assertIsNone(result)


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
            use_case_profile="CustomerSupport",
            conversation_history_summary="First turn.",
            pre_request_flags={"pii_detected_in_prompt": False},
        )
        self.assertIn("evaluate the following AI-generated response", prompt["system"])
        self.assertEqual(prompt["user"]["original_prompt"], "What is our refund policy?")
        self.assertEqual(prompt["user"]["ai_response"], "You can request a refund within 30 days.")
        self.assertEqual(prompt["user"]["use_case_profile"], "CustomerSupport")
        self.assertEqual(prompt["user"]["conversation_history_summary"], "First turn.")
        self.assertEqual(prompt["user"]["pre_request_flags"], {"pii_detected_in_prompt": False})

    def test_pre_request_flags_defaults_to_empty_dict(self):
        prompt = ae.build_audit_prompt("p", "r", "CustomerSupport")
        self.assertEqual(prompt["user"]["pre_request_flags"], {})

    def test_escalated_prompt_names_the_previous_failure_and_differs_from_base(self):
        base = ae.build_audit_prompt("p", "r", "CustomerSupport")
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
            use_case_profile="CustomerSupport",
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
    per-use-case YAML policy file."""

    def test_decision_support_config_matches_the_documents_literal_example(self):
        config = pe.load_policy_config("DecisionSupport")
        self.assertEqual(config["use_case_id"], "DecisionSupport")
        self.assertEqual(config["geography"], ["IN", "EU"])
        self.assertEqual(
            config["thresholds"],
            {
                "block": {"data_leakage_risk": 8, "safety_risk": 8, "toxicity_risk": 9},
                "human_review": {"safety_risk": 7, "policy_violation_risk": 7, "hallucination_risk": 8},
                "modify": {"data_leakage_risk": 5, "pii_detected": True},
                "verify": {"hallucination_risk": 6, "correctness": 5},
            },
        )
        self.assertEqual(config["max_retries"], 2)
        self.assertEqual(config["latency_budget_ms"], 8000)
        self.assertTrue(config["require_human_review_for_final_block"])

    def test_customer_support_config_loads_with_doc_grounded_latency(self):
        config = pe.load_policy_config("CustomerSupport")
        self.assertEqual(config["use_case_id"], "CustomerSupport")
        # Section 3 Step 4: "5 s for CustomerSupport" — the one doc-grounded
        # value in this placeholder config.
        self.assertEqual(config["latency_budget_ms"], 5000)
        for bucket in ("block", "human_review", "modify", "verify"):
            self.assertIn(bucket, config["thresholds"])

    def test_internal_knowledge_config_loads(self):
        config = pe.load_policy_config("InternalKnowledge")
        self.assertEqual(config["use_case_id"], "InternalKnowledge")
        for bucket in ("block", "human_review", "modify", "verify"):
            self.assertIn(bucket, config["thresholds"])


class PolicyEngineOrderingTests(TestCase):
    """Section 3 Step 8 — Policy Engine. Parametrized tests feeding audit
    score combos against DecisionSupport's (doc-literal) thresholds,
    asserting the correct rule fires in the right priority order: BLOCK
    before HUMAN_REVIEW before MODIFY before VERIFY before ALLOW."""

    def setUp(self):
        self.config = pe.load_policy_config("DecisionSupport")

    def evaluate(self, scores, context=None):
        return pe.evaluate_policy(self.config, scores, context)

    def test_baseline_safe_scores_allow(self):
        result = self.evaluate(_safe_scores())
        self.assertEqual(result["final_action"], "ALLOW")
        self.assertEqual(result["rules_triggered"], [])
        self.assertEqual(
            result["rules_evaluated"],
            ["BLOCK_CHECK", "HUMAN_REVIEW_CHECK", "MODIFY_CHECK", "VERIFY_CHECK"],
        )

    # (score overrides, context, expected_final_action) — each row is a
    # single-bucket breach in isolation, in priority order.
    SINGLE_BUCKET_CASES = [
        ({"safety_risk_score": 8}, None, "BLOCK"),
        ({"data_leakage_risk_score": 8}, None, "BLOCK"),
        ({"toxicity_risk_score": 9}, None, "BLOCK"),
        ({"safety_risk_score": 7}, None, "HUMAN_REVIEW"),
        ({"policy_violation_risk_score": 7}, None, "HUMAN_REVIEW"),
        ({"hallucination_risk_score": 8}, None, "HUMAN_REVIEW"),
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
    # MULTIPLE buckets at once; the earlier bucket in BLOCK > HUMAN_REVIEW
    # > MODIFY > VERIFY must always win.
    PRIORITY_CLASH_CASES = [
        # block + human_review + modify + verify all breached at once -> BLOCK wins
        (
            {
                "safety_risk_score": 8, "data_leakage_risk_score": 8,
                "policy_violation_risk_score": 7, "hallucination_risk_score": 8,
                "correctness_score": 4,
            },
            None, "BLOCK",
        ),
        # human_review + modify + verify breached, block not -> HUMAN_REVIEW wins
        (
            {
                "safety_risk_score": 7, "data_leakage_risk_score": 5,
                "hallucination_risk_score": 6,
            },
            None, "HUMAN_REVIEW",
        ),
        # modify + verify breached, block/human_review not -> MODIFY wins
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

    def test_rules_evaluated_checks_all_four_when_none_fire(self):
        result = self.evaluate(_safe_scores())
        self.assertEqual(len(result["rules_evaluated"]), 4)


class PolicyEnginePiiFlagTests(TestCase):
    """Section 5.1's modify bucket: { data_leakage_risk: 5, pii_detected:
    true } — a non-numeric, boolean-flag threshold condition."""

    def setUp(self):
        self.config = pe.load_policy_config("DecisionSupport")

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
        self.config = pe.load_policy_config("DecisionSupport")

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
        payload = _valid_audit_payload(
            safety_risk_score=1, data_leakage_risk_score=4, toxicity_risk_score=1,
            bias_risk_score=2, policy_violation_risk_score=1, prompt_injection_risk_score=1,
            correctness_score=8, hallucination_risk_score=3,
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

    def test_pii_redacted_with_doc_exact_placeholder_labels(self):
        text = "Contact John Smith at john.smith@example.com for details."
        result = de.execute_modify(text)

        self.assertEqual(result["final_decision"], "MODIFY")
        # Section 9's own two examples: "[REDACTED:EMAIL]", "[REDACTED:NAME]"
        self.assertIn("[REDACTED:NAME]", result["user_response"])
        self.assertIn("[REDACTED:EMAIL]", result["user_response"])
        self.assertNotIn("John Smith", result["user_response"])
        self.assertNotIn("john.smith@example.com", result["user_response"])

    def test_disclosure_notice_included_by_default(self):
        result = de.execute_modify("Contact John Smith for details.")
        self.assertIsNotNone(result["disclosure_notice"])

    def test_disclosure_notice_can_be_suppressed(self):
        result = de.execute_modify("Contact John Smith for details.", disclosure_notice=None)
        self.assertIsNone(result["disclosure_notice"])

    def test_original_content_is_encrypted_and_recoverable(self):
        original = "Contact John Smith at john.smith@example.com for details."
        result = de.execute_modify(original)

        encrypted = result["modification_log"]["original_content_encrypted"]
        self.assertNotEqual(encrypted, original)
        self.assertNotIn("John Smith", encrypted)
        decrypted = de.decrypt_original_content(encrypted)
        self.assertEqual(decrypted, original)

    def test_modification_log_records_modified_output_and_categories(self):
        result = de.execute_modify("Contact John Smith at john.smith@example.com for details.")
        log = result["modification_log"]
        self.assertEqual(log["modified_output"], result["user_response"])
        self.assertIn("PERSON", log["categories_redacted"])
        self.assertIn("EMAIL", log["categories_redacted"])

    def test_text_with_no_pii_is_returned_unchanged(self):
        text = "The refund window is 30 days."
        result = de.execute_modify(text)
        self.assertEqual(result["user_response"], text)


class HumanReviewPathTests(TestCase):
    """Section 3 Step 9 HUMAN_REVIEW."""

    def setUp(self):
        self.audit_json = {"safety_risk_score": 7, "safety_risk_reason": "borderline"}
        self.result = de.execute_human_review(
            audit_json=self.audit_json,
            raw_response="Here is some financial guidance.",
            redacted_response="Here is some financial guidance.",
            policy_trigger_reason="human_review threshold breached on 'safety_risk'.",
        )

    def test_queued_case_contains_everything_the_reviewer_needs(self):
        case = self.result["queued_case"]
        self.assertEqual(case["status"], "PENDING")
        self.assertEqual(case["audit_json"], self.audit_json)
        self.assertEqual(case["raw_response"], "Here is some financial guidance.")
        self.assertEqual(case["redacted_response"], "Here is some financial guidance.")
        self.assertEqual(case["policy_trigger_reason"], "human_review threshold breached on 'safety_risk'.")

    def test_user_is_informed_of_wait_time(self):
        self.assertIn("30 minutes", self.result["user_response"])
        self.assertEqual(self.result["estimated_wait_minutes"], 30)

    def test_reviewer_approve_returns_raw_response_and_is_attributed(self):
        decided = de.apply_reviewer_decision(
            self.result["queued_case"], decision="APPROVE", reviewer_id="reviewer-1",
        )
        self.assertEqual(decided["status"], "DECIDED")
        self.assertEqual(decided["decision"], "APPROVE")
        self.assertEqual(decided["reviewer_id"], "reviewer-1")
        self.assertIsNotNone(decided["decided_at"])
        self.assertEqual(decided["final_user_response"], "Here is some financial guidance.")

    def test_reviewer_modify_returns_the_reviewers_edited_text(self):
        decided = de.apply_reviewer_decision(
            self.result["queued_case"], decision="MODIFY", reviewer_id="reviewer-1",
            modified_response="Here is a corrected version of the guidance.",
        )
        self.assertEqual(decided["decision"], "MODIFY")
        self.assertEqual(decided["final_user_response"], "Here is a corrected version of the guidance.")

    def test_reviewer_modify_without_text_raises(self):
        with self.assertRaises(ValueError):
            de.apply_reviewer_decision(
                self.result["queued_case"], decision="MODIFY", reviewer_id="reviewer-1",
            )

    def test_reviewer_reject_returns_safe_message_and_leaks_nothing(self):
        decided = de.apply_reviewer_decision(
            self.result["queued_case"], decision="REJECT", reviewer_id="reviewer-1",
        )
        self.assertEqual(decided["decision"], "REJECT")
        self.assertEqual(decided["final_user_response"], de.SAFE_BLOCK_MESSAGE)
        self.assertNotIn("safety_risk", decided["final_user_response"])

    def test_invalid_decision_value_raises(self):
        with self.assertRaises(ValueError):
            de.apply_reviewer_decision(
                self.result["queued_case"], decision="MAYBE", reviewer_id="reviewer-1",
            )

    def test_decided_at_can_be_supplied_explicitly_for_deterministic_tests(self):
        import datetime
        fixed_time = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        decided = de.apply_reviewer_decision(
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

    def test_exhausting_both_retries_escalates_to_human_review(self):
        calls = []

        def attempt_fn(model_id, enhanced_prompt):
            calls.append((model_id, enhanced_prompt))
            return {"final_action": "VERIFY", "response_text": "still bad", "audit_json": {"x": 1}}

        result = de.execute_verify_retry(attempt_fn, initial_model_id="claude-haiku-4-5", max_retries=2)
        self.assertEqual(len(calls), 2)  # exactly max_retries attempts, no more
        self.assertEqual(result["final_decision"], "HUMAN_REVIEW")
        self.assertEqual(len(result["retry_attempts"]), 2)
        self.assertEqual(result["queued_case"]["audit_json"], {"x": 1})

    def test_resolved_outcome_of_modify_is_correctly_dispatched(self):
        def attempt_fn(model_id, enhanced_prompt):
            return {"final_action": "MODIFY", "response_text": "Contact John Smith for details."}

        result = de.execute_verify_retry(attempt_fn, initial_model_id="claude-haiku-4-5", max_retries=2)
        self.assertEqual(result["final_decision"], "MODIFY")
        self.assertIn("[REDACTED:NAME]", result["user_response"])

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
        self.policy_config = pe.load_policy_config("DecisionSupport")

    def test_allow_path(self):
        scores = _safe_scores()
        policy_result = pe.evaluate_policy(self.policy_config, scores)
        self.assertEqual(policy_result["final_action"], "ALLOW")

        result = de.execute_allow("The refund window is 30 days.")
        self.assertEqual(result["final_decision"], "ALLOW")
        self.assertEqual(result["user_response"], "The refund window is 30 days.")

    def test_verify_path_escalating_to_human_review(self):
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
        self.assertEqual(result["final_decision"], "HUMAN_REVIEW")
        self.assertEqual(len(result["retry_attempts"]), 2)

    def test_modify_path(self):
        scores = _safe_scores(data_leakage_risk_score=5)  # breaches DecisionSupport's modify threshold
        policy_result = pe.evaluate_policy(self.policy_config, scores)
        self.assertEqual(policy_result["final_action"], "MODIFY")

        result = de.execute_modify("Contact John Smith at john@example.com for details.")
        self.assertEqual(result["final_decision"], "MODIFY")
        self.assertIn("[REDACTED:NAME]", result["user_response"])
        self.assertIn("[REDACTED:EMAIL]", result["user_response"])

    def test_human_review_path(self):
        scores = _safe_scores(safety_risk_score=7)  # breaches DecisionSupport's human_review threshold
        policy_result = pe.evaluate_policy(self.policy_config, scores)
        self.assertEqual(policy_result["final_action"], "HUMAN_REVIEW")

        result = de.execute_human_review(
            audit_json=scores,
            raw_response="Here is some financial guidance.",
            redacted_response="Here is some financial guidance.",
            policy_trigger_reason=policy_result["reason"],
        )
        self.assertEqual(result["final_decision"], "HUMAN_REVIEW")
        self.assertEqual(result["queued_case"]["status"], "PENDING")
        self.assertEqual(result["queued_case"]["policy_trigger_reason"], policy_result["reason"])

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
        self.config = pe.load_policy_config("DecisionSupport")

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
        self.assertEqual(escalated["thresholds"]["human_review"]["hallucination_risk"], 7)  # was 8

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
        config = pe.load_policy_config("DecisionSupport")
        session_risk_threshold = config["session_risk_threshold"]  # 5.0
        state = _fresh_session_state()

        # A sequence of individually-borderline turns: safety_risk=6 never
        # breaches DecisionSupport's own human_review threshold (7) or
        # block threshold (8) on any single turn, so each turn on its own
        # would ALLOW. Section 6.1's own callout: "A series of
        # individually borderline responses can collectively establish a
        # harmful pattern."
        borderline_scores = _safe_scores(safety_risk_score=6)
        for _ in range(5):
            policy_result = pe.evaluate_policy(config, borderline_scores)
            self.assertEqual(policy_result["final_action"], "ALLOW")  # each turn alone is fine
            state = sr.update_session_risk_accumulator(
                state, turn_risk_score=6, turn_decision=policy_result["final_action"],
                window_size=config["session_risk_window"],
            )

        # After 5 turns of safety_risk=6, the rolling average is exactly 6.0.
        self.assertAlmostEqual(state["session_risk_accumulator"], 6.0)
        self.assertTrue(sr.is_escalated(state, session_risk_threshold))

        # Apply escalation for the next ("subsequent") turn.
        effective_config = sr.get_effective_policy_config(config, state, session_risk_threshold)
        self.assertNotEqual(effective_config, config)

        # The SAME safety_risk=6 turn that always ALLOWed under the
        # original config now breaches the escalated human_review
        # threshold (7 - 1 = 6), proving stricter thresholds are applied.
        next_turn_result_original = pe.evaluate_policy(config, borderline_scores)
        next_turn_result_escalated = pe.evaluate_policy(effective_config, borderline_scores)
        self.assertEqual(next_turn_result_original["final_action"], "ALLOW")
        self.assertEqual(next_turn_result_escalated["final_action"], "HUMAN_REVIEW")


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


def _seed_dashboard_records(use_case):
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
        ("HUMAN_REVIEW", 300, 0.03, "claude-opus", 0, 4, 8, 2, 3, ["HUMAN_REVIEW_CHECK:safety_risk"]),
        ("BLOCK", 50, 0.005, "claude-haiku-4-5", 0, 2, 9, 1, 9, ["BLOCK_CHECK:data_leakage_risk"]),
    ]
    records = []
    for final_action, latency, cost, model, retries, halluc, safety, bias, leakage, triggered in specs:
        trace = Trace.objects.create(user_id="u1", use_case=use_case, raw_prompt="hi")
        human_review = None
        human_review_status = None
        if final_action == "HUMAN_REVIEW":
            human_review_status = "PENDING"
            human_review = {
                "status": "PENDING",
                "audit_json": {},
                "raw_response": "Here is some financial guidance.",
                "redacted_response": "Here is some financial guidance.",
                "policy_trigger_reason": "human_review threshold breached on 'safety_risk'.",
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
        self.use_case = UseCaseProfile.objects.create(use_case_id="CustomerSupport", name="Customer Support")
        self.records = _seed_dashboard_records(self.use_case)

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
        self.use_case = UseCaseProfile.objects.create(use_case_id="CustomerSupport", name="Customer Support")
        self.records = _seed_dashboard_records(self.use_case)

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


class HumanReviewDecisionViewTests(TestCase):
    """Test: submit a reviewer decision through the UI/API and assert
    it's persisted as a gold-standard label tied to the original audit
    record."""

    def setUp(self):
        self.use_case = UseCaseProfile.objects.create(use_case_id="DecisionSupport", name="Decision Support")
        self.records = _seed_dashboard_records(self.use_case)
        self.pending_record = next(r for r in self.records if r.final_action == "HUMAN_REVIEW")

    def test_approve_decision_persists_as_gold_standard_label(self):
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "reviewer_id": "reviewer-42",
            "decision": "APPROVE",
            "decision_reason": "Looks correct on review.",
        })
        self.assertEqual(response.status_code, 200)

        self.pending_record.refresh_from_db()
        self.assertEqual(self.pending_record.human_review_status, "DECIDED")
        self.assertEqual(self.pending_record.human_review["decision"], "APPROVE")
        self.assertEqual(
            self.pending_record.human_review["final_user_response"],
            "Here is some financial guidance.",
        )

        actions = ReviewerAction.objects.filter(audit_record=self.pending_record)
        self.assertEqual(actions.count(), 1)
        action = actions.first()
        self.assertEqual(action.reviewer_id, "reviewer-42")
        self.assertEqual(action.decision, "APPROVE")
        self.assertEqual(action.decision_reason, "Looks correct on review.")

    def test_modify_decision_uses_reviewers_text(self):
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "reviewer_id": "reviewer-42",
            "decision": "MODIFY",
            "modified_response": "Corrected guidance text.",
        })
        self.assertEqual(response.status_code, 200)
        self.pending_record.refresh_from_db()
        self.assertEqual(self.pending_record.human_review["final_user_response"], "Corrected guidance text.")
        self.assertEqual(ReviewerAction.objects.get(audit_record=self.pending_record).decision, "MODIFY")

    def test_reject_decision_recorded_and_leaks_nothing(self):
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "reviewer_id": "reviewer-42",
            "decision": "REJECT",
        })
        self.assertEqual(response.status_code, 200)
        self.pending_record.refresh_from_db()
        self.assertEqual(self.pending_record.human_review["final_user_response"], de.SAFE_BLOCK_MESSAGE)

    def test_invalid_decision_value_does_not_persist_and_returns_error(self):
        response = self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "reviewer_id": "reviewer-42",
            "decision": "MAYBE",
        })
        self.assertEqual(response.status_code, 400)
        self.pending_record.refresh_from_db()
        self.assertEqual(self.pending_record.human_review_status, "PENDING")
        self.assertEqual(ReviewerAction.objects.filter(audit_record=self.pending_record).count(), 0)

    def test_after_decision_case_no_longer_appears_in_pending_queue(self):
        self.client.post("/dashboard/human-review/", {
            "trace_id": str(self.pending_record.trace_id),
            "reviewer_id": "reviewer-42",
            "decision": "APPROVE",
        })
        response = self.client.get("/dashboard/human-review/")
        self.assertEqual(len(response.context["pending_cases"]), 0)


class FprTuningViewTests(TestCase):
    """Section 9.3 — Operator Dashboard Alert Tuning View."""

    def setUp(self):
        self.use_case = UseCaseProfile.objects.create(use_case_id="DecisionSupport", name="Decision Support")

    def _make_record(self, hallucination_risk_score, rules_triggered):
        trace = Trace.objects.create(user_id="u1", use_case=self.use_case, raw_prompt="hi")
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
            "use_case_id": "DecisionSupport",
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
            "use_case_id": "DecisionSupport",
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
            "use_case_id": "DecisionSupport",
            "bucket": "verify",
            "dimension": "hallucination_risk",
            "current_threshold": "6",
            "proposed_threshold": "8",
            "rationale": "High FPR observed over the last week.",
        })
        self.assertEqual(response.status_code, 200)
        proposal = ThresholdChangeProposal.objects.get()
        self.assertEqual(proposal.status, "PENDING")
        self.assertEqual(proposal.use_case_id, "DecisionSupport")
        self.assertEqual(proposal.proposed_threshold, 8.0)

    def test_report_false_positive_creates_report(self):
        record = self._make_record(7, ["VERIFY_CHECK:hallucination_risk"])
        response = self.client.post("/dashboard/fpr-tuning/", {
            "action": "report_false_positive",
            "trace_id": str(record.trace_id),
            "dimension": "hallucination_risk",
            "reported_by": "op-1",
            "reason": "Manually verified as correct.",
        })
        self.assertEqual(response.status_code, 200)
        report = FalsePositiveReport.objects.get()
        self.assertEqual(report.audit_record_id, record.trace_id)
        self.assertEqual(report.dimension, "hallucination_risk")


class ThumbsDownViewTests(TestCase):
    """Section 7.1 User Thumbs-Down."""

    def setUp(self):
        self.use_case = UseCaseProfile.objects.create(use_case_id="CustomerSupport", name="Customer Support")
        self.trace = Trace.objects.create(user_id="u1", use_case=self.use_case, raw_prompt="hi")

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
    """Computes, from a use-case's own loaded policy config, score values
    that breach exactly one specific bucket without also breaching a
    higher-priority one — used by the end-to-end scenario tests below so
    they adapt to whatever the actual YAML thresholds are, rather than
    relying on hand-copied magic numbers per use case."""
    t = config["thresholds"]
    return {
        "human_review_safety_risk": min(t["human_review"]["safety_risk"], t["block"]["safety_risk"] - 1),
        "verify_hallucination_risk": min(
            t["verify"]["hallucination_risk"], t["human_review"]["hallucination_risk"] - 1
        ),
    }


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
    paths x 3 use-case profiles, run through the real, now-wired
    /api/requests/ endpoint. Test: assert both the expected final
    decision and a complete, correctly-populated audit record."""

    USE_CASES = ["CustomerSupport", "InternalKnowledge", "DecisionSupport"]

    def setUp(self):
        for use_case_id in self.USE_CASES:
            UseCaseProfile.objects.get_or_create(use_case_id=use_case_id, defaults={"name": use_case_id})

    def _post(self, use_case_id, raw_prompt):
        return self.client.post(
            "/api/requests/",
            data=json.dumps({
                "raw_prompt": raw_prompt,
                "user_id": "scenario-user",
                "session_id": str(uuid.uuid4()),
                "use_case_id": use_case_id,
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

    def test_allow_scenario_for_every_use_case(self):
        for use_case_id in self.USE_CASES:
            with self.subTest(use_case=use_case_id):
                response = self._post(use_case_id, "What are your business hours?")
                self.assertEqual(response.status_code, 200)
                body = response.json()
                self.assertEqual(body["status"], "ALLOW")
                record = self._assert_complete_audit_record(body["request_id"], "ALLOW")
                self.assertTrue(record.response_metrics)
                self.assertTrue(record.audit_quality)
                self.assertTrue(record.audit_responsibility)

    def test_block_via_router_pre_check_for_every_use_case(self):
        # Section 3 Step 2, 2C's own Critical-band example content, which
        # pre_request_analysis.risk_score scores at 9 regardless of use
        # case, triggering Section 3 Step 3's router pre-check BLOCK
        # before any model call.
        prompt = "This is a regulated decision affecting a safety-critical hospital system."
        for use_case_id in self.USE_CASES:
            with self.subTest(use_case=use_case_id):
                response = self._post(use_case_id, prompt)
                self.assertEqual(response.status_code, 200)
                body = response.json()
                self.assertEqual(body["status"], "BLOCK")
                self.assertEqual(body["message"], de.SAFE_BLOCK_MESSAGE)
                record = self._assert_complete_audit_record(body["request_id"], "BLOCK")
                self.assertEqual(record.policy_rules_triggered, ["ROUTER_PRE_CHECK:risk_score"])
                self.assertEqual(record.response_metrics, {})  # no model call was made

    def test_modify_via_pii_detection_for_every_use_case(self):
        # MODIFY's redaction target is the model's *response* text
        # (Section 3 Step 9 MODIFY: "The response is passed to a
        # redaction/modification module"), not the original user prompt —
        # the simulated stub response never echoes the prompt's PII back,
        # so this only asserts the correct path fired and the modification
        # log is present, not a redacted placeholder in this stub's reply.
        prompt = "Please update my contact email to john.smith@example.com."
        for use_case_id in self.USE_CASES:
            with self.subTest(use_case=use_case_id):
                response = self._post(use_case_id, prompt)
                self.assertEqual(response.status_code, 200)
                body = response.json()
                self.assertEqual(body["status"], "MODIFY")
                record = self._assert_complete_audit_record(body["request_id"], "MODIFY")
                self.assertIn("original_content_encrypted", record.modification)

    def test_human_review_via_audit_score_for_every_use_case(self):
        for use_case_id in self.USE_CASES:
            with self.subTest(use_case=use_case_id):
                config = pe.load_policy_config(use_case_id)
                trigger = _trigger_values_for(config)["human_review_safety_risk"]
                payload = _all_clear_audit_payload(safety_risk_score=trigger, recommended_action="HUMAN_REVIEW")
                with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(payload)):
                    response = self._post(use_case_id, "Give me guidance on this matter.")
                self.assertEqual(response.status_code, 202)
                body = response.json()
                self.assertEqual(body["status"], "HUMAN_REVIEW")
                record = self._assert_complete_audit_record(body["request_id"], "HUMAN_REVIEW")
                self.assertEqual(record.human_review_status, "PENDING")
                self.assertIsNotNone(record.human_review)

    def test_verify_then_retry_succeeds_to_allow_for_every_use_case(self):
        for use_case_id in self.USE_CASES:
            with self.subTest(use_case=use_case_id):
                config = pe.load_policy_config(use_case_id)
                trigger = _trigger_values_for(config)["verify_hallucination_risk"]
                bad_payload = _all_clear_audit_payload(hallucination_risk_score=trigger, recommended_action="VERIFY")
                good_payload = _all_clear_audit_payload(recommended_action="ALLOW")
                with patch(
                    "core.auditing_engine.call_auditor_model",
                    side_effect=[json.dumps(bad_payload), json.dumps(good_payload)],
                ):
                    response = self._post(use_case_id, "Summarise this document for me.")
                self.assertEqual(response.status_code, 200)
                body = response.json()
                self.assertEqual(body["status"], "ALLOW")
                self._assert_complete_audit_record(body["request_id"], "ALLOW")

    def test_verify_exhausted_escalates_to_human_review_for_every_use_case(self):
        for use_case_id in self.USE_CASES:
            with self.subTest(use_case=use_case_id):
                config = pe.load_policy_config(use_case_id)
                trigger = _trigger_values_for(config)["verify_hallucination_risk"]
                bad_payload = _all_clear_audit_payload(hallucination_risk_score=trigger, recommended_action="VERIFY")
                with patch("core.auditing_engine.call_auditor_model", return_value=json.dumps(bad_payload)):
                    response = self._post(use_case_id, "Summarise this document for me.")
                self.assertEqual(response.status_code, 202)
                body = response.json()
                self.assertEqual(body["status"], "HUMAN_REVIEW")
                self._assert_complete_audit_record(body["request_id"], "HUMAN_REVIEW")


class GeographyRegulationWiringTests(TestCase):
    """Step 10: geography/regulation rule injection wired by the use
    case's configured geography, verified end to end through the real
    endpoint."""

    def setUp(self):
        self.use_case = UseCaseProfile.objects.create(
            use_case_id="DecisionSupport", name="Decision Support",
            geography=["IN", "EU"], regulations=["GDPR", "DPDP"],
            eu_ai_act_high_risk=True, audit_retention_days=90,
        )

    def test_audit_record_carries_geography_and_regulation_versions(self):
        response = self.client.post(
            "/api/requests/",
            data=json.dumps({
                "raw_prompt": "What are your business hours?",
                "user_id": "u1", "session_id": str(uuid.uuid4()), "use_case_id": "DecisionSupport",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        record = AuditRecord.objects.get(trace_id=response.json()["request_id"])
        self.assertEqual(record.geography, ["IN", "EU"])
        self.assertEqual(record.regulation_versions, {"GDPR": "2024-Q4", "DPDP": "2024-Q2"})
        self.assertTrue(record.compliance_metadata["eu_ai_act_high_risk"])
        self.assertEqual(record.compliance_metadata["effective_audit_retention_days"], 2555)
        self.assertIsNotNone(record.compliance_metadata["conformity_log"])


class SessionRiskEscalationLivePipelineTests(TestCase):
    """Step 10: session-risk escalation (Step 8) actually applied across
    real turns through the live endpoint, not just the standalone module
    test from Step 8."""

    def setUp(self):
        self.use_case = UseCaseProfile.objects.create(
            use_case_id="DecisionSupport", name="Decision Support",
        )
        self.config = pe.load_policy_config("DecisionSupport")

    def _post(self, session_id, raw_prompt):
        return self.client.post(
            "/api/requests/",
            data=json.dumps({
                "raw_prompt": raw_prompt, "user_id": "u1",
                "session_id": session_id, "use_case_id": "DecisionSupport",
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
