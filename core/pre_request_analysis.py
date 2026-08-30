"""Section 3 Step 2 — Pre-Request Analysis.

2A PII & Sensitive Content Scan, 2B Complexity Score, 2C Risk Score,
2D Use-Case Classification.

Independently unit-tested and, since this project's Step 10, composed
live in core/pipeline.py, where its complexity/risk scores feed the
Step 3 Model Router (core/model_pipeline.py).
"""

import json
from functools import lru_cache

from django.conf import settings
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import SpacyRecognizer

from . import gemini_client

# ---------------------------------------------------------------------------
# 2A — PII & Sensitive Content Scan
# ---------------------------------------------------------------------------

# "Regex patterns for structured PII: emails, phone numbers, credit card
# numbers, national IDs, IP addresses, passport numbers." These are
# registered as custom presidio PatternRecognizers below, each given
# score=1.0 so a deterministic regex match always outranks a probabilistic
# NER guess when their spans overlap.
_CUSTOM_PII_PATTERNS = {
    "EMAIL": [
        ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ],
    "CREDIT_CARD": [
        ("credit_card", r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)"),
    ],
    "IP_ADDRESS": [
        ("ipv4", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    ],
    "NATIONAL_ID": [
        ("ssn", r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        ("national_id_grouped", r"(?<!\d)\d{4}[ -]\d{4}[ -]\d{4}(?!\d)"),
    ],
    "PASSPORT_NUMBER": [
        ("passport", r"\b[A-Z][0-9]{7,8}\b"),
    ],
    "PHONE_NUMBER": [
        ("phone", r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"),
    ],
}

# Used only to break ties when two candidate spans have identical score and
# length: structured/regex categories are preferred over NER-derived ones.
#
# LOCATION deliberately excluded (explicit product decision): geographic
# place names typed into a prompt are not redacted/pseudonymized here,
# unlike every other category below — see _get_analyzer's supported_entities.
_CATEGORY_PRIORITY = [
    "EMAIL", "CREDIT_CARD", "IP_ADDRESS", "NATIONAL_ID", "PASSPORT_NUMBER",
    "PHONE_NUMBER", "PERSON", "ORGANIZATION",
]


@lru_cache(maxsize=1)
def _get_analyzer():
    """Builds the PII analyzer once per process: the "Named Entity
    Recognition (NER) model (lightweight, < 50 ms) for person names [and]
    organisations" is spaCy's small English model, restricted to exactly
    those two entity types; combined with the custom regex
    PatternRecognizers above for the structured categories.

    LOCATION is deliberately NOT included here (explicit product
    decision): a geographic place name mentioned in a prompt is not
    treated as PII to redact, unlike a person's name, org, email, phone
    number, etc. — spaCy's LOCATION recognizer would otherwise also catch
    this project's own use-case geography codes/region names if they
    ever appeared in prompt text, which must never be pseudonymized."""
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    })
    nlp_engine = provider.create_engine()

    registry = RecognizerRegistry()
    registry.add_recognizer(
        SpacyRecognizer(
            supported_language="en",
            supported_entities=["PERSON", "ORGANIZATION"],
        )
    )
    for entity, patterns in _CUSTOM_PII_PATTERNS.items():
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity=entity,
                patterns=[
                    Pattern(name=name, regex=regex, score=1.0)
                    for name, regex in patterns
                ],
            )
        )

    return AnalyzerEngine(registry=registry, nlp_engine=nlp_engine, supported_languages=["en"])


def _resolve_overlaps(results):
    """Greedily selects a non-overlapping set of entity spans, preferring
    higher score, then longer span, then the fixed category priority."""

    def sort_key(result):
        if result.entity_type in _CATEGORY_PRIORITY:
            priority_index = _CATEGORY_PRIORITY.index(result.entity_type)
        else:
            priority_index = len(_CATEGORY_PRIORITY)
        return (-result.score, -(result.end - result.start), priority_index, result.start)

    accepted = []
    claimed = []
    for result in sorted(results, key=sort_key):
        overlaps = any(not (result.end <= start or result.start >= end) for start, end in claimed)
        if overlaps:
            continue
        accepted.append(result)
        claimed.append((result.start, result.end))
    return sorted(accepted, key=lambda r: r.start)


def detect_and_pseudonymize_pii(text):
    """Section 3 Step 2, 2A: detects structured + named-entity PII and
    replaces each occurrence with a reversible placeholder such as
    "[PERSON_1]" or "[EMAIL_1]" (Section 11.2 prototype scope example).

    Returns a dict with:
      pseudonymized_text — text with PII spans replaced by placeholders
      pii_detected       — bool
      pii_categories     — unique categories found, in order of first
                            appearance (e.g. ["PERSON", "EMAIL"], matching
                            the Section 14.1 audit record example)
      token_map          — {"[CATEGORY_N]": "<original value>"}, enabling
                            reversible de-pseudonymisation
    """
    if not text:
        return {
            "pseudonymized_text": text or "",
            "pii_detected": False,
            "pii_categories": [],
            "token_map": {},
        }

    analyzer = _get_analyzer()
    raw_results = analyzer.analyze(text=text, language="en")
    entities = _resolve_overlaps(raw_results)

    token_map = {}
    pii_categories = []
    category_counts = {}
    pieces = []
    cursor = 0
    for entity in entities:
        pieces.append(text[cursor:entity.start])
        category = entity.entity_type
        category_counts[category] = category_counts.get(category, 0) + 1
        placeholder = f"[{category}_{category_counts[category]}]"
        token_map[placeholder] = text[entity.start:entity.end]
        pieces.append(placeholder)
        if category not in pii_categories:
            pii_categories.append(category)
        cursor = entity.end
    pieces.append(text[cursor:])

    return {
        "pseudonymized_text": "".join(pieces),
        "pii_detected": bool(entities),
        "pii_categories": pii_categories,
        "token_map": token_map,
    }


def depseudonymize(text, token_map):
    """Reverses detect_and_pseudonymize_pii's substitution using its
    returned token_map (Section 9 ALLOW: "Original (or de-pseudonymised)
    response is returned to the user.")."""
    for placeholder, original in token_map.items():
        text = text.replace(placeholder, original)
    return text


# ---------------------------------------------------------------------------
# 2B — Complexity Score (1–10)
# ---------------------------------------------------------------------------

# Keyword bands taken directly from Section 3 Step 2, 2B's own category
# descriptions, ordered highest-to-lowest so that a prompt matching more
# than one band is scored at the highest (most conservative) match.
_COMPLEXITY_BANDS = [
    (9, ["regulatory interpretation", "medical diagnosis", "diagnosis support", "adversarial"]),
    (7, ["financial analysis", "legal analysis", "financial/legal analysis", "multi-document synthesis", "system design"]),
    (4, ["multi-step reasoning", "summarise", "summarize", "summarisation", "summarization", "code generation", "generate code", "write code", "write a function"]),
    (1, ["factual lookup", "single-step arithmetic", "yes/no", "yes or no", "factual", "arithmetic"]),
]

_DEFAULT_COMPLEXITY_SCORE = 2  # Section 2B band 1-3 (Simple) — the baseline absent any escalating signal.


def complexity_score(text):
    """Section 3 Step 2, 2B — a deterministic, keyword-driven stand-in for
    "a lightweight LLM prompt (< 150 tokens) or fine-tuned classifier".
    Section 1.3/11.1 explicitly permit simulated models in the prototype in
    place of live model calls, which is what this heuristic represents."""
    lowered = (text or "").lower()
    for score, keywords in _COMPLEXITY_BANDS:
        if any(keyword in lowered for keyword in keywords):
            return score
    return _DEFAULT_COMPLEXITY_SCORE


# ---------------------------------------------------------------------------
# 2C — Risk Score (1–10)
# ---------------------------------------------------------------------------

_RISK_BANDS = [
    (9, ["regulated decision", "safety-critical", "safety critical", "highly sensitive"]),
    (7, ["financial advice", "medical information", "legal interpretation", "medical advice", "legal advice"]),
    (4, ["internal business data", "internal business", "customer-facing information", "customer-facing", "hr quer"]),
    (1, ["general knowledge", "entertainment", "coding assistance", "public information"]),
]

_DEFAULT_RISK_SCORE = 2  # Section 2C band 1-3 (Low) — the baseline absent any escalating signal.

# Section 3 Step 2, 2C: the High band (7-8) explicitly includes "PII
# contexts", so detected PII floors the risk score at High regardless of
# any other signal.
_PII_RISK_FLOOR = 7


def risk_score(text, pii_detected=False):
    """Section 3 Step 2, 2C — heuristic risk classifier, same rationale as
    complexity_score above."""
    lowered = (text or "").lower()
    score = _DEFAULT_RISK_SCORE
    for band_score, keywords in _RISK_BANDS:
        if any(keyword in lowered for keyword in keywords):
            score = band_score
            break
    if pii_detected:
        score = max(score, _PII_RISK_FLOOR)
    return score


# ---------------------------------------------------------------------------
# 2B/2C — real model-driven analysis (replaces the keyword heuristics above
# for anything outside the test runner)
# ---------------------------------------------------------------------------

# complexity_score/risk_score above are keyword-driven stand-ins with a
# real gap: their band lists were transcribed from the architecture doc's
# own worked examples, so anything not phrased like those examples (e.g.
# "how to harm someone using a gun") silently falls through to the
# low-risk default. analyze_prompt below sends the raw prompt to a real
# Gemini call for actual judgment instead, and is what core.pipeline uses
# outside tests. complexity_score/risk_score are kept as the deterministic
# fallback used under settings.TESTING (see model_pipeline._simulated_response
# for the identical rationale) — the many tests in this module and
# elsewhere that assert exact scores for specific prompts stay unchanged.

_ANALYSIS_MODEL = "gemini-3.5-flash-lite"

_ANALYSIS_SYSTEM_PROMPT = (
    "You are an enterprise AI request-triage analyst. Given a user's raw "
    "prompt, score it on two independent 1-10 scales and return ONLY a "
    "JSON object matching the required schema.\n\n"
    "complexity_score (1-10): how difficult this request is to fulfil "
    "well - reasoning depth, ambiguity, length/structure of the expected "
    "answer. 1 = trivial factual lookup, 10 = requires deep multi-step "
    "reasoning.\n\n"
    "risk_score (1-10): how much potential harm, sensitivity, or "
    "liability this request carries if mishandled. This explicitly "
    "includes (but is not limited to) requests seeking help with "
    "violence, weapons, self-harm, illegal acts, hate speech, or "
    "medical/legal/financial advice. 1-3 = low risk (general knowledge, "
    "harmless small talk). 4-6 = moderate (business/customer data, "
    "internal information). 7-8 = high (medical, legal, or financial "
    "advice, or content that could cause real harm). 9-10 = critical "
    "(the request clearly seeks help causing serious harm - e.g. "
    "violence, weapons, self-harm - or a safety-critical/regulated "
    "decision). Use the 9-10 band even if the request is phrased "
    "indirectly, hypothetically, or as fiction/roleplay."
)

_ANALYSIS_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "complexity_score": {"type": "integer"},
        "complexity_reason": {"type": "string"},
        "risk_score": {"type": "integer"},
        "risk_reason": {"type": "string"},
    },
    "required": ["complexity_score", "complexity_reason", "risk_score", "risk_reason"],
}

_ANALYSIS_MAX_ATTEMPTS = 2


class RiskAnalysisError(Exception):
    """Raised when the real risk/complexity analysis call fails validation
    on every attempt. Mirrors model_pipeline.ModelExecutionError: callers
    let this propagate rather than silently guessing a score for a step
    this safety-critical (a wrong guess here could route a harmful prompt
    around the router's BLOCK pre-check)."""


def _call_risk_analyzer_model(text):
    response = gemini_client.get_client().models.generate_content(
        model=_ANALYSIS_MODEL,
        contents=text,
        config={
            "system_instruction": _ANALYSIS_SYSTEM_PROMPT,
            "response_mime_type": "application/json",
            "response_schema": _ANALYSIS_RESPONSE_SCHEMA,
        },
    )
    return response.text


def _parse_and_validate_analysis_response(raw_text):
    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError):
        return False, None
    if not isinstance(data, dict):
        return False, None
    for key in ("complexity_score", "risk_score"):
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not (1 <= value <= 10):
            return False, None
    return True, data


def analyze_prompt(text, pii_detected=False):
    """Returns (complexity_score, risk_score) for the given prompt text.
    Real Gemini-backed analysis outside tests (see module docstring
    above); the deterministic keyword heuristic under settings.TESTING.
    Retries up to _ANALYSIS_MAX_ATTEMPTS times on a malformed/out-of-range
    response OR the call itself failing (rate limit, a safety-blocked/
    empty response, a network error), then raises RiskAnalysisError.
    """
    if settings.TESTING:
        return complexity_score(text), risk_score(text, pii_detected=pii_detected)

    for _attempt in range(_ANALYSIS_MAX_ATTEMPTS):
        try:
            raw_text = _call_risk_analyzer_model(text)
        except Exception:
            continue
        is_valid, data = _parse_and_validate_analysis_response(raw_text)
        if is_valid:
            score = data["risk_score"]
            if pii_detected:
                score = max(score, _PII_RISK_FLOOR)
            return data["complexity_score"], score

    raise RiskAnalysisError(
        "Risk/complexity analyzer failed to return a valid score after "
        f"{_ANALYSIS_MAX_ATTEMPTS} attempts."
    )
