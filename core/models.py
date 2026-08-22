import uuid

from django.db import models


# Section 7/8/14.1-14.2 of the architecture doc: the auditor's recommendation and
# the policy engine's final action are always one of these five values.
DECISION_CHOICES = [
    ("ALLOW", "Allow"),
    ("VERIFY", "Verify"),
    ("MODIFY", "Modify"),
    ("HUMAN_REVIEW", "Human Review"),
    ("BLOCK", "Block"),
]

# Section 14.2 policy config schema: model_tier_preference: [low, mid, high, expert]
MODEL_TIER_CHOICES = [
    ("low", "Low"),
    ("mid", "Mid"),
    ("high", "High"),
    ("expert", "Expert"),
]


class UseCaseProfile(models.Model):
    """Section 2.2 Decision 3: every request carries a use_case_id that maps to a
    pre-configured profile governing model tier preference, geography/regulation
    set, and session-risk behaviour. Section 2.4/6.1 default session_risk_window
    of 5 turns; Section 10.3 default audit retention of 90 days."""

    use_case_id = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # Section 5.1 example: "geography: IN,EU # applies DPDP, GDPR rules"
    geography = models.JSONField(default=list, blank=True)
    # Section 14.2: "regulations: list[regulation_id]"
    regulations = models.JSONField(default=list, blank=True)

    # Section 14.2: "model_tier_preference: [low, mid, high, expert]"
    model_tier_preference = models.CharField(
        max_length=10, choices=MODEL_TIER_CHOICES, default="mid"
    )

    # Section 6.1: "Rolling average of risk scores across the last N turns
    # (configurable, default N = 5)."
    session_risk_window = models.PositiveIntegerField(default=5)

    # Section 10.3: "Audit records are retained ... minimum 90 days, up to 7 years
    # for regulated industries."
    audit_retention_days = models.PositiveIntegerField(default=90)

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["use_case_id"]

    def __str__(self):
        return self.use_case_id


class PolicyConfig(models.Model):
    """Section 5.1: per-use-case YAML policy file holding thresholds for
    block/human_review/modify/verify, max_retries and latency_budget_ms.
    Section 5 callout: "Changing a threshold requires no code deployment — only
    a config reload", and Section 7.2: "All threshold changes are versioned and
    auditable" — hence this is a distinct, versioned model tied to a
    UseCaseProfile rather than being folded into it."""

    use_case_profile = models.ForeignKey(
        UseCaseProfile, on_delete=models.CASCADE, related_name="policy_configs"
    )
    # Section 14.2: "version: semver string"
    version = models.CharField(max_length=50)

    # Section 5.1 example structure:
    # thresholds: { block: {...}, human_review: {...}, modify: {...}, verify: {...} }
    thresholds = models.JSONField(default=dict, blank=True)

    # Section 14.2: "max_retries: integer (0–3)"; Section 9 default is 2.
    max_retries = models.PositiveSmallIntegerField(default=2)
    # Section 3 Step 4: e.g. 5s for CustomerSupport, 30s for DecisionSupport.
    latency_budget_ms = models.PositiveIntegerField(default=5000)
    # Section 14.2: "require_human_for_block: bool" (5.1: require_human_review_for_final_block)
    require_human_for_block = models.BooleanField(default=False)
    # Section 14.2: "session_risk_threshold: float"
    session_risk_threshold = models.FloatField(default=5.0)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["use_case_profile", "version"],
                name="unique_policy_version_per_use_case",
            )
        ]

    def __str__(self):
        return f"{self.use_case_profile.use_case_id} v{self.version}"


class Trace(models.Model):
    """Section 3 Step 1 — Request Ingestion & Trace Initialisation.
    Inputs: raw_prompt, user_id, session_id, use_case_id, client_metadata.
    Outputs: request_id (UUID), trace_object (open), timestamp.
    "Failure: All failures in this step result in a 503 with a safe error
    message; the trace is never lost." """

    STATUS_OPEN = "OPEN"
    STATUS_CLOSED = "CLOSED"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_CLOSED, "Closed"),
    ]

    request_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_id = models.UUIDField(default=uuid.uuid4)
    user_id = models.CharField(max_length=200)
    use_case = models.ForeignKey(
        UseCaseProfile, on_delete=models.PROTECT, related_name="traces"
    )
    raw_prompt = models.TextField()
    client_metadata = models.JSONField(default=dict, blank=True)

    status = models.CharField(
        max_length=10, choices=STATUS_CHOICES, default=STATUS_OPEN
    )
    # Section 9 Decision Execution: "Trace is closed as ALLOWED" (and analogously
    # for the other four decision outcomes).
    final_decision = models.CharField(
        max_length=20, choices=DECISION_CHOICES, blank=True, null=True
    )

    timestamp = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["session_id"]),
        ]

    def __str__(self):
        return str(self.request_id)


class SessionState(models.Model):
    """Section 6.1 Compounding Risk Tracking — session_risk_accumulator tracks:
    rolling average of risk scores across the last N turns; count of VERIFY,
    MODIFY, HUMAN_REVIEW decisions in the session; flag if any previous turn was
    BLOCKED. Section 6.3: session-level token replacement map for consistent
    PII pseudonymisation/de-pseudonymisation across turns. Section 14.1
    session_state schema: turn_number, session_risk_accumulator,
    session_risk_threshold, previous_decisions."""

    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    use_case = models.ForeignKey(
        UseCaseProfile, on_delete=models.PROTECT, related_name="session_states"
    )

    turn_number = models.PositiveIntegerField(default=0)
    session_risk_accumulator = models.FloatField(default=0.0)

    # Section 6.1: "Count of VERIFY, MODIFY, and HUMAN_REVIEW decisions in the
    # current session."
    verify_count = models.PositiveIntegerField(default=0)
    modify_count = models.PositiveIntegerField(default=0)
    human_review_count = models.PositiveIntegerField(default=0)

    # Section 6.1: "Flag if any previous turn in the session was BLOCKED."
    was_blocked = models.BooleanField(default=False)

    # Section 14.1: "previous_decisions": ["ALLOW", "ALLOW"]
    previous_decisions = models.JSONField(default=list, blank=True)

    # Section 6.3: "maintaining a session-level token replacement map so the
    # de-pseudonymisation step remains consistent throughout the session."
    token_replacement_map = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.session_id)


class AuditRecord(models.Model):
    """Section 14.1 Full Audit Record JSON Schema, and Section 10.3: "Every
    request generates a complete, immutable audit record containing: the full
    request, all pre-request analysis scores, the model routing decision and
    reason, all objective metrics, all 12 audit dimension scores and
    justifications, the policy rules evaluated, the final decision, and (where
    applicable) the human reviewer's decision and rationale." One record per
    Trace/request."""

    trace = models.OneToOneField(
        Trace, on_delete=models.CASCADE, primary_key=True, related_name="audit_record"
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    # Section 14.1 top-level fields: geography and regulation_versions actually
    # active for this specific request (Section 5.2: "The system logs which
    # regulation version was active for each decision — critical for
    # regulatory audits.")
    geography = models.JSONField(default=list, blank=True)
    regulation_versions = models.JSONField(default=dict, blank=True)

    # Section 3 Step 2 (2A/2B/2C/2D) pre-request analysis block.
    pre_request = models.JSONField(default=dict, blank=True)

    # Section 3 Step 3 model routing decision block.
    model_routing = models.JSONField(default=dict, blank=True)

    # Section 3 Step 5 objective metrics block.
    response_metrics = models.JSONField(default=dict, blank=True)

    # Section 4: the 12 audit dimensions, split into the two parallel tracks
    # defined in Section 2.2 Decision 2 (Quality / Safety+Policy).
    audit_quality = models.JSONField(default=dict, blank=True)
    audit_responsibility = models.JSONField(default=dict, blank=True)

    # Section 4.1 composite risk score — monitoring/trend only, never used for
    # policy decisions.
    composite_risk_score = models.FloatField(blank=True, null=True)
    auditor_model = models.CharField(max_length=100, blank=True)
    auditor_confidence = models.FloatField(blank=True, null=True)
    recommended_action = models.CharField(
        max_length=20, choices=DECISION_CHOICES, blank=True, null=True
    )

    # Section 3 Step 8 policy engine outcome.
    policy_profile_version = models.CharField(max_length=50, blank=True)
    policy_rules_evaluated = models.JSONField(default=list, blank=True)
    policy_rules_triggered = models.JSONField(default=list, blank=True)
    final_action = models.CharField(
        max_length=20, choices=DECISION_CHOICES, blank=True, null=True
    )

    # Section 14.1 session_state snapshot at the time of this request.
    session_state_snapshot = models.JSONField(default=dict, blank=True)

    # Section 3 Step 9: MODIFY / HUMAN_REVIEW outcome details; null when the
    # corresponding path was not taken for this request.
    modification = models.JSONField(blank=True, null=True)
    human_review = models.JSONField(blank=True, null=True)

    # Section 14.1: final content returned to the user (de-pseudonymised) plus
    # any disclosure notice.
    user_response = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"AuditRecord({self.trace_id})"
