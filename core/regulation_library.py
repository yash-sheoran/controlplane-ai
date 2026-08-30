"""Section 8 — Regulatory & Geography-Aware Compliance Module.

Regulations are modelled as versioned YAML rule sets stored separately
from application code (Section 8.1), loaded from a fixed `regulations`
list (Section 5.2's geography-aware rule injection — geography determines
*which* regulations apply operationally, but this project passes the
resolved `regulations` list directly rather than re-deriving it from
geography codes, since the doc names specific regulations per geography
example rather than a formal geography-to-regulation mapping table).
"""

from pathlib import Path

import yaml

_REGULATIONS_DIR = Path(__file__).resolve().parent / "config" / "regulations"


def load_regulation(regulation_id):
    """Reads a single regulation's YAML file fresh on every call — Section
    5's callout: "Regulation rules are stored as versioned YAML files and
    can be updated without a code deployment." """
    path = _REGULATIONS_DIR / f"{regulation_id}.yaml"
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def apply_regulations(regulation_ids):
    """Loads and aggregates every regulation named in regulation_ids.

    Returns:
      regulation_versions: {regulation_id: version, ...} — "The system
        logs which regulation version was active for each decision —
        critical for regulatory audits" (Section 5.2 callout).
      regulations_applied: {regulation_id: full rule set dict, ...}
      requires_pii_pseudonymisation: bool — true if ANY applicable
        regulation requires it (Section 8.1: "PII categories that
        trigger mandatory pseudonymisation in this jurisdiction").
      data_residency_required: bool — Section 8.1: "Data residency
        requirements (flag if data must not leave a geographic region)."
      breach_notification_hours: the strictest (minimum) notification
        window among applicable regulations that specify one, else None.
    """
    regulations_applied = {reg_id: load_regulation(reg_id) for reg_id in (regulation_ids or [])}

    notification_windows = [
        reg["breach_notification_hours"]
        for reg in regulations_applied.values()
        if reg.get("breach_notification_hours") is not None
    ]

    return {
        "regulation_versions": {
            reg_id: reg["version"] for reg_id, reg in regulations_applied.items()
        },
        "regulations_applied": regulations_applied,
        "requires_pii_pseudonymisation": any(
            reg.get("requires_pii_pseudonymisation") for reg in regulations_applied.values()
        ),
        "data_residency_required": any(
            reg.get("data_residency_required") for reg in regulations_applied.values()
        ),
        "breach_notification_hours": min(notification_windows) if notification_windows else None,
    }


def build_compliance_metadata(regulation_ids, eu_ai_act_high_risk, base_audit_retention_days):
    """Section 8.2 — AI Act High-Risk Classification: use-cases flagged
    high-risk receive "Conformity logging with structured metadata",
    "Auditability flag that extends the log retention period to the
    regulatory minimum" (Section 10.3: up to 7 years), and (structurally,
    per Section 3 Step 9's own design) mandatory human oversight on
    HUMAN_REVIEW decisions — already true of every HUMAN_REVIEW case in
    this project, since core.decision_executor.apply_prompt_review_
    decision always requires a human reviewer_id; there is no
    auto-approve path for it to be disabled for.

    `eu_ai_act_high_risk` is a fixed configuration flag (core.pipeline's
    _FIXED_EU_AI_ACT_HIGH_RISK) — the document references "EU AI Act
    Annex III high-risk categories" without enumerating them or giving a
    concrete classification rule, so classification is an explicit
    configuration decision an operator makes, not something this system
    infers.
    """
    regulation_result = apply_regulations(regulation_ids)

    effective_audit_retention_days = base_audit_retention_days
    if eu_ai_act_high_risk:
        # The eu_ai_act_high_risk flag governs its own consequence
        # directly, from the EU_AI_Act regulation file's own retention
        # parameter — it does not additionally require "EU_AI_Act" to be
        # listed in this use case's `regulations` (that list drives the
        # other, unrelated regulations' rules, e.g. GDPR pseudonymisation).
        eu_ai_act = regulation_result["regulations_applied"].get("EU_AI_Act") or load_regulation("EU_AI_Act")
        high_risk_retention = eu_ai_act.get("high_risk_audit_retention_days")
        if high_risk_retention:
            effective_audit_retention_days = max(base_audit_retention_days, high_risk_retention)

    conformity_log = None
    if eu_ai_act_high_risk:
        conformity_log = {
            "classification": "high_risk",
            "human_oversight_mandatory_for_human_review": True,
            "bias_monitoring_required": True,
        }

    return {
        "regulation_versions": regulation_result["regulation_versions"],
        "requires_pii_pseudonymisation": regulation_result["requires_pii_pseudonymisation"],
        "data_residency_required": regulation_result["data_residency_required"],
        "breach_notification_hours": regulation_result["breach_notification_hours"],
        "eu_ai_act_high_risk": eu_ai_act_high_risk,
        "effective_audit_retention_days": effective_audit_retention_days,
        "conformity_log": conformity_log,
    }
