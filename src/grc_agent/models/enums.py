"""Enumerations for GRC domain values.

Enums keep later LLM output constrained to a known vocabulary. An agent may
propose a label; it cannot invent an arbitrary string that silently passes
into scoring or reporting.
"""

from enum import Enum


class AssetCriticality(str, Enum):
    """Business importance of an asset. Independent of risk score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    """High-level threat taxonomy for grouping (not used in arithmetic)."""

    MALWARE = "malware"
    PHISHING = "phishing"
    INSIDER = "insider"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "denial_of_service"
    DATA_DISCLOSURE = "data_disclosure"
    MISCONFIGURATION = "misconfiguration"
    SUPPLY_CHAIN = "supply_chain"
    PHYSICAL = "physical"
    OTHER = "other"


class VulnerabilitySeverity(str, Enum):
    """Qualitative severity of a weakness. Independent of risk score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ControlEffectiveness(str, Enum):
    """How well a control is believed to operate. Residual risk is later."""

    INEFFECTIVE = "ineffective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    EFFECTIVE = "effective"
    HIGHLY_EFFECTIVE = "highly_effective"


class RiskRating(str, Enum):
    """Qualitative band derived only from the deterministic risk matrix."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskTreatment(str, Enum):
    """ISO 31000-style treatment options. Selection is not a score."""

    MITIGATE = "mitigate"
    ACCEPT = "accept"
    TRANSFER = "transfer"
    AVOID = "avoid"
