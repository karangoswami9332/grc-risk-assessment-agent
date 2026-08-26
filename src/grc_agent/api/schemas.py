"""HTTP request/response models. Score and rating are output-only."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from grc_agent.agents.proposals import RiskProposal
from grc_agent.engine.matrix import validate_scale
from grc_agent.models.enums import (
    AssetCriticality,
    ControlEffectiveness,
    RiskRating,
    RiskTreatment,
    ThreatCategory,
    VulnerabilitySeverity,
)


class _ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class _ScaleMixin:
    @field_validator("likelihood", "impact", mode="before")
    @classmethod
    def reject_boolean_scale(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("likelihood and impact must be integers 1–5, not booleans")
        return value


class AssetCreate(_ApiModel):
    id: str | None = None
    name: str = Field(min_length=1)
    description: str = ""
    criticality: AssetCriticality


class AssetRead(_ApiModel):
    id: str
    name: str
    description: str
    criticality: AssetCriticality


class ThreatCreate(_ApiModel):
    id: str | None = None
    name: str = Field(min_length=1)
    description: str = ""
    category: ThreatCategory
    asset_ids: list[str] = Field(default_factory=list)


class ThreatRead(_ApiModel):
    id: str
    name: str
    description: str
    category: ThreatCategory
    asset_ids: list[str]


class VulnerabilityCreate(_ApiModel):
    id: str | None = None
    name: str = Field(min_length=1)
    description: str = ""
    severity: VulnerabilitySeverity
    asset_ids: list[str] = Field(default_factory=list)


class VulnerabilityRead(_ApiModel):
    id: str
    name: str
    description: str
    severity: VulnerabilitySeverity
    asset_ids: list[str]


class ControlCreate(_ApiModel):
    id: str | None = None
    name: str = Field(min_length=1)
    description: str = ""
    effectiveness: ControlEffectiveness


class ControlRead(_ApiModel):
    id: str
    name: str
    description: str
    effectiveness: ControlEffectiveness


class RiskCreate(_ScaleMixin, _ApiModel):
    """Caller supplies likelihood and impact only. Score/rating are forbidden."""

    id: str | None = None
    title: str = Field(min_length=1)
    description: str = ""
    likelihood: int
    impact: int
    asset_ids: list[str] = Field(default_factory=list)
    threat_ids: list[str] = Field(default_factory=list)
    vulnerability_ids: list[str] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)
    treatment: RiskTreatment | None = None

    @field_validator("likelihood", "impact", mode="after")
    @classmethod
    def on_scale(cls, value: int) -> int:
        return validate_scale("value", value)


class RiskRead(_ApiModel):
    id: str
    title: str
    description: str
    likelihood: int
    impact: int
    risk_score: int
    risk_rating: RiskRating
    asset_ids: list[str]
    threat_ids: list[str]
    vulnerability_ids: list[str]
    control_ids: list[str]
    treatment: RiskTreatment | None = None


class AssessmentCreate(_ApiModel):
    title: str = Field(min_length=1)
    scenario: str = Field(min_length=1)
    environment_notes: str = ""
    assets: list[AssetCreate] = Field(default_factory=list)
    threats: list[ThreatCreate] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityCreate] = Field(default_factory=list)
    controls: list[ControlCreate] = Field(default_factory=list)
    risks: list[RiskCreate] = Field(default_factory=list)


class AssessmentSummary(_ApiModel):
    id: str
    title: str
    scenario: str
    tenant_id: str = "local"


class AssessmentRead(_ApiModel):
    id: str
    title: str
    scenario: str
    environment_notes: str
    tenant_id: str = "local"
    owner_subject: str = "local"
    assets: list[AssetRead]
    threats: list[ThreatRead]
    vulnerabilities: list[VulnerabilityRead]
    controls: list[ControlRead]
    risks: list[RiskRead]


class AssessmentList(_ApiModel):
    items: list[AssessmentSummary]


class RiskAssessmentRequest(_ApiModel):
    """Free-text scenario for the Phase 3 orchestrator. Score fields are forbidden."""

    scenario: str = Field(min_length=1)


class OrchestratedRiskRead(_ApiModel):
    """One risk after RiskEngine scoring. Score/rating are engine output only."""

    id: str
    title: str
    description: str
    likelihood: int
    impact: int
    rationale: str
    risk_score: int
    risk_rating: RiskRating
    asset_ids: list[str]
    threat_ids: list[str]
    vulnerability_ids: list[str]


class MappedControlRead(_ApiModel):
    """Authoritative control mapping after catalog validation (not LLM-invented)."""

    control_id: str
    name: str


class RiskAssessmentResponse(_ApiModel):
    scenario: str
    proposal: RiskProposal
    scored_risks: list[OrchestratedRiskRead]
    risk_score: int
    risk_rating: RiskRating
    rationale: str
    mapped_controls: list[MappedControlRead] = Field(default_factory=list)
