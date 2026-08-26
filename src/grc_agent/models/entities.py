"""Pydantic domain models for a GRC assessment.

Design decisions:

- Extra fields are forbidden so unexpected LLM JSON keys fail closed.
- Likelihood and impact live on ``Risk`` as *inputs*. Score and rating are
  not writable on ``Risk``; they exist only on ``InherentRisk``, which
  re-validates arithmetic against the Python matrix.
- Identifiers are strings so later persistence (SQLite) can store UUIDs
  without coupling models to a database layer.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from grc_agent.engine.matrix import calculate_rating, calculate_score, validate_scale
from grc_agent.models.enums import (
    AssetCriticality,
    ControlEffectiveness,
    RiskRating,
    RiskTreatment,
    ThreatCategory,
    VulnerabilitySeverity,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class _LikelihoodImpactMixin:
    """Reject bool before Pydantic coerces True→1 / False→0."""

    @field_validator("likelihood", "impact", mode="before")
    @classmethod
    def reject_boolean_scale(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("likelihood and impact must be integers 1–5, not booleans")
        return value


class Asset(_StrictModel):
    """Something of value to the organization (system, data, process, people)."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    criticality: AssetCriticality


class Threat(_StrictModel):
    """A potential cause of an unwanted incident."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    category: ThreatCategory
    asset_ids: list[str] = Field(
        default_factory=list,
        description=(
            "IDs of assets in the same proposal that this threat targets. "
            "Each value must equal an assets[].id. Do not leave empty in a RiskProposal."
        ),
    )


class Vulnerability(_StrictModel):
    """A weakness that a threat could exploit."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    severity: VulnerabilitySeverity
    asset_ids: list[str] = Field(
        default_factory=list,
        description=(
            "IDs of assets in the same proposal that this weakness affects. "
            "Each value must equal an assets[].id. Do not leave empty in a RiskProposal."
        ),
    )


class Control(_StrictModel):
    """A safeguard that reduces likelihood or impact. Not scored here."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    effectiveness: ControlEffectiveness


class InherentRisk(_LikelihoodImpactMixin, _StrictModel):
    """Engine output: score and rating must match likelihood × impact.

    Construct this via ``RiskEngine.calculate_inherent_risk``. Direct
    construction is allowed only when fields are internally consistent,
    so a fabricated ``risk_score`` cannot survive validation.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)

    likelihood: int
    impact: int
    risk_score: int
    risk_rating: RiskRating

    @model_validator(mode="after")
    def score_and_rating_must_match_matrix(self) -> InherentRisk:
        likelihood = validate_scale("likelihood", self.likelihood)
        impact = validate_scale("impact", self.impact)
        expected_score = calculate_score(likelihood, impact)
        expected_rating = RiskRating(calculate_rating(expected_score))
        if self.risk_score != expected_score:
            raise ValueError(
                f"risk_score {self.risk_score} does not match "
                f"likelihood × impact ({expected_score}); "
                "scores are assigned only by the Python risk engine"
            )
        if self.risk_rating != expected_rating:
            raise ValueError(
                f"risk_rating {self.risk_rating} does not match matrix "
                f"rating {expected_rating} for score {expected_score}"
            )
        return self


class Risk(_LikelihoodImpactMixin, _StrictModel):
    """A risk scenario with likelihood and impact inputs (scale 1–5).

    ``risk_score`` and ``risk_rating`` are intentionally absent. Call
    ``RiskEngine.calculate_inherent_risk(likelihood, impact)`` instead.
    """

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = ""
    likelihood: int
    impact: int
    asset_ids: list[str] = Field(default_factory=list)
    threat_ids: list[str] = Field(default_factory=list)
    vulnerability_ids: list[str] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)
    treatment: RiskTreatment | None = None

    @model_validator(mode="after")
    def likelihood_and_impact_on_scale(self) -> Risk:
        validate_scale("likelihood", self.likelihood)
        validate_scale("impact", self.impact)
        return self


class GRCAssessment(_StrictModel):
    """A single assessment: scenario plus structured GRC entities."""

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    scenario: str = Field(min_length=1)
    environment_notes: str = ""
    assets: list[Asset] = Field(default_factory=list)
    threats: list[Threat] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    controls: list[Control] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list)
