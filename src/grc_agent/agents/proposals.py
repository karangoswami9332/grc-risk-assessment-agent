"""Structured Risk Agent output. Score and rating are forbidden here.

The agent may propose likelihood and impact. ``RiskEngine`` is the only
component allowed to compute ``risk_score`` and ``risk_rating``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from grc_agent.engine.matrix import validate_scale
from grc_agent.models.entities import Asset, Threat, Vulnerability
from grc_agent.models.enums import RiskTreatment


class _ProposalModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ProposedRisk(_ProposalModel):
    """A candidate risk. Contains inputs and rationale, never a final score."""

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = ""
    likelihood: int
    impact: int
    rationale: str = Field(min_length=1)
    asset_ids: list[str] = Field(
        min_length=1,
        description="assets[].id values from this proposal that are in scope for this risk.",
    )
    threat_ids: list[str] = Field(
        min_length=1,
        description="threats[].id values from this proposal that could cause this risk.",
    )
    vulnerability_ids: list[str] = Field(
        min_length=1,
        description="vulnerabilities[].id values from this proposal that could be exploited.",
    )
    treatment: RiskTreatment | None = None

    @field_validator("likelihood", "impact", mode="before")
    @classmethod
    def reject_boolean_scale(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("likelihood and impact must be integers 1–5, not booleans")
        return value

    @model_validator(mode="after")
    def likelihood_and_impact_on_scale(self) -> ProposedRisk:
        validate_scale("likelihood", self.likelihood)
        validate_scale("impact", self.impact)
        return self


class RiskProposal(_ProposalModel):
    """Validated agent output for one scenario. No scoring fields."""

    assets: list[Asset] = Field(default_factory=list)
    threats: list[Threat] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    risks: list[ProposedRisk] = Field(default_factory=list)
    selected_control_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Advisory control IDs selected from retrieved GRC context only "
            "(for example CTRL-CLD-001). Do not invent IDs. Empty if none apply."
        ),
    )

    @model_validator(mode="after")
    def relationship_ids_must_exist_in_this_proposal(self) -> RiskProposal:
        asset_ids = {item.id for item in self.assets}
        threat_ids = {item.id for item in self.threats}
        vulnerability_ids = {item.id for item in self.vulnerabilities}
        if len(asset_ids) != len(self.assets):
            raise ValueError("asset ids must be unique")
        if len(threat_ids) != len(self.threats):
            raise ValueError("threat ids must be unique")
        if len(vulnerability_ids) != len(self.vulnerabilities):
            raise ValueError("vulnerability ids must be unique")

        def require_known(kind: str, entity_id: str, field: str, refs: list[str], known: set[str]) -> None:
            if not refs:
                raise ValueError(
                    f"{kind} {entity_id!r} must set {field} to ids defined in this proposal"
                )
            unknown = sorted({ref for ref in refs if ref not in known})
            if unknown:
                raise ValueError(
                    f"{kind} {entity_id!r} {field} contains unknown ids {unknown}; "
                    "use only ids defined in this proposal"
                )

        for threat in self.threats:
            require_known("threat", threat.id, "asset_ids", threat.asset_ids, asset_ids)
        for vulnerability in self.vulnerabilities:
            require_known(
                "vulnerability",
                vulnerability.id,
                "asset_ids",
                vulnerability.asset_ids,
                asset_ids,
            )
        for risk in self.risks:
            require_known("risk", risk.id, "asset_ids", risk.asset_ids, asset_ids)
            require_known("risk", risk.id, "threat_ids", risk.threat_ids, threat_ids)
            require_known(
                "risk",
                risk.id,
                "vulnerability_ids",
                risk.vulnerability_ids,
                vulnerability_ids,
            )
        return self
