"""Orchestrator outputs: proposal plus engine-scored inherent risk."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from grc_agent.agents.proposals import ProposedRisk, RiskProposal
from grc_agent.controls.mapping import MappedControl
from grc_agent.models.entities import InherentRisk


class _ResultModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScoredRisk(_ResultModel):
    """One proposed risk paired with ``RiskEngine`` output (never agent output)."""

    proposal: ProposedRisk
    inherent_risk: InherentRisk


class OrchestratedAssessment(_ResultModel):
    """Result of scenario → RiskAgent → validate → RiskEngine (+ optional control mapping)."""

    scenario: str = Field(min_length=1)
    proposal: RiskProposal
    scored_risks: list[ScoredRisk]
    mapped_controls: list[MappedControl] = Field(default_factory=list)
