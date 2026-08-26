"""Harden coverage of control-mapping validation rules (deterministic, no live Ollama)."""

from __future__ import annotations

from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.agents.proposals import RiskProposal
from grc_agent.controls.catalog import get_control_catalog
from grc_agent.controls.mapping import MappedControl, resolve_mapped_controls
from grc_agent.engine import RiskEngine
from grc_agent.models.enums import RiskRating
from grc_agent.orchestrator import RiskOrchestrator
from grc_agent.rag.types import Chunk, RetrievalHit

CATALOG = get_control_catalog()
CANDIDATES = {"CTRL-CLD-001", "CTRL-CLD-002", "CTRL-CLD-003"}


def test_rule_a_valid_retrieved_control_accepted() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-001"],
        candidate_control_ids=CANDIDATES,
        catalog=CATALOG,
    )
    assert mapped == [
        MappedControl(
            control_id="CTRL-CLD-001",
            name="Block Public Access to Cloud Storage",
        )
    ]


def test_rule_b_unknown_id_rejected() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-999"],
        candidate_control_ids={"CTRL-CLD-001", "CTRL-CLD-999"},
        catalog=CATALOG,
    )
    assert mapped == []


def test_rule_c_catalog_id_not_retrieved_rejected() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-002"],
        candidate_control_ids={"CTRL-CLD-001"},
        catalog=CATALOG,
    )
    assert mapped == []
    assert "CTRL-CLD-002" in CATALOG


def test_rule_d_multiple_valid_controls_accepted() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-001", "CTRL-CLD-002"],
        candidate_control_ids=CANDIDATES,
        catalog=CATALOG,
    )
    assert mapped == [
        MappedControl(
            control_id="CTRL-CLD-001",
            name="Block Public Access to Cloud Storage",
        ),
        MappedControl(
            control_id="CTRL-CLD-002",
            name="Review Cloud IAM Configurations",
        ),
    ]


def test_rule_e_mixed_valid_invalid_drops_invalid() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-001", "CTRL-CLD-999", "CTRL-CLD-002"],
        candidate_control_ids=CANDIDATES,
        catalog=CATALOG,
    )
    assert [item.control_id for item in mapped] == ["CTRL-CLD-001", "CTRL-CLD-002"]
    assert all(item.control_id != "CTRL-CLD-999" for item in mapped)
    assert mapped[0].name == CATALOG["CTRL-CLD-001"].name
    assert mapped[1].name == CATALOG["CTRL-CLD-002"].name


def test_rule_f_empty_selection_empty_mapping() -> None:
    assert (
        resolve_mapped_controls(
            [],
            candidate_control_ids=CANDIDATES,
            catalog=CATALOG,
        )
        == []
    )


def test_rule_g_no_retrieved_candidates_empty_mapping() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-001", "CTRL-AC-001"],
        candidate_control_ids=[],
        catalog=CATALOG,
    )
    assert mapped == []


class _SelectingAgent(MockRiskAgent):
    """Mock agent that also emits selected_control_ids (for orchestrator validation)."""

    def __init__(self, selected_control_ids: list[str]) -> None:
        self._selected = selected_control_ids

    def propose(self, scenario: str, context: str = "") -> RiskProposal:
        base = super().propose(scenario, context=context)
        return base.model_copy(update={"selected_control_ids": list(self._selected)})


class _ForcedRetriever:
    def __init__(self, hits: list[RetrievalHit]) -> None:
        self._hits = hits

    def retrieve(self, query: str, top_k: int = 3) -> list[RetrievalHit]:
        return list(self._hits)


def test_orchestrator_no_candidates_keeps_empty_mapping_and_score() -> None:
    agent = _SelectingAgent(["CTRL-CLD-001"])
    result = RiskOrchestrator(agent, RiskEngine(), retriever=None).assess(
        "A public cloud bucket exposes confidential reports."
    )
    assert result.mapped_controls == []
    assert result.scored_risks[0].inherent_risk.risk_score == 20
    assert result.scored_risks[0].inherent_risk.risk_rating == RiskRating.CRITICAL


def test_orchestrator_mapping_does_not_change_scoring() -> None:
    hits = [
        RetrievalHit(
            chunk=Chunk(
                id="controls.md:5",
                text=(
                    "## CTRL-CLD-001 — Block Public Access to Cloud Storage\n"
                    "**Control ID:** CTRL-CLD-001\n"
                    "**Name:** Block Public Access to Cloud Storage\n"
                ),
                source="controls.md",
            ),
            score=0.9,
        )
    ]
    without = RiskOrchestrator(MockRiskAgent(), RiskEngine(), retriever=_ForcedRetriever(hits)).assess(
        "Public bucket."
    )
    with_map = RiskOrchestrator(
        _SelectingAgent(["CTRL-CLD-001"]),
        RiskEngine(),
        retriever=_ForcedRetriever(hits),
    ).assess("Public bucket.")
    assert with_map.mapped_controls == [
        MappedControl(
            control_id="CTRL-CLD-001",
            name="Block Public Access to Cloud Storage",
        )
    ]
    assert (
        without.scored_risks[0].inherent_risk.risk_score
        == with_map.scored_risks[0].inherent_risk.risk_score
        == 20
    )
    assert (
        without.scored_risks[0].inherent_risk.risk_rating
        == with_map.scored_risks[0].inherent_risk.risk_rating
    )
    assert without.proposal.risks[0].likelihood == with_map.proposal.risks[0].likelihood
    assert without.proposal.risks[0].impact == with_map.proposal.risks[0].impact
    assert without.proposal.risks[0].rationale == with_map.proposal.risks[0].rationale


def test_orchestrator_rejects_catalog_control_absent_from_rag_hits() -> None:
    hits = [
        RetrievalHit(
            chunk=Chunk(
                id="controls.md:5",
                text="**Control ID:** CTRL-CLD-001\n**Name:** Block Public Access",
                source="controls.md",
            ),
            score=0.9,
        )
    ]
    result = RiskOrchestrator(
        _SelectingAgent(["CTRL-CLD-002"]),
        RiskEngine(),
        retriever=_ForcedRetriever(hits),
    ).assess("Public bucket.")
    assert result.mapped_controls == []
    assert result.scored_risks[0].inherent_risk.risk_score == 20
