"""Offline security tests: catalog controls must also be RAG candidates."""

from __future__ import annotations

from grc_agent.controls.catalog import get_control_catalog
from grc_agent.controls.mapping import resolve_mapped_controls
from grc_agent.engine import RiskEngine
from grc_agent.orchestrator import RiskOrchestrator

from tests.security.helpers import (
    CTRL_AC_001,
    CTRL_CLD_001,
    ForcedRetriever,
    SelectingAgent,
    control_hit,
)

CATALOG = get_control_catalog()


def test_catalog_control_absent_from_rag_candidates_is_rejected() -> None:
    """Offline: valid catalog ID not present in retrieved candidates is dropped."""
    assert CTRL_AC_001 in CATALOG
    mapped = resolve_mapped_controls(
        [CTRL_AC_001],
        candidate_control_ids={CTRL_CLD_001},
        catalog=CATALOG,
    )
    assert mapped == []


def test_orchestrator_rejects_catalog_id_not_in_retrieved_hits() -> None:
    """Offline: agent selects CTRL-AC-001 but RAG only returned CTRL-CLD-001."""
    result = RiskOrchestrator(
        SelectingAgent([CTRL_AC_001]),
        RiskEngine(),
        retriever=ForcedRetriever([control_hit(CTRL_CLD_001)]),
    ).assess("Least privilege scenario for a cloud administrator.")

    assert result.mapped_controls == []
    assert CTRL_AC_001 in CATALOG
    assert result.scored_risks[0].inherent_risk.risk_score == 20
