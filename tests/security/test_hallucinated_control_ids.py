"""Offline security tests: hallucinated / unknown control IDs are rejected."""

from __future__ import annotations

import pytest

from grc_agent.controls.catalog import get_control_catalog
from grc_agent.controls.mapping import resolve_mapped_controls
from grc_agent.engine import RiskEngine
from grc_agent.orchestrator import RiskOrchestrator

from tests.security.helpers import CTRL_CLD_001, ForcedRetriever, SelectingAgent, control_hit

CATALOG = get_control_catalog()
HALLUCINATED = ["CTRL-999", "CTRL-1", "CTRL-AC-999", "CTRL-CLD-999", "CTRL-FAKE-001"]


@pytest.mark.parametrize("bad_id", HALLUCINATED)
def test_hallucinated_control_id_rejected_by_resolver(bad_id: str) -> None:
    """Offline: unknown IDs never appear in mapped_controls even if listed as candidates."""
    mapped = resolve_mapped_controls(
        [bad_id],
        candidate_control_ids={bad_id, CTRL_CLD_001},
        catalog=CATALOG,
    )
    assert mapped == []
    assert bad_id not in CATALOG


def test_hallucinated_ids_rejected_on_orchestrator_path() -> None:
    """Offline: complying agent returning invented IDs yields empty mapping."""
    result = RiskOrchestrator(
        SelectingAgent(HALLUCINATED),
        RiskEngine(),
        retriever=ForcedRetriever([control_hit(CTRL_CLD_001)]),
    ).assess("Public cloud bucket exposes confidential reports.")

    assert result.mapped_controls == []
    assert result.scored_risks[0].inherent_risk.risk_score == 20
