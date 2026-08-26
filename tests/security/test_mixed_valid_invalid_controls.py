"""Offline security tests: mixed valid + malicious control selections."""

from __future__ import annotations

from grc_agent.controls.catalog import get_control_catalog
from grc_agent.controls.mapping import resolve_mapped_controls
from grc_agent.engine import RiskEngine
from grc_agent.orchestrator import RiskOrchestrator

from tests.security.helpers import (
    CTRL_AC_001,
    CTRL_AC_001_NAME,
    CTRL_CLD_001,
    CTRL_CLD_001_NAME,
    ForcedRetriever,
    SelectingAgent,
    control_hit,
)

CATALOG = get_control_catalog()


def test_mixed_valid_and_malicious_ids_keep_only_valid_candidates() -> None:
    """Offline: only IDs that are both catalogued and retrieved survive."""
    mapped = resolve_mapped_controls(
        [CTRL_CLD_001, "CTRL-999", "CTRL-1", CTRL_AC_001, "CTRL-AC-999", "CTRL-HACK-001"],
        candidate_control_ids={CTRL_CLD_001, CTRL_AC_001},
        catalog=CATALOG,
    )
    assert [item.control_id for item in mapped] == [CTRL_CLD_001, CTRL_AC_001]
    assert [item.name for item in mapped] == [CTRL_CLD_001_NAME, CTRL_AC_001_NAME]


def test_orchestrator_mixed_selection_filters_malicious_ids() -> None:
    """Offline: orchestrator path drops unknown / non-candidate IDs."""
    result = RiskOrchestrator(
        SelectingAgent(
            [
                CTRL_CLD_001,
                "CTRL-999",
                "CTRL-1",
                CTRL_AC_001,  # catalog-valid but not retrieved → drop
                "CTRL-AC-999",
            ]
        ),
        RiskEngine(),
        retriever=ForcedRetriever([control_hit(CTRL_CLD_001)]),
    ).assess("Mixed mapping abuse scenario.")

    assert [item.control_id for item in result.mapped_controls] == [CTRL_CLD_001]
    assert result.mapped_controls[0].name == CTRL_CLD_001_NAME
    assert result.scored_risks[0].inherent_risk.risk_score == 20
