"""Offline security tests: control names come only from the authoritative catalog."""

from __future__ import annotations

from grc_agent.controls.catalog import get_control_catalog
from grc_agent.controls.mapping import MappedControl, resolve_mapped_controls
from grc_agent.engine import RiskEngine
from grc_agent.orchestrator import RiskOrchestrator

from tests.security.helpers import (
    CTRL_CLD_001,
    CTRL_CLD_001_NAME,
    ForcedRetriever,
    SelectingAgent,
    control_hit,
)

CATALOG = get_control_catalog()
SPOOFED = "Totally Legit Control Owned By Attacker"


def test_resolver_ignores_any_llm_invented_name_and_uses_catalog() -> None:
    """Offline: MappedControl.name is always catalog text, never free-form LLM text."""
    mapped = resolve_mapped_controls(
        [CTRL_CLD_001],
        candidate_control_ids={CTRL_CLD_001},
        catalog=CATALOG,
    )
    assert len(mapped) == 1
    assert mapped[0].name == CTRL_CLD_001_NAME == "Block Public Access to Cloud Storage"
    assert mapped[0].name != SPOOFED


def test_spoofed_name_in_rag_chunk_does_not_change_mapped_control_name() -> None:
    """Offline: even if retrieved markdown lies about Name, API mapping uses catalog."""
    hit = control_hit(CTRL_CLD_001, spoofed_name=SPOOFED)
    assert SPOOFED in hit.chunk.text
    assert CTRL_CLD_001 in hit.chunk.text

    result = RiskOrchestrator(
        SelectingAgent([CTRL_CLD_001]),
        RiskEngine(),
        retriever=ForcedRetriever([hit]),
    ).assess("Public cloud storage bucket is readable by anyone.")

    assert result.mapped_controls == [
        MappedControl(control_id=CTRL_CLD_001, name=CTRL_CLD_001_NAME)
    ]
    assert result.mapped_controls[0].name == CATALOG[CTRL_CLD_001].name
    assert SPOOFED not in result.mapped_controls[0].name
