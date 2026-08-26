"""Scenario → RiskAgent → validate → RiskEngine.

The agent never receives a hook to set score or rating. This class always
calls ``RiskEngine.calculate_inherent_risk(likelihood, impact)``.
"""

from __future__ import annotations

import logging

from grc_agent.agents.base import RiskAgent
from grc_agent.agents.proposals import RiskProposal
from grc_agent.controls.catalog import extract_control_ids_from_text, get_control_catalog
from grc_agent.controls.mapping import resolve_mapped_controls
from grc_agent.engine.risk_engine import RiskEngine
from grc_agent.orchestrator.results import OrchestratedAssessment, ScoredRisk
from grc_agent.rag.retriever import Retriever, format_hits

logger = logging.getLogger(__name__)


def format_rag_debug_block(scenario: str, context: str, hit_count: int) -> str:
    """Render the exact RAG debug block written immediately before ``propose``."""
    return (
        "=== RAG DEBUG ===\n"
        "Scenario:\n"
        f"{scenario}\n"
        "\n"
        f"Retrieved hits: {hit_count}\n"
        "\n"
        "Retrieved context:\n"
        f"{context}\n"
        "\n"
        "=== END RAG DEBUG ==="
    )


class RiskOrchestrator:
    """Runs the Phase 3 pipeline with a injected ``RiskAgent`` (mock or later LLM)."""

    def __init__(
        self,
        agent: RiskAgent,
        risk_engine: RiskEngine | None = None,
        retriever: Retriever | None = None,
        rag_debug: bool = False,
    ) -> None:
        self._agent = agent
        self._risk_engine = risk_engine or RiskEngine()
        self._retriever = retriever
        self._rag_debug = rag_debug

    def assess(self, scenario: str) -> OrchestratedAssessment:
        text = scenario.strip()
        if not text:
            raise ValueError("scenario must not be empty")

        hits = []
        context = ""
        if self._retriever is not None:
            hits = self._retriever.retrieve(text)
            context = format_hits(hits)
        if self._rag_debug and self._retriever is not None:
            block = format_rag_debug_block(text, context, len(hits))
            logger.info(block)
            # uvicorn's default config does not emit app INFO logs; print so the
            # same propose() context is visible in the process console.
            print(block, flush=True)
        raw = self._agent.propose(text, context=context)
        proposal = RiskProposal.model_validate(raw.model_dump())
        scored_risks = [
            ScoredRisk(
                proposal=risk,
                inherent_risk=self._risk_engine.calculate_inherent_risk(
                    risk.likelihood, risk.impact
                ),
            )
            for risk in proposal.risks
        ]
        # Assessment-level mapping: RAG candidates are scenario-scoped, so we
        # validate once rather than duplicating the same controls on every risk.
        candidate_ids = extract_control_ids_from_text(context) if context else []
        mapped_controls = resolve_mapped_controls(
            proposal.selected_control_ids,
            candidate_control_ids=candidate_ids,
            catalog=get_control_catalog() if candidate_ids else {},
        )
        return OrchestratedAssessment(
            scenario=text,
            proposal=proposal,
            scored_risks=scored_risks,
            mapped_controls=mapped_controls,
        )
