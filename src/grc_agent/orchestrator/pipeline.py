"""Scenario → RiskAgent → validate → RiskEngine.

The agent never receives a hook to set score or rating. This class always
calls ``RiskEngine.calculate_inherent_risk(likelihood, impact)``.

Security/audit observability is additive and must not change scoring,
retrieval ranking, or control-mapping acceptance rules.
"""

from __future__ import annotations

import logging

from grc_agent.agents.base import RiskAgent
from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.agents.proposals import RiskProposal
from grc_agent.controls.catalog import extract_control_ids_from_text, get_control_catalog
from grc_agent.controls.mapping import resolve_mapped_controls
from grc_agent.engine.risk_engine import RiskEngine
from grc_agent.observability import audit
from grc_agent.observability.context import ensure_correlation_id
from grc_agent.observability.metrics import (
    ASSESSMENTS_FAILED_TOTAL,
    ASSESSMENTS_TOTAL,
    INVALID_CONTROL_IDS_TOTAL,
    LLM_FAILURES_TOTAL,
    MAPPED_CONTROLS_TOTAL,
    RAG_RETRIEVALS_TOTAL,
    get_metrics,
)
from grc_agent.orchestrator.results import OrchestratedAssessment, ScoredRisk
from grc_agent.rag.retriever import DEFAULT_TOP_K, Retriever, format_hits

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


def _agent_kind(agent: RiskAgent) -> str:
    name = type(agent).__name__
    if name == "OllamaRiskAgent":
        return "ollama"
    if name == "MockRiskAgent":
        return "mock"
    return name


def _agent_model(agent: RiskAgent) -> str | None:
    if isinstance(agent, OllamaRiskAgent):
        client = getattr(agent, "_client", None)
        model = getattr(client, "model", None)
        return str(model) if model else None
    return None


def _rejection_reason(
    control_id: str,
    *,
    candidates: set[str],
    catalog_ids: set[str],
) -> str:
    """Classify why a selected ID did not become a mapped control."""
    if control_id not in candidates:
        return "not_in_rag_candidates"
    if control_id not in catalog_ids:
        return "not_in_catalog"
    return "rejected"


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

        correlation_id = ensure_correlation_id()
        metrics = get_metrics()
        metrics.incr(ASSESSMENTS_TOTAL)
        fingerprint = audit.scenario_fingerprint(text)
        audit.emit_audit_event(
            audit.ASSESSMENT_STARTED,
            scenario_length=len(text),
            scenario_fingerprint=fingerprint,
            agent_kind=_agent_kind(self._agent),
            rag_enabled=self._retriever is not None,
        )

        try:
            return self._assess_with_audit(text, fingerprint=fingerprint)
        except Exception as exc:
            metrics.incr(ASSESSMENTS_FAILED_TOTAL)
            audit.emit_audit_event(
                audit.ASSESSMENT_FAILED,
                error_type=type(exc).__name__,
                scenario_fingerprint=fingerprint,
            )
            raise

    def _assess_with_audit(self, text: str, *, fingerprint: str) -> OrchestratedAssessment:
        metrics = get_metrics()
        hits = []
        context = ""
        if self._retriever is not None:
            hits = self._retriever.retrieve(text)
            context = format_hits(hits)
            metrics.incr(RAG_RETRIEVALS_TOTAL)
            candidate_preview = extract_control_ids_from_text(context)
            audit.emit_audit_event(
                audit.RAG_RETRIEVAL_COMPLETED,
                hit_count=len(hits),
                chunk_ids=[hit.chunk.id for hit in hits],
                retrieved_control_ids=candidate_preview,
                top_k=DEFAULT_TOP_K,
                control_candidate_found=bool(candidate_preview),
                scenario_fingerprint=fingerprint,
            )
        if self._rag_debug and self._retriever is not None:
            block = format_rag_debug_block(text, context, len(hits))
            logger.info(block)
            # uvicorn's default config does not emit app INFO logs; print so the
            # same propose() context is visible in the process console.
            print(block, flush=True)

        try:
            raw = self._agent.propose(text, context=context)
        except Exception:
            if isinstance(self._agent, OllamaRiskAgent):
                metrics.incr(LLM_FAILURES_TOTAL)
            raise

        proposal = RiskProposal.model_validate(raw.model_dump())
        audit.emit_audit_event(
            audit.LLM_PROPOSAL_GENERATED,
            success=True,
            agent_kind=_agent_kind(self._agent),
            llm_model=_agent_model(self._agent),
            selected_control_id_count=len(proposal.selected_control_ids),
            risk_proposal_count=len(proposal.risks),
            scenario_fingerprint=fingerprint,
        )

        scored_risks = [
            ScoredRisk(
                proposal=risk,
                inherent_risk=self._risk_engine.calculate_inherent_risk(
                    risk.likelihood, risk.impact
                ),
            )
            for risk in proposal.risks
        ]
        primary_score = scored_risks[0].inherent_risk.risk_score if scored_risks else None
        primary_rating = (
            scored_risks[0].inherent_risk.risk_rating.value if scored_risks else None
        )
        audit.emit_audit_event(
            audit.RISK_SCORED,
            scored_risk_count=len(scored_risks),
            risk_score=primary_score,
            risk_rating=primary_rating,
            score_source="RiskEngine",
            scenario_fingerprint=fingerprint,
        )

        # Assessment-level mapping: RAG candidates are scenario-scoped, so we
        # validate once rather than duplicating the same controls on every risk.
        candidate_ids = extract_control_ids_from_text(context) if context else []
        catalog = get_control_catalog() if candidate_ids else {}
        mapped_controls = resolve_mapped_controls(
            proposal.selected_control_ids,
            candidate_control_ids=candidate_ids,
            catalog=catalog,
        )

        candidate_set = set(candidate_ids)
        catalog_ids = set(catalog)
        mapped_ids = {item.control_id for item in mapped_controls}
        seen_selected: set[str] = set()
        rejected_count = 0
        for raw_id in proposal.selected_control_ids:
            control_id = raw_id.strip()
            if not control_id or control_id in seen_selected:
                continue
            seen_selected.add(control_id)
            if control_id in mapped_ids:
                continue
            reason = _rejection_reason(
                control_id, candidates=candidate_set, catalog_ids=catalog_ids
            )
            rejected_count += 1
            metrics.incr(INVALID_CONTROL_IDS_TOTAL)
            audit.emit_audit_event(
                audit.INVALID_CONTROL_ID_REJECTED,
                control_id=control_id,
                reason=reason,
                scenario_fingerprint=fingerprint,
            )

        metrics.incr(MAPPED_CONTROLS_TOTAL, len(mapped_controls))
        audit.emit_audit_event(
            audit.CONTROL_MAPPING_COMPLETED,
            selected_control_id_count=len(proposal.selected_control_ids),
            candidate_control_id_count=len(candidate_ids),
            mapped_control_count=len(mapped_controls),
            rejected_control_id_count=rejected_count,
            mapped_control_ids=[item.control_id for item in mapped_controls],
            scenario_fingerprint=fingerprint,
        )

        result = OrchestratedAssessment(
            scenario=text,
            proposal=proposal,
            scored_risks=scored_risks,
            mapped_controls=mapped_controls,
        )
        audit.emit_audit_event(
            audit.ASSESSMENT_COMPLETED,
            scored_risk_count=len(scored_risks),
            risk_score=primary_score,
            risk_rating=primary_rating,
            mapped_control_count=len(mapped_controls),
            scenario_fingerprint=fingerprint,
        )
        return result
