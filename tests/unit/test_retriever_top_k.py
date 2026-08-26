"""Production Retriever default top_k (orchestrator does not override)."""

from __future__ import annotations

import inspect

from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.config import Settings
from grc_agent.orchestrator import RiskOrchestrator
from grc_agent.rag.debug_retrieve import parse_args as parse_file_debug_args
from grc_agent.rag.debug_retrieve_knowledge import parse_args as parse_knowledge_debug_args
from grc_agent.rag.embeddings import FakeEmbedder
from grc_agent.rag.retriever import DEFAULT_TOP_K, Retriever, format_hits
from grc_agent.rag.types import Chunk
from grc_agent.rag.wiring import build_startup_retriever

CLOUD_SCENARIO = (
    "A cloud storage bucket containing confidential financial reports is publicly "
    "accessible because of an incorrect access control configuration."
)


def test_production_default_top_k_is_five() -> None:
    assert DEFAULT_TOP_K == 5
    assert inspect.signature(Retriever.retrieve).parameters["top_k"].default == DEFAULT_TOP_K


def test_retrieve_without_override_returns_up_to_five_hits() -> None:
    retriever = Retriever(FakeEmbedder())
    retriever.add_chunks(
        [
            Chunk(
                id=f"c{index}",
                text=f"least privilege access control policy chunk {index}",
                source="note.md",
            )
            for index in range(8)
        ]
    )
    hits = retriever.retrieve("least privilege access")
    assert len(hits) == DEFAULT_TOP_K
    rendered = format_hits(hits)
    for rank in range(1, DEFAULT_TOP_K + 1):
        assert f"[{rank}] source=note.md" in rendered
    assert f"[{DEFAULT_TOP_K + 1}]" not in rendered


def test_orchestrator_retrieve_uses_default_top_k() -> None:
    settings = Settings(risk_agent="ollama", rag_enabled=True)
    retriever = build_startup_retriever(settings, embedder=FakeEmbedder())
    assert retriever is not None
    captured: list[tuple[tuple, dict]] = []
    original = retriever.retrieve

    def tracking(query: str, *args, **kwargs):
        captured.append((args, kwargs))
        return original(query, *args, **kwargs)

    retriever.retrieve = tracking  # type: ignore[method-assign]
    RiskOrchestrator(MockRiskAgent(), retriever=retriever).assess(CLOUD_SCENARIO)
    assert captured == [((), {})]
    hits = original(CLOUD_SCENARIO)
    assert len(hits) == DEFAULT_TOP_K


def test_startup_retriever_default_path_returns_five_candidates() -> None:
    settings = Settings(risk_agent="ollama", rag_enabled=True)
    retriever = build_startup_retriever(settings, embedder=FakeEmbedder())
    assert retriever is not None
    hits = retriever.retrieve(CLOUD_SCENARIO)
    assert len(hits) == DEFAULT_TOP_K


def test_debug_helpers_default_to_production_top_k() -> None:
    assert parse_file_debug_args([]).top_k == DEFAULT_TOP_K
    assert parse_knowledge_debug_args([]).top_k == DEFAULT_TOP_K
