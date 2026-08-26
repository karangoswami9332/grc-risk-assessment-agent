"""Offline checks for knowledge-dir RAG debug (FakeEmbedder; no live Ollama)."""

from __future__ import annotations

from grc_agent.rag.debug_retrieve_knowledge import (
    DEFAULT_QUERY,
    parse_args,
    run_knowledge_rag_debug,
)
from grc_agent.rag.embeddings import FakeEmbedder
from grc_agent.rag.ingest import default_knowledge_dir


def test_knowledge_dir_debug_report_includes_controls_and_access_control() -> None:
    knowledge_dir = default_knowledge_dir()
    assert (knowledge_dir / "controls.md").is_file()
    assert (knowledge_dir / "access_control.md").is_file()

    report = run_knowledge_rag_debug(embedder=FakeEmbedder(), top_k=5)
    assert "Knowledge-dir RAG verification" in report
    assert DEFAULT_QUERY in report
    assert "controls.md" in report
    assert "access_control.md" in report
    assert "chunk_id:" in report
    assert "similarity_score:" in report
    assert "contains_ctrl_id:" in report
    assert "Expected control:" in report
    assert "Retrieved:" in report


def test_parse_args_accepts_query_and_expected_control() -> None:
    args = parse_args(
        [
            "--query",
            "A cloud administrator has excessive permissions.",
            "--expected-control",
            "CTRL-AC-001",
            "--top-k",
            "5",
        ]
    )
    assert args.query == "A cloud administrator has excessive permissions."
    assert args.expected_control == "CTRL-AC-001"
    assert args.top_k == 5


def test_custom_query_appears_in_report() -> None:
    query = "A cloud administrator has excessive permissions and can access systems."
    report = run_knowledge_rag_debug(
        query=query,
        expected_control="CTRL-AC-001",
        embedder=FakeEmbedder(),
        top_k=5,
    )
    assert query in report
    assert "Expected control: CTRL-AC-001" in report
    assert "Rank:" in report
    assert "Score:" in report
