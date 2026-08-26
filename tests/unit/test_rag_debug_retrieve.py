"""Printer/wiring for the manual RAG debug command. Does not replace live Ollama checks."""

from __future__ import annotations

from grc_agent.rag.debug_retrieve import DEFAULT_QUERY, knowledge_file_path, parse_args, run_rag_debug
from grc_agent.rag.embeddings import FakeEmbedder


def test_debug_report_layout_with_fake_embedder() -> None:
    report = run_rag_debug(embedder=FakeEmbedder())
    path = knowledge_file_path()
    assert path.is_file()
    assert "RAG manual verification" in report
    assert str(path.resolve()) in report
    assert DEFAULT_QUERY in report
    assert "chunk_id:" in report
    assert "similarity_score:" in report
    assert "source: access_control.md" in report
    assert "chunk_text:" in report
    assert "Formatted context for OllamaRiskAgent" in report
    assert "source=access_control.md" in report


def test_debug_retrieve_parse_args_query() -> None:
    args = parse_args(["--query", "Excessive admin permissions.", "--top-k", "4"])
    assert args.query == "Excessive admin permissions."
    assert args.top_k == 4
