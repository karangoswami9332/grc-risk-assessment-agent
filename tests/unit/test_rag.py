"""Unit tests for custom RAG (no live Ollama, no FAISS/Chroma)."""

from __future__ import annotations

import pytest

from grc_agent.rag.chunking import chunk_text
from grc_agent.rag.embeddings import FakeEmbedder
from grc_agent.rag.retriever import Retriever, format_hits
from grc_agent.rag.store import InMemoryVectorStore, cosine_similarity
from grc_agent.rag.types import Chunk


def test_chunk_text_splits_long_input() -> None:
    text = "Least privilege reduces unauthorized access. " * 20
    chunks = chunk_text(text, source="note.md", chunk_size=80, overlap=10)
    assert len(chunks) >= 2
    assert chunks[0].source == "note.md"
    assert chunks[0].id.startswith("note.md:")
    assert all(chunk.text for chunk in chunks)
    assert all(len(chunk.text) <= 80 for chunk in chunks)
    assert all(chunk.text[0].isupper() for chunk in chunks)


def test_chunk_text_empty() -> None:
    assert chunk_text("   ") == []


def test_fake_embedder_is_deterministic() -> None:
    embedder = FakeEmbedder()
    first = embedder.embed("Lack of MFA on a public portal")
    second = embedder.embed("Lack of MFA on a public portal")
    assert first == second
    assert len(first) == 32


def test_retriever_ranks_related_chunk_first() -> None:
    embedder = FakeEmbedder()
    retriever = Retriever(embedder)
    retriever.add_chunks(
        [
            Chunk(
                id="mfa",
                text="mfa authentication for customer portal access control",
                source="cis.md",
            ),
            Chunk(
                id="unrelated",
                text="zzzzzzzz qqqqqqqq wwwwwwww yyyyyyyy",
                source="ops.md",
            ),
        ]
    )
    hits = retriever.retrieve("customer portal mfa authentication", top_k=2)
    assert len(hits) == 2
    assert hits[0].chunk.id == "mfa"
    assert hits[0].score >= hits[1].score


def test_format_hits_and_empty_query() -> None:
    embedder = FakeEmbedder()
    retriever = Retriever(embedder, InMemoryVectorStore())
    retriever.add_chunks([Chunk(id="a", text="Access control policy requires unique user IDs.", source="iso.md")])
    assert retriever.retrieve("   ") == []
    hits = retriever.retrieve("unique user IDs")
    rendered = format_hits(hits)
    assert "iso.md" in rendered
    assert "Access control" in rendered


def test_cosine_rejects_mismatched_dimensions() -> None:
    with pytest.raises(ValueError, match="dimensions"):
        cosine_similarity([1.0, 0.0], [1.0])
