"""Unit tests for semantic markdown/plain-text chunking."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from grc_agent.rag.chunking import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, chunk_text


def test_chunk_text_empty() -> None:
    assert chunk_text("   ") == []
    assert chunk_text("") == []


def test_short_document_remains_intact() -> None:
    text = "## Short\n\nOne brief paragraph about MFA."
    chunks = chunk_text(text, source="short.md", chunk_size=400, overlap=80)
    assert len(chunks) == 1
    assert chunks[0].id == "short.md:1"
    assert chunks[0].source == "short.md"
    assert chunks[0].text == text.strip()
    assert chunks[0].metadata == {}


def test_prefers_paragraph_and_heading_boundaries() -> None:
    text = (
        "# Title\n\n"
        "## Section one\n"
        "First paragraph stays together as one unit about access control.\n\n"
        "## Section two\n"
        "Second paragraph covers cloud storage buckets and misconfiguration."
    )
    chunks = chunk_text(text, source="policy.md", chunk_size=180, overlap=20)
    assert len(chunks) >= 2
    assert all(chunk.source == "policy.md" for chunk in chunks)
    assert chunks[0].id == "policy.md:1"
    assert chunks[1].id == "policy.md:2"
    joined = "\n".join(chunk.text for chunk in chunks)
    assert "Section one" in joined
    assert "Section two" in joined
    # Prefer not to glue both section bodies into one oversized blob.
    assert not any(
        "Section one" in chunk.text and "Section two" in chunk.text for chunk in chunks
    )


def test_does_not_split_mid_word_when_whitespace_exists() -> None:
    words = [f"word{i:02d}" for i in range(40)]
    text = " ".join(words)
    chunks = chunk_text(text, source="words.md", chunk_size=50, overlap=10)
    assert len(chunks) >= 2
    for chunk in chunks:
        assert chunk.text == chunk.text.strip()
        # Every fragment must be a sequence of whole words.
        for token in chunk.text.split():
            assert token in words
        assert not chunk.text.startswith("ord")
        assert not chunk.text.endswith("wor")


def test_sentence_boundaries_preferred_inside_long_paragraph() -> None:
    text = (
        "First sentence about least privilege and MFA. "
        "Second sentence about privileged accounts and monitoring. "
        "Third sentence about shared admin credentials and exposure."
    )
    chunks = chunk_text(text, source="s.md", chunk_size=90, overlap=10)
    assert len(chunks) >= 2
    for chunk in chunks:
        assert chunk.text[0].isupper() or chunk.text[0] in "\"'"
        assert not chunk.text[0].islower()
        # Prefer ending on sentence punctuation when the piece is not the final
        # partial pack of remaining text that still fits cleanly.
        assert chunk.text[-1] in ".!?" or len(chunk.text) <= 90


def test_maximum_chunk_size_respected() -> None:
    paragraphs = [f"Paragraph {i}. " + ("content " * 20) for i in range(8)]
    text = "\n\n".join(paragraphs)
    chunk_size = 120
    chunks = chunk_text(text, source="long.md", chunk_size=chunk_size, overlap=20)
    assert chunks
    assert all(len(chunk.text) <= chunk_size for chunk in chunks)


def test_deterministic_ids_and_source() -> None:
    text = "## A\n\nAlpha sentence here.\n\n## B\n\nBeta sentence here."
    first = chunk_text(text, source="doc.md", chunk_size=40, overlap=5)
    second = chunk_text(text, source="doc.md", chunk_size=40, overlap=5)
    assert [c.id for c in first] == [c.id for c in second]
    assert [c.text for c in first] == [c.text for c in second]
    assert all(c.id == f"doc.md:{i}" for i, c in enumerate(first, start=1))
    assert all(c.source == "doc.md" for c in first)


def test_defaults_exported() -> None:
    assert DEFAULT_CHUNK_SIZE == 400
    assert DEFAULT_OVERLAP == 80


def test_invalid_sizes_rejected() -> None:
    with pytest.raises(ValueError, match="chunk_size"):
        chunk_text("hello", chunk_size=0)
    with pytest.raises(ValueError, match="overlap"):
        chunk_text("hello", chunk_size=10, overlap=10)


def test_access_control_knowledge_has_readable_edges() -> None:
    path = Path(__file__).resolve().parents[2] / "data" / "knowledge" / "access_control.md"
    text = path.read_text(encoding="utf-8")
    chunks = chunk_text(text, source="access_control.md")
    assert len(chunks) >= 2
    for chunk in chunks:
        assert chunk.source == "access_control.md"
        assert len(chunk.text) <= DEFAULT_CHUNK_SIZE
        assert chunk.text == chunk.text.strip()
        assert chunk.text[0] in "#ABCDEFGHIJKLMNOPQRSTUVWXYZ\"'("
        assert chunk.text[-1] not in " \t\n"
        assert not chunk.text.endswith("ccounts")
        assert not chunk.text.startswith("ccounts")
        assert not chunk.text.startswith("r unexpected")
        assert not chunk.text.startswith("ent\n")
        # Whole-word edges: first/last word appear intact in the source document.
        first_word = re.split(r"\s+", chunk.text, maxsplit=1)[0].lstrip("#")
        last_word = re.split(r"\s+", chunk.text)[-1].rstrip(".,;:!?")
        assert first_word in text or chunk.text.startswith("#")
        assert last_word in text
