"""Atomic control-catalog chunking (controls.md only)."""

from __future__ import annotations

import re
from pathlib import Path

from grc_agent.rag.chunking import DEFAULT_CHUNK_SIZE, chunk_text
from grc_agent.rag.control_chunking import CONTROL_CATALOG_CHUNK_SIZE, chunk_control_catalog
from grc_agent.rag.embeddings import FakeEmbedder
from grc_agent.rag.ingest import default_knowledge_dir, ingest_file
from grc_agent.rag.retriever import Retriever
from grc_agent.rag.store import InMemoryVectorStore

CONTROL_IDS = (
    "CTRL-AC-001",
    "CTRL-AC-002",
    "CTRL-AC-003",
    "CTRL-CLD-001",
    "CTRL-CLD-002",
    "CTRL-CLD-003",
    "CTRL-DAT-001",
    "CTRL-DAT-002",
    "CTRL-DAT-003",
    "CTRL-MON-001",
)

REQUIRED_FIELDS = (
    "Control ID:",
    "Name:",
    "Objective:",
    "Control Type:",
    "Domain:",
    "Description:",
    "Example Implementation:",
)


def test_ctrl_cld_001_id_and_body_stay_together() -> None:
    text = (default_knowledge_dir() / "controls.md").read_text(encoding="utf-8")
    chunks = chunk_control_catalog(text, source="controls.md")
    matches = [c for c in chunks if "CTRL-CLD-001" in c.text]
    assert len(matches) == 1
    body = matches[0].text
    assert "## CTRL-CLD-001" in body
    for field in REQUIRED_FIELDS:
        assert field in body
    assert "Block Public Access to Cloud Storage" in body
    assert "block-public-access" in body.lower() or "public access" in body.lower()


def test_fitting_controls_remain_atomic() -> None:
    text = (default_knowledge_dir() / "controls.md").read_text(encoding="utf-8")
    chunks = chunk_control_catalog(text, source="controls.md")
    control_chunks = [c for c in chunks if re.search(r"^##\s+CTRL-", c.text, re.M)]
    assert len(control_chunks) == len(CONTROL_IDS)
    for chunk in control_chunks:
        assert len(chunk.text) <= CONTROL_CATALOG_CHUNK_SIZE
        for field in REQUIRED_FIELDS:
            assert field in chunk.text
        ids = set(re.findall(r"CTRL-[A-Z]+-\d+", chunk.text))
        assert len(ids) == 1


def test_oversized_control_keeps_id_on_every_piece() -> None:
    section = (
        "## CTRL-CLD-001 — Block Public Access to Cloud Storage\n\n"
        "**Control ID:** CTRL-CLD-001\n\n"
        "**Name:** Block Public Access to Cloud Storage\n\n"
        "**Objective:** Prevent unauthorized public access.\n\n"
        "**Control Type:** Preventive\n\n"
        "**Domain:** Cloud Security\n\n"
        "**Description:** "
        + ("Sensitive cloud storage must remain private. " * 20)
        + "\n\n"
        "**Example Implementation:** Enable block-public-access and restrict IAM."
    )
    chunks = chunk_control_catalog(section, source="controls.md", chunk_size=180, overlap=20)
    assert len(chunks) >= 2
    for chunk in chunks:
        assert "CTRL-CLD-001" in chunk.text
        assert chunk.text == chunk.text.strip()
        assert not re.match(r"^[a-z]", chunk.text)


def test_ingest_file_uses_control_chunker_only_for_controls_md() -> None:
    store = InMemoryVectorStore()
    retriever = Retriever(FakeEmbedder(), store)
    chunks = ingest_file(default_knowledge_dir() / "controls.md", retriever)
    assert all(c.source == "controls.md" for c in chunks)
    control_chunks = [c for c in chunks if "CTRL-CLD-001" in c.text]
    assert len(control_chunks) == 1
    assert all(field in control_chunks[0].text for field in REQUIRED_FIELDS)


def test_access_control_chunking_unchanged_by_control_catalog_path() -> None:
    path = default_knowledge_dir() / "access_control.md"
    text = path.read_text(encoding="utf-8")
    via_chunk_text = chunk_text(text, source="access_control.md")
    store = InMemoryVectorStore()
    via_ingest = ingest_file(path, Retriever(FakeEmbedder(), store))
    assert [c.text for c in via_ingest] == [c.text for c in via_chunk_text]
    assert [c.id for c in via_ingest] == [c.id for c in via_chunk_text]
    assert len(via_ingest) == 11
    assert via_ingest[0].id == "access_control.md:1"
    assert via_chunk_text[0].text.startswith("# Access control")


def test_general_chunk_size_default_still_400() -> None:
    assert DEFAULT_CHUNK_SIZE == 400
    assert CONTROL_CATALOG_CHUNK_SIZE == 800
