"""Internal GRC control catalog loads via existing ingest_file path."""

from __future__ import annotations

from grc_agent.rag.embeddings import FakeEmbedder
from grc_agent.rag.ingest import default_knowledge_dir, ingest_file, ingest_knowledge_dir
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

CATALOG_PATH = default_knowledge_dir() / "controls.md"


def test_controls_md_exists_with_stable_ids() -> None:
    assert CATALOG_PATH.is_file()
    text = CATALOG_PATH.read_text(encoding="utf-8")
    assert "Internal GRC Control Catalog" in text
    for control_id in CONTROL_IDS:
        assert control_id in text


def test_ingest_file_controls_md_produces_chunks_with_control_ids() -> None:
    store = InMemoryVectorStore()
    retriever = Retriever(FakeEmbedder(), store)
    chunks = ingest_file(CATALOG_PATH, retriever)
    assert chunks
    assert all(chunk.source == "controls.md" for chunk in chunks)
    blob = "\n".join(chunk.text for chunk in chunks)
    for control_id in CONTROL_IDS:
        assert control_id in blob


def test_ingest_knowledge_dir_discovers_controls_md() -> None:
    store = InMemoryVectorStore()
    retriever = Retriever(FakeEmbedder(), store)
    chunks = ingest_knowledge_dir(retriever, default_knowledge_dir())
    sources = {chunk.source for chunk in chunks}
    assert "controls.md" in sources
    assert "access_control.md" in sources
