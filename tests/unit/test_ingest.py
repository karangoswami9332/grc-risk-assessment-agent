"""Ingest curated knowledge into an in-memory retriever (no live Ollama)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from grc_agent.config import Settings
from grc_agent.rag.embeddings import FakeEmbedder, OllamaEmbedder
from grc_agent.rag.ingest import (
    default_knowledge_dir,
    ingest_file,
    ingest_knowledge_dir,
    ollama_embedder_from_settings,
)
from grc_agent.rag.retriever import Retriever
from grc_agent.rag.store import InMemoryVectorStore

ACCESS_CONTROL_MD = default_knowledge_dir() / "access_control.md"


class _FakeHttpResponse:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_knowledge_document_exists_and_covers_topics() -> None:
    text = ACCESS_CONTROL_MD.read_text(encoding="utf-8").lower()
    assert ACCESS_CONTROL_MD.is_file()
    for topic in (
        "least privilege",
        "unauthorized access",
        "cloud storage",
        "misconfiguration",
        "confidentiality",
        "preventive",
        "detective",
        "mitigate",
    ):
        assert topic in text


def test_ingest_chunks_embeds_and_stores_with_fake_embedder() -> None:
    store = InMemoryVectorStore()
    retriever = Retriever(FakeEmbedder(), store)
    chunks = ingest_file(ACCESS_CONTROL_MD, retriever)
    assert len(chunks) >= 1
    assert all(chunk.source == "access_control.md" for chunk in chunks)
    assert len(store) == len(chunks)


def test_ingest_dir_retrieves_relevant_chunk() -> None:
    retriever = Retriever(FakeEmbedder())
    ingest_knowledge_dir(retriever, default_knowledge_dir())
    hits = retriever.retrieve(
        "public cloud storage bucket is publicly readable due to misconfiguration",
        top_k=3,
    )
    assert hits
    blob = " ".join(hit.chunk.text.lower() for hit in hits)
    assert "cloud" in blob or "bucket" in blob or "misconfigur" in blob


def test_ingest_with_mocked_ollama_embedder_uses_configured_model() -> None:
    captured: list[dict] = []

    def fake_urlopen(request, timeout=None):
        captured.append(json.loads(request.data.decode("utf-8")))
        dim = 4
        index = len(captured)
        vector = [float(index), 0.1, 0.0, 0.0][:dim]
        return _FakeHttpResponse({"embeddings": [vector]})

    settings = Settings(ollama_embed_model="nomic-embed-text")
    embedder = ollama_embedder_from_settings(settings)
    assert isinstance(embedder, OllamaEmbedder)
    retriever = Retriever(embedder)
    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        chunks = ingest_file(ACCESS_CONTROL_MD, retriever)
        hits = retriever.retrieve("least privilege and MFA for privileged accounts", top_k=2)

    assert chunks
    assert len(captured) == len(chunks) + 1  # one embed per chunk plus the query
    assert all(item["model"] == "nomic-embed-text" for item in captured)
    assert all("input" in item for item in captured)
    assert hits
    assert hits[0].chunk.source == "access_control.md"


def test_ingest_missing_directory() -> None:
    retriever = Retriever(FakeEmbedder())
    with pytest.raises(FileNotFoundError, match="Knowledge directory"):
        ingest_knowledge_dir(retriever, Path("data/knowledge/does-not-exist"))
