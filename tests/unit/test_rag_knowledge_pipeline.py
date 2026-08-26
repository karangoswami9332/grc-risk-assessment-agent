"""End-to-end RAG pipeline against data/knowledge/access_control.md (mocked Ollama)."""

from __future__ import annotations

import json
from unittest.mock import patch

from grc_agent.config import Settings
from grc_agent.rag.embeddings import FakeEmbedder, OllamaEmbedder
from grc_agent.rag.ingest import default_knowledge_dir, ingest_file, ollama_embedder_from_settings
from grc_agent.rag.retriever import Retriever, format_hits
from grc_agent.rag.store import InMemoryVectorStore

SCENARIO = (
    "A cloud storage bucket containing confidential financial reports is publicly "
    "accessible because of an incorrect access control configuration."
)


class _FakeHttpResponse:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_access_control_knowledge_pipeline_retrieves_public_storage_guidance() -> None:
    knowledge_path = default_knowledge_dir() / "access_control.md"
    assert knowledge_path.is_file()

    # Content-aware vectors via FakeEmbedder, delivered as mocked Ollama /api/embed payloads.
    lexical = FakeEmbedder()

    def fake_urlopen(request, timeout=None):
        body = json.loads(request.data.decode("utf-8"))
        assert request.full_url.endswith("/api/embed")
        assert body["model"] == "nomic-embed-text"
        vector = lexical.embed(body["input"])
        return _FakeHttpResponse({"embeddings": [vector]})

    store = InMemoryVectorStore()
    embedder = ollama_embedder_from_settings(Settings(ollama_embed_model="nomic-embed-text"))
    assert isinstance(embedder, OllamaEmbedder)
    retriever = Retriever(embedder, store)

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        chunks = ingest_file(knowledge_path, retriever)
        hits = retriever.retrieve(SCENARIO, top_k=3)

    assert chunks
    assert all(chunk.source == "access_control.md" for chunk in chunks)
    assert len(store) == len(chunks)
    assert hits

    context = format_hits(hits).lower()
    assert "access_control.md" in context
    assert "public" in context
    assert any(
        term in context
        for term in ("cloud storage", "bucket", "misconfigur", "block-public-access")
    )
    assert any(
        term in context
        for term in ("confidential", "least privilege", "iam", "access control")
    )
