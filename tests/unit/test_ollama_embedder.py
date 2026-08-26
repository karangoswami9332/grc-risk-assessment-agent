"""OllamaEmbedder tests. HTTP is mocked; Ollama does not need to be running."""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from grc_agent.llm.errors import OllamaResponseError, OllamaUnavailableError
from grc_agent.rag.embeddings import OllamaEmbedder
from grc_agent.rag.retriever import Retriever
from grc_agent.rag.types import Chunk


class _FakeHttpResponse:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _patch_urlopen(payload: dict):
    return patch(
        "grc_agent.llm.ollama_client.urllib.request.urlopen",
        return_value=_FakeHttpResponse(payload),
    )


def test_successful_embedding() -> None:
    vector = [0.1, -0.2, 0.3, 0.0]
    captured: dict = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _FakeHttpResponse({"embeddings": [vector]})

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        result = OllamaEmbedder().embed("  public portal MFA  ")

    assert result == vector
    assert captured["url"] == "http://127.0.0.1:11434/api/embed"
    assert captured["body"] == {"model": "nomic-embed-text", "input": "public portal MFA"}


def test_malformed_embed_response_is_rejected() -> None:
    with _patch_urlopen({"message": "oops"}):
        with pytest.raises(OllamaResponseError, match="embeddings"):
            OllamaEmbedder().embed("hello")


def test_empty_embedding_vector_is_rejected() -> None:
    with _patch_urlopen({"embeddings": [[]]}):
        with pytest.raises(OllamaResponseError, match="empty"):
            OllamaEmbedder().embed("hello")


def test_embed_http_failure() -> None:
    error = HTTPError(
        url="http://127.0.0.1:11434/api/embed",
        code=500,
        msg="Internal Server Error",
        hdrs=None,
        fp=BytesIO(b""),
    )
    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=error):
        with pytest.raises(OllamaUnavailableError, match="HTTP error 500"):
            OllamaEmbedder().embed("hello")


def test_embed_connection_failure() -> None:
    with patch(
        "grc_agent.llm.ollama_client.urllib.request.urlopen",
        side_effect=URLError("connection refused"),
    ):
        with pytest.raises(OllamaUnavailableError, match="unavailable"):
            OllamaEmbedder().embed("hello")


def test_empty_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        OllamaEmbedder().embed("   ")


def test_retriever_accepts_ollama_embedder_vectors() -> None:
    """Dimension is whatever Ollama returns; the in-memory store does not hard-code it."""
    calls = {"n": 0}

    def fake_urlopen(request, timeout=None):
        calls["n"] += 1
        # Distinct dummy vectors of length 4 (not nomic's 768).
        if calls["n"] == 1:
            return _FakeHttpResponse({"embeddings": [[1.0, 0.0, 0.0, 0.0]]})
        return _FakeHttpResponse({"embeddings": [[0.9, 0.1, 0.0, 0.0]]})

    retriever = Retriever(OllamaEmbedder())
    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        retriever.add_chunks([Chunk(id="a", text="Require MFA for remote access.", source="cis.md")])
        hits = retriever.retrieve("MFA remote access", top_k=1)

    assert len(hits) == 1
    assert hits[0].chunk.id == "a"
    assert len(hits[0].chunk.text) > 0
