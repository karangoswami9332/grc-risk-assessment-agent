"""Embedding protocol and a deterministic fake for tests (no Ollama, no numpy)."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

from grc_agent.llm.ollama_client import (
    DEFAULT_OLLAMA_EMBED_MODEL,
    DEFAULT_OLLAMA_HOST,
    DEFAULT_TIMEOUT_SECONDS,
    OllamaChatClient,
)

_TOKEN = re.compile(r"[a-z0-9]+")
FAKE_EMBEDDING_DIM = 32


class Embedder(Protocol):
    def embed(self, text: str) -> list[float]:
        """Return a vector for one string."""


class FakeEmbedder:
    """Bag-of-tokens hashed into a fixed-size L2-normalized vector.

    Shared tokens produce similar vectors so retrieval tests do not need a model.
    """

    def __init__(self, dim: int = FAKE_EMBEDDING_DIM) -> None:
        if dim < 2:
            raise ValueError("dim must be at least 2")
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in _TOKEN.findall(text.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dim
            vec[index] += 1.0
        norm = math.sqrt(sum(value * value for value in vec)) or 1.0
        return [value / norm for value in vec]


class OllamaEmbedder:
    """Embedder that calls local Ollama ``POST /api/embed``. Does not score risks."""

    def __init__(
        self,
        client: OllamaChatClient | None = None,
        host: str = DEFAULT_OLLAMA_HOST,
        embed_model: str = DEFAULT_OLLAMA_EMBED_MODEL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._client = client or OllamaChatClient(
            host=host,
            embed_model=embed_model,
            timeout_seconds=timeout_seconds,
        )

    def embed(self, text: str) -> list[float]:
        cleaned = text.strip()
        if not cleaned:
            raise ValueError("text must not be empty")
        return self._client.embed(cleaned)
