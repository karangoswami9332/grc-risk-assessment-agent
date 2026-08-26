"""Retrieve relevant chunks for a query. Independently testable; no LLM."""

from __future__ import annotations

from grc_agent.rag.embeddings import Embedder
from grc_agent.rag.store import InMemoryVectorStore
from grc_agent.rag.types import Chunk, RetrievalHit

# Production retrieval depth. RiskOrchestrator calls retrieve(query) with no override.
DEFAULT_TOP_K = 5


def format_hits(hits: list[RetrievalHit]) -> str:
    """Render hits as plain text for an LLM context block."""
    if not hits:
        return ""
    parts: list[str] = []
    for index, hit in enumerate(hits, start=1):
        source = hit.chunk.source or hit.chunk.id
        parts.append(f"[{index}] source={source}\n{hit.chunk.text}")
    return "\n\n".join(parts)


class Retriever:
    def __init__(self, embedder: Embedder, store: InMemoryVectorStore | None = None) -> None:
        self._embedder = embedder
        self._store = store if store is not None else InMemoryVectorStore()

    def add_chunks(self, chunks: list[Chunk]) -> None:
        for chunk in chunks:
            self._store.add(chunk, self._embedder.embed(chunk.text))

    def retrieve(self, query: str, top_k: int = DEFAULT_TOP_K) -> list[RetrievalHit]:
        text = query.strip()
        if not text:
            return []
        return self._store.search(self._embedder.embed(text), top_k=top_k)
