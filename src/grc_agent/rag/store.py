"""In-memory cosine similarity store. No FAISS/Chroma."""

from __future__ import annotations

import math

from grc_agent.rag.types import Chunk, RetrievalHit


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ValueError("embedding dimensions must match")
    if not left:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    norm_left = math.sqrt(sum(a * a for a in left)) or 1.0
    norm_right = math.sqrt(sum(b * b for b in right)) or 1.0
    return dot / (norm_left * norm_right)


class InMemoryVectorStore:
    """Holds chunks and their embeddings in process memory."""

    def __init__(self) -> None:
        self._items: list[tuple[Chunk, list[float]]] = []

    def add(self, chunk: Chunk, embedding: list[float]) -> None:
        self._items.append((chunk, list(embedding)))

    def __len__(self) -> int:
        return len(self._items)

    def search(self, query_embedding: list[float], top_k: int = 3) -> list[RetrievalHit]:
        if top_k < 1:
            raise ValueError("top_k must be at least 1")
        scored = [
            RetrievalHit(chunk=chunk, score=cosine_similarity(query_embedding, embedding))
            for chunk, embedding in self._items
        ]
        scored.sort(key=lambda hit: hit.score, reverse=True)
        return scored[:top_k]
