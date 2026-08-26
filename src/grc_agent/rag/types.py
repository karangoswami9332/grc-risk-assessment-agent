"""RAG domain types. No scoring, no LLM."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Chunk(BaseModel):
    """A text fragment from a GRC knowledge source."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    source: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class RetrievalHit(BaseModel):
    """A chunk plus similarity score (higher is more similar)."""

    model_config = ConfigDict(extra="forbid")

    chunk: Chunk
    score: float
