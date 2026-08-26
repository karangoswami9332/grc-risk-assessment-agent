"""Load curated GRC markdown into a Retriever. No persistence, no API wiring."""

from __future__ import annotations

from pathlib import Path

from grc_agent.config import Settings, get_settings
from grc_agent.rag.chunking import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, chunk_text
from grc_agent.rag.control_chunking import CONTROL_CATALOG_CHUNK_SIZE, chunk_control_catalog
from grc_agent.rag.embeddings import Embedder, OllamaEmbedder
from grc_agent.rag.retriever import Retriever
from grc_agent.rag.types import Chunk

KNOWLEDGE_DIR_NAME = "knowledge"
CONTROL_CATALOG_FILENAME = "controls.md"


def default_knowledge_dir() -> Path:
    """``<repo>/data/knowledge`` when running from the source tree."""
    return Path(__file__).resolve().parents[3] / "data" / KNOWLEDGE_DIR_NAME


def ollama_embedder_from_settings(settings: Settings | None = None) -> OllamaEmbedder:
    """Build an OllamaEmbedder using OLLAMA_HOST and OLLAMA_EMBED_MODEL."""
    resolved = settings or get_settings()
    return OllamaEmbedder(
        host=resolved.ollama_host,
        embed_model=resolved.ollama_embed_model,
        timeout_seconds=resolved.ollama_timeout_seconds,
    )


def ingest_file(
    path: Path,
    retriever: Retriever,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_OVERLAP,
) -> list[Chunk]:
    """Chunk one document, embed each chunk, and add it to the retriever's store.

    ``controls.md`` uses control-catalog chunking so each CTRL-* section stays
    atomic when it fits. All other knowledge files use ``chunk_text``.
    """
    text = path.read_text(encoding="utf-8")
    if path.name == CONTROL_CATALOG_FILENAME:
        catalog_chunk_size = (
            CONTROL_CATALOG_CHUNK_SIZE
            if chunk_size == DEFAULT_CHUNK_SIZE
            else chunk_size
        )
        chunks = chunk_control_catalog(
            text,
            source=path.name,
            chunk_size=catalog_chunk_size,
            overlap=overlap,
        )
    else:
        chunks = chunk_text(
            text,
            source=path.name,
            chunk_size=chunk_size,
            overlap=overlap,
        )
    retriever.add_chunks(chunks)
    return chunks


def ingest_knowledge_dir(
    retriever: Retriever,
    knowledge_dir: Path | None = None,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_OVERLAP,
) -> list[Chunk]:
    """Ingest all ``*.md`` files in the knowledge directory (sorted by name)."""
    directory = knowledge_dir or default_knowledge_dir()
    if not directory.is_dir():
        raise FileNotFoundError(f"Knowledge directory not found: {directory}")
    ingested: list[Chunk] = []
    for path in sorted(directory.glob("*.md")):
        ingested.extend(
            ingest_file(path, retriever, chunk_size=chunk_size, overlap=overlap)
        )
    return ingested
