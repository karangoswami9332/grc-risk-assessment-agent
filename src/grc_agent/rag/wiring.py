"""Build an in-memory Retriever at app startup. Not used unless Ollama + RAG are on."""

from __future__ import annotations

import logging
from pathlib import Path

from grc_agent.agents.factory import OLLAMA_AGENT
from grc_agent.config import Settings
from grc_agent.rag.embeddings import Embedder
from grc_agent.rag.ingest import default_knowledge_dir, ingest_knowledge_dir, ollama_embedder_from_settings
from grc_agent.rag.retriever import Retriever
from grc_agent.rag.store import InMemoryVectorStore

logger = logging.getLogger(__name__)


def rag_should_run(settings: Settings) -> bool:
    """RAG runs only for the Ollama agent and only when GRC_RAG_ENABLED is true."""
    return settings.risk_agent == OLLAMA_AGENT and settings.rag_enabled


def build_startup_retriever(
    settings: Settings,
    *,
    embedder: Embedder | None = None,
    knowledge_dir: Path | None = None,
) -> Retriever | None:
    """Index ``data/knowledge`` when RAG is enabled. Returns None when RAG is off.

    Missing or empty knowledge directories do not fail startup: an empty
    retriever is returned so retrieval still runs and yields no hits.
    """
    if not rag_should_run(settings):
        return None

    resolved_embedder = embedder or ollama_embedder_from_settings(settings)
    retriever = Retriever(resolved_embedder, InMemoryVectorStore())
    directory = knowledge_dir or default_knowledge_dir()
    if not directory.is_dir():
        logger.warning("RAG is enabled but knowledge directory is missing: %s", directory)
        return retriever

    ingested = ingest_knowledge_dir(retriever, directory)
    if not ingested:
        logger.warning("RAG is enabled but no markdown files were found in %s", directory)
    return retriever
