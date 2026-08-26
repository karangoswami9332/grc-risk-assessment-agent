"""Lightweight custom RAG. No LangChain. Scoring stays in RiskEngine."""

from grc_agent.rag.chunking import chunk_text
from grc_agent.rag.embeddings import FakeEmbedder, OllamaEmbedder
from grc_agent.rag.ingest import ingest_file, ingest_knowledge_dir, ollama_embedder_from_settings
from grc_agent.rag.retriever import Retriever, format_hits
from grc_agent.rag.store import InMemoryVectorStore
from grc_agent.rag.types import Chunk, RetrievalHit
from grc_agent.rag.wiring import build_startup_retriever, rag_should_run

__all__ = [
    "Chunk",
    "FakeEmbedder",
    "OllamaEmbedder",
    "InMemoryVectorStore",
    "RetrievalHit",
    "Retriever",
    "build_startup_retriever",
    "chunk_text",
    "ingest_file",
    "ingest_knowledge_dir",
    "ollama_embedder_from_settings",
    "format_hits",
    "rag_should_run",
]
