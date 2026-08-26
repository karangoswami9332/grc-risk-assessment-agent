"""Manual RAG verification against local Ollama. Not used by the API."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from grc_agent.config import Settings, get_settings
from grc_agent.rag.embeddings import Embedder
from grc_agent.rag.ingest import default_knowledge_dir, ingest_file, ollama_embedder_from_settings
from grc_agent.rag.retriever import DEFAULT_TOP_K, Retriever, format_hits
from grc_agent.rag.store import InMemoryVectorStore

DEFAULT_QUERY = (
    "A cloud storage bucket containing confidential financial reports is publicly "
    "accessible because of an incorrect access control configuration."
)
DEFAULT_KNOWLEDGE_FILE = "access_control.md"


def knowledge_file_path(knowledge_dir: Path | None = None) -> Path:
    directory = knowledge_dir or default_knowledge_dir()
    return directory / DEFAULT_KNOWLEDGE_FILE


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Diagnostic RAG retrieval for a single knowledge file "
            "(default: access_control.md). For control-catalog diagnostics use "
            "python -m grc_agent.rag.debug_retrieve_knowledge"
        )
    )
    parser.add_argument("--query", default=DEFAULT_QUERY, help="Free-text retrieval query")
    parser.add_argument(
        "--top-k",
        type=int,
        default=DEFAULT_TOP_K,
        help=f"Number of hits to retrieve (default: {DEFAULT_TOP_K})",
    )
    return parser.parse_args(argv)


def run_rag_debug(
    *,
    query: str = DEFAULT_QUERY,
    top_k: int = DEFAULT_TOP_K,
    knowledge_path: Path | None = None,
    embedder: Embedder | None = None,
    settings: Settings | None = None,
) -> str:
    """Ingest one knowledge file, retrieve ``top_k`` hits, and format a debug report.

    When ``embedder`` is omitted, uses ``OllamaEmbedder`` and the live Ollama
    model from ``OLLAMA_EMBED_MODEL``.
    """
    path = (knowledge_path or knowledge_file_path()).resolve()
    resolved_settings = settings or get_settings()
    resolved_embedder = embedder or ollama_embedder_from_settings(resolved_settings)
    store = InMemoryVectorStore()
    retriever = Retriever(resolved_embedder, store)
    chunks = ingest_file(path, retriever)
    hits = retriever.retrieve(query, top_k=top_k)
    context = format_hits(hits)
    return _format_report(
        path=path,
        query=query,
        chunk_count=len(chunks),
        store_size=len(store),
        embed_model=resolved_settings.ollama_embed_model,
        host=resolved_settings.ollama_host,
        hits=hits,
        context=context,
    )


def _format_report(
    *,
    path: Path,
    query: str,
    chunk_count: int,
    store_size: int,
    embed_model: str,
    host: str,
    hits,
    context: str,
) -> str:
    lines: list[str] = [
        "=== RAG manual verification ===",
        f"knowledge_path: {path}",
        f"chunks_ingested: {chunk_count}",
        f"store_size: {store_size}",
        f"ollama_host: {host}",
        f"embed_model: {embed_model}",
        f"top_k: {len(hits)}",
        "",
        "=== Query ===",
        query,
        "",
    ]
    if not hits:
        lines.append("=== Results ===")
        lines.append("(no hits)")
    else:
        for index, hit in enumerate(hits, start=1):
            lines.extend(
                [
                    f"=== Result {index} ===",
                    f"rank: {index}",
                    f"chunk_id: {hit.chunk.id}",
                    f"similarity_score: {hit.score:.6f}",
                    f"source: {hit.chunk.source or hit.chunk.id}",
                    f"path: {path}",
                    "chunk_text:",
                    hit.chunk.text,
                    "",
                ]
            )
    lines.extend(
        [
            "=== Formatted context for OllamaRiskAgent ===",
            context if context else "(empty)",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    print(run_rag_debug(query=args.query, top_k=args.top_k))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
