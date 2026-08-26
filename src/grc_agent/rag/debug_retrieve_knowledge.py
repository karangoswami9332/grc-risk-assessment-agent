"""Manual verification that data/knowledge/*.md (including controls.md) is retrieved.

Uses the existing ingest/retrieve path. Not used by the API.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from grc_agent.config import Settings, get_settings
from grc_agent.rag.embeddings import Embedder
from grc_agent.rag.ingest import default_knowledge_dir, ingest_knowledge_dir, ollama_embedder_from_settings
from grc_agent.rag.retriever import DEFAULT_TOP_K, Retriever, format_hits
from grc_agent.rag.store import InMemoryVectorStore

DEFAULT_QUERY = (
    "A cloud storage bucket containing confidential financial reports is publicly "
    "accessible because of an incorrect access control configuration."
)
DEFAULT_EXPECTED_CONTROL = "CTRL-AC-001"
_CONTROL_ID_RE = re.compile(r"CTRL-[A-Z]+-\d+")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Diagnostic RAG retrieval over data/knowledge/*.md (real Ollama embeddings)."
    )
    parser.add_argument(
        "--query",
        default=DEFAULT_QUERY,
        help="Free-text scenario / retrieval query",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=DEFAULT_TOP_K,
        help=f"Number of hits to retrieve (default: {DEFAULT_TOP_K})",
    )
    parser.add_argument(
        "--expected-control",
        default=DEFAULT_EXPECTED_CONTROL,
        help="Control ID to summarize as expected (default: CTRL-AC-001)",
    )
    return parser.parse_args(argv)


def run_knowledge_rag_debug(
    *,
    query: str = DEFAULT_QUERY,
    top_k: int = DEFAULT_TOP_K,
    expected_control: str = DEFAULT_EXPECTED_CONTROL,
    knowledge_dir: Path | None = None,
    embedder: Embedder | None = None,
    settings: Settings | None = None,
) -> str:
    """Ingest ``data/knowledge/*.md``, retrieve ``top_k`` hits, and format a report."""
    directory = (knowledge_dir or default_knowledge_dir()).resolve()
    resolved_settings = settings or get_settings()
    resolved_embedder = embedder or ollama_embedder_from_settings(resolved_settings)
    store = InMemoryVectorStore()
    retriever = Retriever(resolved_embedder, store)
    chunks = ingest_knowledge_dir(retriever, directory)
    hits = retriever.retrieve(query, top_k=top_k)
    context = format_hits(hits)

    sources = sorted({chunk.source for chunk in chunks})
    by_source: dict[str, int] = {}
    for chunk in chunks:
        by_source[chunk.source] = by_source.get(chunk.source, 0) + 1

    lines: list[str] = [
        "=== Knowledge-dir RAG verification ===",
        f"knowledge_dir: {directory}",
        f"sources_ingested: {', '.join(sources) if sources else '(none)'}",
        f"chunks_ingested: {len(chunks)}",
        f"store_size: {len(store)}",
        f"chunks_by_source: {by_source}",
        f"ollama_host: {resolved_settings.ollama_host}",
        f"embed_model: {resolved_settings.ollama_embed_model}",
        f"top_k: {len(hits)}",
        "",
        "=== Query ===",
        query,
        "",
    ]

    retrieved_control_ids: list[str] = []
    expected_rank: int | None = None
    expected_score: float | None = None
    if not hits:
        lines.append("=== Results ===")
        lines.append("(no hits)")
    else:
        for index, hit in enumerate(hits, start=1):
            source = hit.chunk.source or hit.chunk.id
            found_ids = list(dict.fromkeys(_CONTROL_ID_RE.findall(hit.chunk.text)))
            for control_id in found_ids:
                if control_id not in retrieved_control_ids:
                    retrieved_control_ids.append(control_id)
            if expected_control in found_ids and expected_rank is None:
                expected_rank = index
                expected_score = hit.score
            contains_ctrl = "YES" if found_ids else "NO"
            lines.extend(
                [
                    f"=== Result {index} ===",
                    f"rank: {index}",
                    f"chunk_id: {hit.chunk.id}",
                    f"similarity_score: {hit.score:.6f}",
                    f"source: {source}",
                    f"contains_ctrl_id: {contains_ctrl}",
                    f"control_ids_in_chunk: {', '.join(found_ids) if found_ids else '(none)'}",
                    "chunk_text:",
                    hit.chunk.text,
                    "",
                ]
            )

    lines.extend(
        [
            "=== Source breakdown (top results) ===",
            f"access_control.md hits: {sum(1 for h in hits if h.chunk.source == 'access_control.md')}",
            f"controls.md hits: {sum(1 for h in hits if h.chunk.source == 'controls.md')}",
            "",
            "=== Control ID summary ===",
            f"control_ids_retrieved: {', '.join(retrieved_control_ids) if retrieved_control_ids else '(none)'}",
            "",
            "=== Expected control ===",
            f"Expected control: {expected_control}",
            f"Retrieved: {'YES' if expected_rank is not None else 'NO'}",
            f"Rank: {expected_rank if expected_rank is not None else 'N/A'}",
            f"Score: {expected_score:.6f}" if expected_score is not None else "Score: N/A",
            "",
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
    print(
        run_knowledge_rag_debug(
            query=args.query,
            top_k=args.top_k,
            expected_control=args.expected_control,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
