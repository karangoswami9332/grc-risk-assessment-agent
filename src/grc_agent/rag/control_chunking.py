"""Control-catalog chunking. Keeps each CTRL-* section atomic when it fits.

Isolated from the general-purpose ``chunk_text`` used for access_control.md.
"""

from __future__ import annotations

import re

from grc_agent.rag.chunking import DEFAULT_OVERLAP, _split_oversized
from grc_agent.rag.types import Chunk

# Catalog sections are ~600–700 chars; keep one control per chunk when it fits.
CONTROL_CATALOG_CHUNK_SIZE = 800

_CONTROL_SECTION = re.compile(
    r"(?=^##\s+CTRL-[A-Z]+-\d+\b)",
    re.MULTILINE,
)
_CONTROL_ID = re.compile(r"CTRL-[A-Z]+-\d+")
_CONTROL_HEADING = re.compile(r"^##\s+(CTRL-[A-Z]+-\d+)\b", re.MULTILINE)


def chunk_control_catalog(
    text: str,
    *,
    source: str = "",
    chunk_size: int = CONTROL_CATALOG_CHUNK_SIZE,
    overlap: int = DEFAULT_OVERLAP,
) -> list[Chunk]:
    """Chunk an Internal GRC Control Catalog markdown document.

    Each ``## CTRL-…`` section is one chunk when ``len(section) <= chunk_size``.
    Oversized sections are split on sentence/word boundaries; every continuation
    piece is prefixed with the Control ID so the relationship is not lost.
    Leading preamble (before the first control) is chunked separately if present.
    """
    if chunk_size < 1:
        raise ValueError("chunk_size must be at least 1")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be >= 0 and < chunk_size")

    body = text.strip()
    if not body:
        return []

    pieces = _control_catalog_pieces(body, chunk_size=chunk_size, overlap=overlap)
    return [
        Chunk(id=f"{source or 'doc'}:{index}", text=piece, source=source)
        for index, piece in enumerate(pieces, start=1)
    ]


def _control_catalog_pieces(text: str, *, chunk_size: int, overlap: int) -> list[str]:
    parts = _CONTROL_SECTION.split(text)
    pieces: list[str] = []
    for part in parts:
        section = part.strip()
        section = re.sub(r"^---\s*", "", section)
        section = re.sub(r"\s*---\s*$", "", section)
        section = section.strip()
        if not section:
            continue
        if not _CONTROL_HEADING.search(section):
            # Preamble before the first control heading.
            if len(section) <= chunk_size:
                pieces.append(section)
            else:
                pieces.extend(_split_oversized(section, chunk_size=chunk_size, overlap=overlap))
            continue
        pieces.extend(_chunk_one_control(section, chunk_size=chunk_size, overlap=overlap))
    return pieces


def _chunk_one_control(section: str, *, chunk_size: int, overlap: int) -> list[str]:
    control_id = _extract_control_id(section)
    if len(section) <= chunk_size:
        return [section]

    body_pieces = _split_oversized(section, chunk_size=chunk_size, overlap=overlap)
    if not control_id:
        return body_pieces

    related: list[str] = []
    for piece in body_pieces:
        if control_id in piece:
            related.append(piece)
            continue
        prefix = f"**Control ID:** {control_id}\n\n"
        # Leave room for the ID prefix when continuing an oversized control.
        max_body = max(chunk_size - len(prefix), 1)
        if len(piece) > max_body:
            piece = piece[:max_body].rsplit(" ", 1)[0] or piece[:max_body]
        related.append(f"{prefix}{piece}".strip())
    return related


def _extract_control_id(section: str) -> str | None:
    heading = _CONTROL_HEADING.search(section)
    if heading:
        return heading.group(1)
    match = _CONTROL_ID.search(section)
    return match.group(0) if match else None
