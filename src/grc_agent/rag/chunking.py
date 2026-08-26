"""Plain-text / markdown chunking. No embeddings."""

from __future__ import annotations

import re

from grc_agent.rag.types import Chunk

DEFAULT_CHUNK_SIZE = 400
DEFAULT_OVERLAP = 80

_HEADING_LINE = re.compile(r"^#{1,6}\s+\S")
# Sentence boundary: end punctuation then whitespace before a new sentence.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])(?:\s+|\n+)(?=[\"'(A-Z0-9])")
_WHITESPACE = re.compile(r"\s+")


def chunk_text(
    text: str,
    *,
    source: str = "",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_OVERLAP,
) -> list[Chunk]:
    """Split ``text`` into readable chunks preferring natural boundaries.

    Prefer markdown headings, blank-line paragraphs, then sentences, then
    word boundaries. Never normally splits mid-word. ``overlap`` applies when
    a single oversized unit must be hard-split into multiple windows.

    ``overlap`` must be smaller than ``chunk_size``. Empty input yields no chunks.
    """
    if chunk_size < 1:
        raise ValueError("chunk_size must be at least 1")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be >= 0 and < chunk_size")

    body = text.strip()
    if not body:
        return []

    pieces = _pack_units(_units_from_text(body), chunk_size=chunk_size, overlap=overlap)
    if not pieces:
        return []
    return [
        Chunk(id=f"{source or 'doc'}:{index}", text=piece, source=source)
        for index, piece in enumerate(pieces, start=1)
    ]


def _units_from_text(text: str) -> list[str]:
    """Break text into heading/paragraph units, then sentences if needed later."""
    return _paragraph_blocks(text)


def _paragraph_blocks(text: str) -> list[str]:
    """Split on blank lines and markdown headings (heading starts a new block)."""
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if _HEADING_LINE.match(stripped) and current:
            blocks.append("\n".join(current).strip())
            current = [stripped]
        elif not stripped:
            if current:
                blocks.append("\n".join(current).strip())
                current = []
        else:
            current.append(stripped)
    if current:
        blocks.append("\n".join(current).strip())
    return [block for block in blocks if block]


def _split_sentences(block: str) -> list[str]:
    parts = _SENTENCE_SPLIT.split(block.strip())
    return [part.strip() for part in parts if part.strip()]


def _split_words(unit: str) -> list[str]:
    return [token for token in _WHITESPACE.split(unit.strip()) if token]


def _pack_units(units: list[str], *, chunk_size: int, overlap: int) -> list[str]:
    pieces: list[str] = []
    buffer = ""

    def flush() -> None:
        nonlocal buffer
        text = buffer.strip()
        if text:
            pieces.append(text)
        buffer = ""

    for unit in units:
        # Prefer keeping heading-led sections as separate chunks when possible.
        if buffer and _HEADING_LINE.match(unit.splitlines()[0].strip()):
            flush()

        if len(unit) <= chunk_size:
            candidate = f"{buffer}\n\n{unit}".strip() if buffer else unit
            if len(candidate) <= chunk_size:
                buffer = candidate
            else:
                flush()
                buffer = unit
            continue

        # Oversized unit: flush buffer, then split by sentences / words.
        flush()
        for piece in _split_oversized(unit, chunk_size=chunk_size, overlap=overlap):
            pieces.append(piece)

    flush()
    return pieces


def _split_oversized(unit: str, *, chunk_size: int, overlap: int) -> list[str]:
    sentences = _split_sentences(unit)
    if len(sentences) == 1 and len(sentences[0]) <= chunk_size:
        return sentences

    # Prefer packing sentences; fall back to words / hard split for huge tokens.
    expandable: list[str] = []
    for sentence in sentences:
        if len(sentence) <= chunk_size:
            expandable.append(sentence)
        else:
            expandable.extend(_split_by_words(sentence, chunk_size=chunk_size, overlap=overlap))
    return _pack_small_units(expandable, chunk_size=chunk_size, join=" ")


def _split_by_words(text: str, *, chunk_size: int, overlap: int) -> list[str]:
    words = _split_words(text)
    if not words:
        return []
    if all(len(word) <= chunk_size for word in words):
        return _pack_small_units(words, chunk_size=chunk_size, join=" ")

    # Last resort: a single token longer than chunk_size (no whitespace to use).
    pieces: list[str] = []
    for word in words:
        if len(word) <= chunk_size:
            pieces.extend(_pack_small_units([word], chunk_size=chunk_size, join=" "))
            continue
        start = 0
        while start < len(word):
            end = min(start + chunk_size, len(word))
            pieces.append(word[start:end])
            if end >= len(word):
                break
            start = max(end - overlap, start + 1)
    return pieces


def _pack_small_units(units: list[str], *, chunk_size: int, join: str) -> list[str]:
    pieces: list[str] = []
    buffer = ""
    for unit in units:
        if not unit:
            continue
        if not buffer:
            buffer = unit
            continue
        candidate = f"{buffer}{join}{unit}"
        if len(candidate) <= chunk_size:
            buffer = candidate
        else:
            pieces.append(buffer)
            buffer = unit
    if buffer:
        pieces.append(buffer)
    return pieces
