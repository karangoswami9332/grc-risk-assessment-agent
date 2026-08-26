"""Request/assessment correlation ID via contextvars."""

from __future__ import annotations

import uuid
from contextvars import ContextVar

CORRELATION_HEADER = "X-Request-ID"
_correlation_id: ContextVar[str | None] = ContextVar("grc_correlation_id", default=None)


def get_correlation_id() -> str | None:
    return _correlation_id.get()


def set_correlation_id(value: str) -> str:
    text = value.strip()
    if not text:
        text = str(uuid.uuid4())
    _correlation_id.set(text)
    return text


def clear_correlation_id() -> None:
    _correlation_id.set(None)


def ensure_correlation_id() -> str:
    """Return the active correlation ID, creating one if the caller has none."""
    current = _correlation_id.get()
    if current:
        return current
    return set_correlation_id(str(uuid.uuid4()))
