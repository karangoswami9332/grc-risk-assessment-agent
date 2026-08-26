"""Runtime settings. No secrets are required for local SQLite or local Ollama."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SQLITE_PATH = Path("data") / "grc_agent.db"
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"
DEFAULT_RISK_AGENT = "mock"
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"
DEFAULT_OLLAMA_EMBED_MODEL = "nomic-embed-text"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 180
DEFAULT_RAG_ENABLED = False
DEFAULT_RAG_DEBUG = False
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def parse_bool_env(name: str, raw: str | None, *, default: bool) -> bool:
    """Parse a boolean environment variable. Empty or missing uses ``default``."""
    if raw is None:
        return default
    value = raw.strip().lower()
    if not value:
        return default
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be true or false, got {raw!r}")


@dataclass(frozen=True)
class Settings:
    """Process configuration from environment variables."""

    database_url: str = DEFAULT_DATABASE_URL
    risk_agent: str = DEFAULT_RISK_AGENT
    ollama_host: str = DEFAULT_OLLAMA_HOST
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    ollama_embed_model: str = DEFAULT_OLLAMA_EMBED_MODEL
    ollama_timeout_seconds: float = DEFAULT_OLLAMA_TIMEOUT_SECONDS
    rag_enabled: bool = DEFAULT_RAG_ENABLED
    rag_debug: bool = DEFAULT_RAG_DEBUG


def get_settings() -> Settings:
    url = os.environ.get("GRC_DATABASE_URL", DEFAULT_DATABASE_URL).strip()
    agent = os.environ.get("GRC_RISK_AGENT", DEFAULT_RISK_AGENT).strip().lower() or DEFAULT_RISK_AGENT
    if agent not in {"mock", "ollama"}:
        raise ValueError(f"Unknown GRC_RISK_AGENT={agent!r}; use 'mock' or 'ollama'")
    host = os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST).strip() or DEFAULT_OLLAMA_HOST
    model = os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL).strip() or DEFAULT_OLLAMA_MODEL
    embed_model = (
        os.environ.get("OLLAMA_EMBED_MODEL", DEFAULT_OLLAMA_EMBED_MODEL).strip()
        or DEFAULT_OLLAMA_EMBED_MODEL
    )
    timeout_raw = os.environ.get("OLLAMA_TIMEOUT_SECONDS", str(DEFAULT_OLLAMA_TIMEOUT_SECONDS)).strip()
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ValueError(
            f"OLLAMA_TIMEOUT_SECONDS must be a number, got {timeout_raw!r}"
        ) from exc
    if timeout <= 0:
        raise ValueError("OLLAMA_TIMEOUT_SECONDS must be greater than 0")
    rag_enabled = parse_bool_env(
        "GRC_RAG_ENABLED",
        os.environ.get("GRC_RAG_ENABLED"),
        default=DEFAULT_RAG_ENABLED,
    )
    rag_debug = parse_bool_env(
        "GRC_RAG_DEBUG",
        os.environ.get("GRC_RAG_DEBUG"),
        default=DEFAULT_RAG_DEBUG,
    )
    return Settings(
        database_url=url or DEFAULT_DATABASE_URL,
        risk_agent=agent,
        ollama_host=host,
        ollama_model=model,
        ollama_embed_model=embed_model,
        ollama_timeout_seconds=timeout,
        rag_enabled=rag_enabled,
        rag_debug=rag_debug,
    )
