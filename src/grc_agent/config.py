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
DEFAULT_APP_ENV = "development"
DEFAULT_AUTH_ENABLED = False
DEFAULT_JWT_ALGORITHM = "HS256"
DEFAULT_JWT_ISSUER = ""
DEFAULT_JWT_AUDIENCE = ""
# Empty placeholders only — never commit real secrets. Values come from the environment.
DEFAULT_JWT_SECRET = ""  # nosec B105
DEFAULT_JWT_PUBLIC_KEY = ""
VALID_APP_ENVS = frozenset({"development", "test", "production"})
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
    app_env: str = DEFAULT_APP_ENV
    auth_enabled: bool = DEFAULT_AUTH_ENABLED
    jwt_algorithm: str = DEFAULT_JWT_ALGORITHM
    jwt_issuer: str = DEFAULT_JWT_ISSUER
    jwt_audience: str = DEFAULT_JWT_AUDIENCE
    jwt_secret: str = DEFAULT_JWT_SECRET
    jwt_public_key: str = DEFAULT_JWT_PUBLIC_KEY


def assert_auth_configuration(settings: Settings) -> None:
    """Fail closed for unsafe auth settings (used by get_settings and create_app).

    Production cannot run unauthenticated and must have issuer/audience configured.
    When auth is enabled (any environment), required key material must be present.
    """
    algorithm = (settings.jwt_algorithm or "").strip()
    if not algorithm or algorithm.lower() == "none":
        raise ValueError("JWT_ALGORITHM must not be 'none'")

    if settings.app_env == "production" and not settings.auth_enabled:
        raise ValueError(
            "AUTH_ENABLED must be true when GRC_APP_ENV=production "
            "(unauthenticated production mode is not allowed)"
        )

    if settings.auth_enabled:
        algo = algorithm.upper()
        if algo.startswith("HS") and not (settings.jwt_secret or "").strip():
            raise ValueError(
                "JWT_SECRET is required when AUTH_ENABLED=true and using HS* algorithms"
            )
        if (algo.startswith("RS") or algo.startswith("ES")) and not (
            settings.jwt_public_key or ""
        ).strip():
            raise ValueError(
                "JWT_PUBLIC_KEY is required when AUTH_ENABLED=true and using RS*/ES* algorithms"
            )

    if settings.app_env == "production":
        if not (settings.jwt_issuer or "").strip() or not (settings.jwt_audience or "").strip():
            raise ValueError(
                "JWT_ISSUER and JWT_AUDIENCE are required when GRC_APP_ENV=production"
            )


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
    app_env = (os.environ.get("GRC_APP_ENV", DEFAULT_APP_ENV).strip().lower() or DEFAULT_APP_ENV)
    if app_env not in VALID_APP_ENVS:
        raise ValueError(
            f"Unknown GRC_APP_ENV={app_env!r}; use development, test, or production"
        )

    auth_raw = os.environ.get("AUTH_ENABLED")
    if app_env == "production":
        # Production must not silently fail open when AUTH_ENABLED is omitted.
        if auth_raw is None or not str(auth_raw).strip():
            raise ValueError(
                "AUTH_ENABLED must be explicitly set to true when GRC_APP_ENV=production"
            )
        auth_enabled = parse_bool_env("AUTH_ENABLED", auth_raw, default=False)
        if not auth_enabled:
            raise ValueError(
                "AUTH_ENABLED=false is not allowed when GRC_APP_ENV=production"
            )
    else:
        auth_enabled = parse_bool_env(
            "AUTH_ENABLED",
            auth_raw,
            default=DEFAULT_AUTH_ENABLED,
        )

    jwt_algorithm = (
        os.environ.get("JWT_ALGORITHM", DEFAULT_JWT_ALGORITHM).strip() or DEFAULT_JWT_ALGORITHM
    )
    jwt_issuer = os.environ.get("JWT_ISSUER", DEFAULT_JWT_ISSUER).strip()
    jwt_audience = os.environ.get("JWT_AUDIENCE", DEFAULT_JWT_AUDIENCE).strip()
    jwt_secret = os.environ.get("JWT_SECRET", DEFAULT_JWT_SECRET)
    jwt_public_key = os.environ.get("JWT_PUBLIC_KEY", DEFAULT_JWT_PUBLIC_KEY)
    settings = Settings(
        database_url=url or DEFAULT_DATABASE_URL,
        risk_agent=agent,
        ollama_host=host,
        ollama_model=model,
        ollama_embed_model=embed_model,
        ollama_timeout_seconds=timeout,
        rag_enabled=rag_enabled,
        rag_debug=rag_debug,
        app_env=app_env,
        auth_enabled=auth_enabled,
        jwt_algorithm=jwt_algorithm,
        jwt_issuer=jwt_issuer,
        jwt_audience=jwt_audience,
        jwt_secret=jwt_secret,
        jwt_public_key=jwt_public_key,
    )
    assert_auth_configuration(settings)
    return settings
