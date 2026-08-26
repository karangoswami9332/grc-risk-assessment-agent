"""SQLite engine and schema bootstrap. Independent of FastAPI and RiskEngine."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from grc_agent.config import DEFAULT_SQLITE_PATH, Settings, get_settings
from grc_agent.db.tables import Base

# Columns added after the initial assessments schema (auth / multi-tenant ownership).
_OWNERSHIP_COLUMNS: tuple[tuple[str, str], ...] = (
    ("tenant_id", "VARCHAR(128) NOT NULL DEFAULT 'local'"),
    ("owner_subject", "VARCHAR(255) NOT NULL DEFAULT 'local'"),
)


def sqlite_file_path(database_url: str) -> Path | None:
    """Return the filesystem path for a SQLite URL, if any."""
    if not database_url.startswith("sqlite:///"):
        return None
    raw = database_url.removeprefix("sqlite:///")
    if raw in {":memory:", ""} or raw.startswith("file:"):
        return None
    return Path(raw)


def ensure_sqlite_directory(database_url: str) -> None:
    path = sqlite_file_path(database_url)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)


def create_db_engine(database_url: str | None = None) -> Engine:
    url = database_url or get_settings().database_url
    ensure_sqlite_directory(url)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, future=True, connect_args=connect_args)


def ensure_assessment_ownership_columns(engine: Engine) -> list[str]:
    """Non-destructive migration: add tenant_id / owner_subject if missing.

    Existing rows receive the SQL DEFAULT ('local'). Never drops or rewrites data.
    Returns the list of columns that were added.
    """
    inspector = inspect(engine)
    if "assessments" not in inspector.get_table_names():
        return []
    existing = {col["name"] for col in inspector.get_columns("assessments")}
    added: list[str] = []
    with engine.begin() as connection:
        for name, ddl_type in _OWNERSHIP_COLUMNS:
            if name in existing:
                continue
            # SQLite supports ADD COLUMN; defaults backfill existing rows.
            connection.execute(
                # Column names come only from the fixed _OWNERSHIP_COLUMNS whitelist.
                text(f"ALTER TABLE assessments ADD COLUMN {name} {ddl_type}")  # nosec B608
            )
            added.append(name)
    return added


def init_db(engine: Engine | None = None) -> Engine:
    """Create tables if they do not exist and apply safe ownership-column migration."""
    db_engine = engine or create_db_engine()
    ensure_sqlite_directory(str(db_engine.url))
    Base.metadata.create_all(db_engine)
    ensure_assessment_ownership_columns(db_engine)
    return db_engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def table_names(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def default_sqlite_path() -> Path:
    return DEFAULT_SQLITE_PATH


def settings_from_optional(settings: Settings | None) -> Settings:
    return settings or get_settings()
