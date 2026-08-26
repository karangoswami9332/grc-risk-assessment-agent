"""SQLite engine and schema bootstrap. Independent of FastAPI and RiskEngine."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from grc_agent.config import DEFAULT_SQLITE_PATH, Settings, get_settings
from grc_agent.db.tables import Base


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


def init_db(engine: Engine | None = None) -> Engine:
    """Create tables if they do not exist. Returns the engine used."""
    db_engine = engine or create_db_engine()
    ensure_sqlite_directory(str(db_engine.url))
    Base.metadata.create_all(db_engine)
    return db_engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def table_names(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def default_sqlite_path() -> Path:
    return DEFAULT_SQLITE_PATH


def settings_from_optional(settings: Settings | None) -> Settings:
    return settings or get_settings()
