"""Non-destructive SQLite ownership-column migration tests."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from grc_agent.api.schemas import AssessmentCreate
from grc_agent.api.service import AssessmentService
from grc_agent.auth.models import Principal, Role
from grc_agent.db.session import create_db_engine, ensure_assessment_ownership_columns, init_db
from grc_agent.db.tables import Base


def test_fresh_database_has_ownership_columns(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}"
    engine = init_db(create_db_engine(url))
    columns = {c["name"] for c in inspect(engine).get_columns("assessments")}
    assert {"tenant_id", "owner_subject"} <= columns


def test_old_schema_upgraded_non_destructively(tmp_path: Path) -> None:
    """Pre-auth SQLite DB gains ownership columns; existing rows keep data + defaults."""
    path = tmp_path / "legacy.db"
    url = f"sqlite:///{path.as_posix()}"
    engine = create_engine(url, future=True)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE assessments (
                    id VARCHAR(36) PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    scenario TEXT NOT NULL,
                    environment_notes TEXT NOT NULL DEFAULT '',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                "INSERT INTO assessments (id, title, scenario, environment_notes) "
                "VALUES ('legacy-1', 'Legacy', 'Old scenario', '')"
            )
        )

    before = {c["name"] for c in inspect(engine).get_columns("assessments")}
    assert "tenant_id" not in before
    assert "owner_subject" not in before

    added = ensure_assessment_ownership_columns(engine)
    assert set(added) == {"tenant_id", "owner_subject"}

    after = {c["name"] for c in inspect(engine).get_columns("assessments")}
    assert {"tenant_id", "owner_subject"} <= after

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT id, title, scenario, tenant_id, owner_subject "
                "FROM assessments WHERE id = 'legacy-1'"
            )
        ).one()
    assert row.title == "Legacy"
    assert row.scenario == "Old scenario"
    assert row.tenant_id == "local"
    assert row.owner_subject == "local"


def test_init_db_upgrades_legacy_and_supports_new_writes(tmp_path: Path) -> None:
    path = tmp_path / "legacy2.db"
    url = f"sqlite:///{path.as_posix()}"
    raw = create_engine(url, future=True)
    with raw.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE assessments (
                    id VARCHAR(36) PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    scenario TEXT NOT NULL,
                    environment_notes TEXT NOT NULL DEFAULT '',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                "INSERT INTO assessments (id, title, scenario, environment_notes) "
                "VALUES ('legacy-2', 'Keep Me', 'Scenario', '')"
            )
        )
    raw.dispose()

    engine = init_db(create_db_engine(url))
    # Remaining related tables created; ownership columns present.
    assert "assets" in inspect(engine).get_table_names()
    columns = {c["name"] for c in inspect(engine).get_columns("assessments")}
    assert {"tenant_id", "owner_subject"} <= columns

    with Session(engine) as session:
        service = AssessmentService(session)
        principal = Principal(subject="alice", role=Role.ASSESSOR, tenant_id="tenant-a")
        created = service.create_assessment(
            AssessmentCreate(title="New", scenario="After migration"),
            principal,
        )
        session.commit()
        assert created.tenant_id == "tenant-a"
        assert created.owner_subject == "alice"
        loaded = service.get_assessment(created.id, principal)
        assert loaded.tenant_id == "tenant-a"

        # Legacy row still readable for admin / local principal
        legacy = service.get_assessment("legacy-2")
        assert legacy.title == "Keep Me"
        assert legacy.tenant_id == "local"


def test_create_all_idempotent_with_ownership_columns(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'idem.db').as_posix()}"
    engine = init_db(create_db_engine(url))
    assert ensure_assessment_ownership_columns(engine) == []
    Base.metadata.create_all(engine)
    assert ensure_assessment_ownership_columns(engine) == []
