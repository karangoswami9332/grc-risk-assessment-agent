"""Offline security tests: AssessmentService create invariant (Bandit B101)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from grc_agent.api.app import create_app
from grc_agent.api.schemas import AssessmentCreate
from grc_agent.api.service import AssessmentService
from grc_agent.config import Settings
from grc_agent.db.session import create_db_engine, init_db, make_session_factory
from grc_agent.engine import RiskEngine


def test_create_assessment_raises_when_reload_returns_none(tmp_path: Path) -> None:
    """Offline: missing post-create reload raises RuntimeError (not assert)."""
    url = f"sqlite:///{(tmp_path / 'inv.db').as_posix()}"
    engine = init_db(create_db_engine(url))
    SessionLocal = make_session_factory(engine)
    session: Session = SessionLocal()
    try:
        service = AssessmentService(session, RiskEngine())
        with patch.object(service._repo, "get_assessment", return_value=None):
            with pytest.raises(RuntimeError, match="could not be reloaded after create"):
                service.create_assessment(
                    AssessmentCreate(title="Invariant probe", scenario="Scenario text.")
                )
    finally:
        session.close()


def test_create_assessment_success_unchanged(tmp_path: Path) -> None:
    """Offline: happy-path create still returns the persisted assessment."""
    url = f"sqlite:///{(tmp_path / 'ok.db').as_posix()}"
    engine = init_db(create_db_engine(url))
    SessionLocal = make_session_factory(engine)
    session: Session = SessionLocal()
    try:
        service = AssessmentService(session, RiskEngine())
        created = service.create_assessment(
            AssessmentCreate(title="Portal review", scenario="Internet-facing app.")
        )
        assert created.title == "Portal review"
        assert created.scenario == "Internet-facing app."
        assert created.id
    finally:
        session.close()


def test_create_assessment_invariant_failure_api_does_not_leak_internals(
    tmp_path: Path,
) -> None:
    """Offline: unexpected RuntimeError yields controlled 500 without internals."""
    app = create_app(
        Settings(database_url=f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    )

    def boom(*_args, **_kwargs):
        raise RuntimeError("Assessment could not be reloaded after create")

    with patch("grc_agent.api.service.AssessmentService.create_assessment", side_effect=boom):
        response = TestClient(app, raise_server_exceptions=False).post(
            "/assessments",
            json={"title": "x", "scenario": "y"},
        )

    assert response.status_code == 500
    text = response.text
    assert "Traceback" not in text
    assert "Assessment could not be reloaded after create" not in text
    assert "AssessmentService" not in text
    assert "sqlalchemy" not in text.lower()
    # Starlette default unhandled error body (plain text or JSON detail).
    assert "Internal Server Error" in text
