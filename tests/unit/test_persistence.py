"""Persistence tests using a temporary SQLite file (not data/grc_agent.db)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import update

from grc_agent.api.schemas import AssessmentCreate, RiskCreate
from grc_agent.api.service import AssessmentNotFoundError, AssessmentService
from grc_agent.config import Settings
from grc_agent.db.session import create_db_engine, init_db, make_session_factory, table_names
from grc_agent.db.tables import RiskRow
from grc_agent.models.enums import RiskRating


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'phase2.db').as_posix()}"


def test_init_db_creates_expected_tables(db_url: str) -> None:
    engine = init_db(create_db_engine(db_url))
    names = table_names(engine)
    assert names >= {
        "assessments",
        "assets",
        "threats",
        "vulnerabilities",
        "controls",
        "risks",
    }


def test_create_and_get_assessment_across_sessions(db_url: str) -> None:
    engine = init_db(create_db_engine(db_url))
    factory = make_session_factory(engine)

    with factory() as session:
        service = AssessmentService(session)
        created = service.create_assessment(
            AssessmentCreate(title="Portal review", scenario="Public web portal with PII.")
        )
        session.commit()
        assessment_id = created.id

    with factory() as session:
        service = AssessmentService(session)
        loaded = service.get_assessment(assessment_id)

    assert loaded.id == assessment_id
    assert loaded.title == "Portal review"


def test_list_assessments(db_url: str) -> None:
    engine = init_db(create_db_engine(db_url))
    factory = make_session_factory(engine)
    with factory() as session:
        service = AssessmentService(session)
        service.create_assessment(AssessmentCreate(title="A", scenario="Scenario A"))
        service.create_assessment(AssessmentCreate(title="B", scenario="Scenario B"))
        session.commit()
        listed = service.list_assessments()
    assert {item.title for item in listed.items} == {"A", "B"}


def test_create_risk_uses_risk_engine(db_url: str) -> None:
    engine = init_db(create_db_engine(db_url))
    factory = make_session_factory(engine)
    with factory() as session:
        service = AssessmentService(session)
        assessment = service.create_assessment(
            AssessmentCreate(title="A", scenario="Scenario")
        )
        risk = service.add_risk(
            assessment.id,
            RiskCreate(title="Account takeover", likelihood=4, impact=5),
        )
        session.commit()

    assert risk.risk_score == 20
    assert risk.risk_rating == RiskRating.CRITICAL


def test_read_path_does_not_trust_stored_score(db_url: str) -> None:
    engine = init_db(create_db_engine(db_url))
    factory = make_session_factory(engine)
    with factory() as session:
        service = AssessmentService(session)
        assessment = service.create_assessment(
            AssessmentCreate(
                title="A",
                scenario="Scenario",
                risks=[RiskCreate(title="R", likelihood=4, impact=5)],
            )
        )
        session.commit()
        risk_id = assessment.risks[0].id

    with factory() as session:
        session.execute(
            update(RiskRow)
            .where(RiskRow.id == risk_id)
            .values(risk_score=1, risk_rating="low")
        )
        session.commit()

    with factory() as session:
        service = AssessmentService(session)
        loaded = service.get_assessment(assessment.id)

    assert loaded.risks[0].risk_score == 20
    assert loaded.risks[0].risk_rating == RiskRating.CRITICAL


def test_missing_assessment_raises(db_url: str) -> None:
    engine = init_db(create_db_engine(db_url))
    factory = make_session_factory(engine)
    with factory() as session:
        service = AssessmentService(session)
        with pytest.raises(AssessmentNotFoundError):
            service.get_assessment("does-not-exist")


def test_settings_default_points_at_local_sqlite() -> None:
    settings = Settings()
    assert "grc_agent.db" in settings.database_url
    assert settings.database_url.startswith("sqlite:///")
