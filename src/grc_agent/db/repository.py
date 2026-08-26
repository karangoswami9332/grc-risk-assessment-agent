"""Persistence helpers. Maps SQLAlchemy rows; does not score risks."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from grc_agent.db.tables import (
    AssessmentRow,
    AssetRow,
    ControlRow,
    RiskRow,
    ThreatRow,
    VulnerabilityRow,
)

_ASSESSMENT_LOAD = (
    selectinload(AssessmentRow.assets),
    selectinload(AssessmentRow.threats),
    selectinload(AssessmentRow.vulnerabilities),
    selectinload(AssessmentRow.controls),
    selectinload(AssessmentRow.risks),
)


class AssessmentRepository:
    """CRUD for one assessment graph. Scoring belongs in the application service."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_assessment(self, row: AssessmentRow) -> AssessmentRow:
        self._session.add(row)
        self._session.flush()
        return row

    def get_assessment(self, assessment_id: str) -> AssessmentRow | None:
        stmt = (
            select(AssessmentRow)
            .options(*_ASSESSMENT_LOAD)
            .where(AssessmentRow.id == assessment_id)
        )
        return self._session.scalars(stmt).first()

    def list_assessments(self, *, tenant_id: str | None = None) -> list[AssessmentRow]:
        stmt = select(AssessmentRow).order_by(AssessmentRow.created_at.desc())
        if tenant_id is not None:
            stmt = stmt.where(AssessmentRow.tenant_id == tenant_id)
        return list(self._session.scalars(stmt).all())

    def add_asset(self, row: AssetRow) -> AssetRow:
        self._session.add(row)
        self._session.flush()
        return row

    def add_threat(self, row: ThreatRow) -> ThreatRow:
        self._session.add(row)
        self._session.flush()
        return row

    def add_vulnerability(self, row: VulnerabilityRow) -> VulnerabilityRow:
        self._session.add(row)
        self._session.flush()
        return row

    def add_control(self, row: ControlRow) -> ControlRow:
        self._session.add(row)
        self._session.flush()
        return row

    def add_risk(self, row: RiskRow) -> RiskRow:
        self._session.add(row)
        self._session.flush()
        return row

    def list_risks(self, assessment_id: str) -> list[RiskRow]:
        stmt = select(RiskRow).where(RiskRow.assessment_id == assessment_id)
        return list(self._session.scalars(stmt).all())
