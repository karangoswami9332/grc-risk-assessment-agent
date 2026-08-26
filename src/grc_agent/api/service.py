"""Application service: persist assessments and score risks via RiskEngine."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from grc_agent.api.schemas import (
    AssessmentCreate,
    AssessmentList,
    AssessmentRead,
    AssessmentSummary,
    AssetCreate,
    AssetRead,
    ControlCreate,
    ControlRead,
    RiskCreate,
    RiskRead,
    ThreatCreate,
    ThreatRead,
    VulnerabilityCreate,
    VulnerabilityRead,
)
from grc_agent.db.repository import AssessmentRepository
from grc_agent.db.tables import (
    AssessmentRow,
    AssetRow,
    ControlRow,
    RiskRow,
    ThreatRow,
    VulnerabilityRow,
)
from grc_agent.engine.risk_engine import RiskEngine
from grc_agent.models.enums import (
    AssetCriticality,
    ControlEffectiveness,
    RiskTreatment,
    ThreatCategory,
    VulnerabilitySeverity,
)


class AssessmentNotFoundError(Exception):
    def __init__(self, assessment_id: str) -> None:
        super().__init__(assessment_id)
        self.assessment_id = assessment_id


def _new_id(provided: str | None) -> str:
    return provided.strip() if provided else str(uuid.uuid4())


class AssessmentService:
    """Orchestrates repository + RiskEngine. FastAPI stays a thin HTTP adapter."""

    def __init__(self, session: Session, risk_engine: RiskEngine | None = None) -> None:
        self._repo = AssessmentRepository(session)
        self._risk_engine = risk_engine or RiskEngine()

    def create_assessment(self, payload: AssessmentCreate) -> AssessmentRead:
        row = AssessmentRow(
            id=str(uuid.uuid4()),
            title=payload.title,
            scenario=payload.scenario,
            environment_notes=payload.environment_notes,
        )
        for asset in payload.assets:
            row.assets.append(self._asset_row(row.id, asset))
        for threat in payload.threats:
            row.threats.append(self._threat_row(row.id, threat))
        for vulnerability in payload.vulnerabilities:
            row.vulnerabilities.append(self._vulnerability_row(row.id, vulnerability))
        for control in payload.controls:
            row.controls.append(self._control_row(row.id, control))
        for risk in payload.risks:
            row.risks.append(self._risk_row(row.id, risk))
        stored = self._repo.add_assessment(row)
        loaded = self._repo.get_assessment(stored.id)
        if loaded is None:
            # Internal persistence invariant — not an AssessmentNotFoundError (client 404).
            raise RuntimeError("Assessment could not be reloaded after create")
        return self._to_assessment_read(loaded)

    def get_assessment(self, assessment_id: str) -> AssessmentRead:
        row = self._repo.get_assessment(assessment_id)
        if row is None:
            raise AssessmentNotFoundError(assessment_id)
        return self._to_assessment_read(row)

    def list_assessments(self) -> AssessmentList:
        rows = self._repo.list_assessments()
        return AssessmentList(
            items=[
                AssessmentSummary(id=row.id, title=row.title, scenario=row.scenario)
                for row in rows
            ]
        )

    def add_asset(self, assessment_id: str, payload: AssetCreate) -> AssetRead:
        self._require_assessment(assessment_id)
        row = self._repo.add_asset(self._asset_row(assessment_id, payload))
        return self._to_asset_read(row)

    def add_threat(self, assessment_id: str, payload: ThreatCreate) -> ThreatRead:
        self._require_assessment(assessment_id)
        row = self._repo.add_threat(self._threat_row(assessment_id, payload))
        return self._to_threat_read(row)

    def add_vulnerability(self, assessment_id: str, payload: VulnerabilityCreate) -> VulnerabilityRead:
        self._require_assessment(assessment_id)
        row = self._repo.add_vulnerability(self._vulnerability_row(assessment_id, payload))
        return self._to_vulnerability_read(row)

    def add_control(self, assessment_id: str, payload: ControlCreate) -> ControlRead:
        self._require_assessment(assessment_id)
        row = self._repo.add_control(self._control_row(assessment_id, payload))
        return self._to_control_read(row)

    def add_risk(self, assessment_id: str, payload: RiskCreate) -> RiskRead:
        self._require_assessment(assessment_id)
        row = self._repo.add_risk(self._risk_row(assessment_id, payload))
        return self._to_risk_read(row)

    def list_risks(self, assessment_id: str) -> list[RiskRead]:
        self._require_assessment(assessment_id)
        return [self._to_risk_read(row) for row in self._repo.list_risks(assessment_id)]

    def _require_assessment(self, assessment_id: str) -> AssessmentRow:
        row = self._repo.get_assessment(assessment_id)
        if row is None:
            raise AssessmentNotFoundError(assessment_id)
        return row

    def _asset_row(self, assessment_id: str, payload: AssetCreate) -> AssetRow:
        return AssetRow(
            id=_new_id(payload.id),
            assessment_id=assessment_id,
            name=payload.name,
            description=payload.description,
            criticality=payload.criticality.value,
        )

    def _threat_row(self, assessment_id: str, payload: ThreatCreate) -> ThreatRow:
        return ThreatRow(
            id=_new_id(payload.id),
            assessment_id=assessment_id,
            name=payload.name,
            description=payload.description,
            category=payload.category.value,
            asset_ids=list(payload.asset_ids),
        )

    def _vulnerability_row(self, assessment_id: str, payload: VulnerabilityCreate) -> VulnerabilityRow:
        return VulnerabilityRow(
            id=_new_id(payload.id),
            assessment_id=assessment_id,
            name=payload.name,
            description=payload.description,
            severity=payload.severity.value,
            asset_ids=list(payload.asset_ids),
        )

    def _control_row(self, assessment_id: str, payload: ControlCreate) -> ControlRow:
        return ControlRow(
            id=_new_id(payload.id),
            assessment_id=assessment_id,
            name=payload.name,
            description=payload.description,
            effectiveness=payload.effectiveness.value,
        )

    def _risk_row(self, assessment_id: str, payload: RiskCreate) -> RiskRow:
        inherent = self._risk_engine.calculate_inherent_risk(payload.likelihood, payload.impact)
        return RiskRow(
            id=_new_id(payload.id),
            assessment_id=assessment_id,
            title=payload.title,
            description=payload.description,
            likelihood=inherent.likelihood,
            impact=inherent.impact,
            risk_score=inherent.risk_score,
            risk_rating=inherent.risk_rating.value,
            asset_ids=list(payload.asset_ids),
            threat_ids=list(payload.threat_ids),
            vulnerability_ids=list(payload.vulnerability_ids),
            control_ids=list(payload.control_ids),
            treatment=payload.treatment.value if payload.treatment else None,
        )

    def _to_assessment_read(self, row: AssessmentRow) -> AssessmentRead:
        return AssessmentRead(
            id=row.id,
            title=row.title,
            scenario=row.scenario,
            environment_notes=row.environment_notes,
            assets=[self._to_asset_read(item) for item in row.assets],
            threats=[self._to_threat_read(item) for item in row.threats],
            vulnerabilities=[self._to_vulnerability_read(item) for item in row.vulnerabilities],
            controls=[self._to_control_read(item) for item in row.controls],
            risks=[self._to_risk_read(item) for item in row.risks],
        )

    def _to_asset_read(self, row: AssetRow) -> AssetRead:
        return AssetRead(
            id=row.id,
            name=row.name,
            description=row.description,
            criticality=AssetCriticality(row.criticality),
        )

    def _to_threat_read(self, row: ThreatRow) -> ThreatRead:
        return ThreatRead(
            id=row.id,
            name=row.name,
            description=row.description,
            category=ThreatCategory(row.category),
            asset_ids=list(row.asset_ids or []),
        )

    def _to_vulnerability_read(self, row: VulnerabilityRow) -> VulnerabilityRead:
        return VulnerabilityRead(
            id=row.id,
            name=row.name,
            description=row.description,
            severity=VulnerabilitySeverity(row.severity),
            asset_ids=list(row.asset_ids or []),
        )

    def _to_control_read(self, row: ControlRow) -> ControlRead:
        return ControlRead(
            id=row.id,
            name=row.name,
            description=row.description,
            effectiveness=ControlEffectiveness(row.effectiveness),
        )

    def _to_risk_read(self, row: RiskRow) -> RiskRead:
        inherent = self._risk_engine.calculate_inherent_risk(row.likelihood, row.impact)
        return RiskRead(
            id=row.id,
            title=row.title,
            description=row.description,
            likelihood=inherent.likelihood,
            impact=inherent.impact,
            risk_score=inherent.risk_score,
            risk_rating=inherent.risk_rating,
            asset_ids=list(row.asset_ids or []),
            threat_ids=list(row.threat_ids or []),
            vulnerability_ids=list(row.vulnerability_ids or []),
            control_ids=list(row.control_ids or []),
            treatment=RiskTreatment(row.treatment) if row.treatment else None,
        )
