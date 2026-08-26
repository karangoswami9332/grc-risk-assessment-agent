"""HTTP routes. Scoring is delegated to AssessmentService → RiskEngine."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from grc_agent.api.dependencies import get_risk_engine, get_risk_orchestrator, get_session
from grc_agent.api.schemas import (
    AssessmentCreate,
    AssessmentList,
    AssessmentRead,
    AssetCreate,
    AssetRead,
    ControlCreate,
    ControlRead,
    OrchestratedRiskRead,
    RiskAssessmentRequest,
    RiskAssessmentResponse,
    RiskCreate,
    RiskRead,
    ThreatCreate,
    ThreatRead,
    VulnerabilityCreate,
    VulnerabilityRead,
)
from grc_agent.api.service import AssessmentService
from grc_agent.engine.risk_engine import RiskEngine
from grc_agent.orchestrator import RiskOrchestrator

router = APIRouter()


def get_service(
    session: Session = Depends(get_session),
    risk_engine: RiskEngine = Depends(get_risk_engine),
) -> AssessmentService:
    return AssessmentService(session, risk_engine)


@router.post("/assessments", response_model=AssessmentRead, status_code=201)
def create_assessment(
    payload: AssessmentCreate,
    service: AssessmentService = Depends(get_service),
) -> AssessmentRead:
    return service.create_assessment(payload)


@router.get("/assessments", response_model=AssessmentList)
def list_assessments(service: AssessmentService = Depends(get_service)) -> AssessmentList:
    return service.list_assessments()


@router.get("/assessments/{assessment_id}", response_model=AssessmentRead)
def get_assessment(
    assessment_id: str,
    service: AssessmentService = Depends(get_service),
) -> AssessmentRead:
    return service.get_assessment(assessment_id)


@router.post("/assessments/{assessment_id}/assets", response_model=AssetRead, status_code=201)
def add_asset(
    assessment_id: str,
    payload: AssetCreate,
    service: AssessmentService = Depends(get_service),
) -> AssetRead:
    return service.add_asset(assessment_id, payload)


@router.post("/assessments/{assessment_id}/threats", response_model=ThreatRead, status_code=201)
def add_threat(
    assessment_id: str,
    payload: ThreatCreate,
    service: AssessmentService = Depends(get_service),
) -> ThreatRead:
    return service.add_threat(assessment_id, payload)


@router.post(
    "/assessments/{assessment_id}/vulnerabilities",
    response_model=VulnerabilityRead,
    status_code=201,
)
def add_vulnerability(
    assessment_id: str,
    payload: VulnerabilityCreate,
    service: AssessmentService = Depends(get_service),
) -> VulnerabilityRead:
    return service.add_vulnerability(assessment_id, payload)


@router.post("/assessments/{assessment_id}/controls", response_model=ControlRead, status_code=201)
def add_control(
    assessment_id: str,
    payload: ControlCreate,
    service: AssessmentService = Depends(get_service),
) -> ControlRead:
    return service.add_control(assessment_id, payload)


@router.post("/assessments/{assessment_id}/risks", response_model=RiskRead, status_code=201)
def add_risk(
    assessment_id: str,
    payload: RiskCreate,
    service: AssessmentService = Depends(get_service),
) -> RiskRead:
    return service.add_risk(assessment_id, payload)


@router.get("/assessments/{assessment_id}/risks", response_model=list[RiskRead])
def list_risks(
    assessment_id: str,
    service: AssessmentService = Depends(get_service),
) -> list[RiskRead]:
    return service.list_risks(assessment_id)


@router.post("/risk-assessments", response_model=RiskAssessmentResponse)
def create_risk_assessment(
    payload: RiskAssessmentRequest,
    orchestrator: RiskOrchestrator = Depends(get_risk_orchestrator),
) -> RiskAssessmentResponse:
    """Run RiskAgent + RiskEngine on a free-text scenario. Does not persist."""
    result = orchestrator.assess(payload.scenario)
    if not result.scored_risks:
        raise HTTPException(status_code=422, detail="The agent proposed no risks")

    scored = [
        OrchestratedRiskRead(
            id=item.proposal.id,
            title=item.proposal.title,
            description=item.proposal.description,
            likelihood=item.inherent_risk.likelihood,
            impact=item.inherent_risk.impact,
            rationale=item.proposal.rationale,
            risk_score=item.inherent_risk.risk_score,
            risk_rating=item.inherent_risk.risk_rating,
            asset_ids=item.proposal.asset_ids,
            threat_ids=item.proposal.threat_ids,
            vulnerability_ids=item.proposal.vulnerability_ids,
        )
        for item in result.scored_risks
    ]
    primary = scored[0]
    return RiskAssessmentResponse(
        scenario=result.scenario,
        proposal=result.proposal,
        scored_risks=scored,
        risk_score=primary.risk_score,
        risk_rating=primary.risk_rating,
        rationale=primary.rationale,
        mapped_controls=[
            {"control_id": item.control_id, "name": item.name}
            for item in result.mapped_controls
        ],
    )
