"""Offline security tests: RiskEngine remains authoritative for scores/ratings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.agents.proposals import ProposedRisk
from grc_agent.api.app import create_app
from grc_agent.config import Settings
from grc_agent.engine import RiskEngine
from grc_agent.llm.errors import OllamaResponseError
from grc_agent.models.enums import RiskRating
from grc_agent.orchestrator import RiskOrchestrator
from grc_agent.rag.embeddings import FakeEmbedder

from tests.security.helpers import (
    SelectingAgent,
    ollama_http_body,
    patch_ollama_urlopen,
    proposal_dict,
)


def test_proposal_schema_rejects_llm_supplied_risk_score_fields() -> None:
    """Offline: RiskProposal/ProposedRisk forbid risk_score and risk_rating."""
    with pytest.raises(ValidationError):
        ProposedRisk.model_validate(
            {
                "id": "risk-1",
                "title": "Manipulated risk",
                "likelihood": 1,
                "impact": 1,
                "rationale": "Attacker tries to force a low score.",
                "asset_ids": ["asset-1"],
                "threat_ids": ["threat-1"],
                "vulnerability_ids": ["vuln-1"],
                "risk_score": 1,
                "risk_rating": "low",
            }
        )


def test_ollama_agent_rejects_score_fields_in_model_json() -> None:
    """Offline: mocked Ollama returning score fields → OllamaResponseError."""
    tainted = proposal_dict()
    tainted["risks"][0]["risk_score"] = 1
    tainted["risks"][0]["risk_rating"] = "low"
    with patch_ollama_urlopen(ollama_http_body(tainted)):
        with pytest.raises(OllamaResponseError, match="risk_score"):
            OllamaRiskAgent().propose("Score manipulation scenario.")


def test_engine_score_ignores_agent_desire_for_artificially_low_score() -> None:
    """Offline: agent can propose low L/I, but engine product is still authoritative."""
    agent = SelectingAgent([], likelihood=1, impact=1)
    result = RiskOrchestrator(agent, RiskEngine()).assess("Try to force residual score 1.")
    inherent = result.scored_risks[0].inherent_risk
    expected = RiskEngine().calculate_inherent_risk(1, 1)
    assert inherent.risk_score == expected.risk_score == 1
    assert inherent.risk_rating == expected.risk_rating == RiskRating.LOW
    assert inherent.risk_score == inherent.likelihood * inherent.impact


def test_engine_score_for_high_proposal_is_still_likelihood_times_impact() -> None:
    """Offline: high L/I still yields engine product, not an LLM-invented band."""
    agent = SelectingAgent([], likelihood=5, impact=5)
    result = RiskOrchestrator(agent, RiskEngine()).assess("High severity scenario.")
    inherent = result.scored_risks[0].inherent_risk
    assert inherent.risk_score == 25
    assert inherent.risk_rating == RiskRating.CRITICAL


def test_api_request_cannot_override_score_or_rating(tmp_path: Path) -> None:
    """Offline: client-supplied risk_score/risk_rating on request are rejected (422)."""
    url = f"sqlite:///{(tmp_path / 'sec.db').as_posix()}"
    client = TestClient(create_app(Settings(database_url=url)))
    response = client.post(
        "/risk-assessments",
        json={
            "scenario": "Portal stores PII without MFA.",
            "risk_score": 1,
            "risk_rating": "low",
        },
    )
    assert response.status_code == 422
    body = client.post(
        "/risk-assessments",
        json={"scenario": "Portal stores PII without MFA."},
    ).json()
    assert body["risk_score"] == 20
    assert body["risk_rating"] == "critical"


def test_api_mocked_ollama_cannot_smuggle_score_fields(tmp_path: Path) -> None:
    """Offline: API with Ollama agent rejects score-tainted JSON via 502."""
    app = create_app(
        Settings(
            database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}",
            risk_agent="ollama",
            rag_enabled=False,
        ),
        rag_embedder=FakeEmbedder(),
    )
    tainted = proposal_dict()
    tainted["risks"][0]["risk_score"] = 99
    tainted["risks"][0]["risk_rating"] = "low"

    with patch_ollama_urlopen(ollama_http_body(tainted)):
        response = TestClient(app).post(
            "/risk-assessments",
            json={"scenario": "Attempt to force risk_score=99."},
        )

    assert response.status_code == 502
    detail = json.dumps(response.json()).lower()
    assert "risk_score" in detail or "rejected" in detail
    assert "traceback" not in detail
