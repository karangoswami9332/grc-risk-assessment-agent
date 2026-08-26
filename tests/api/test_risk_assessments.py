"""API tests for POST /risk-assessments (Phase 3 orchestrator, mock agent)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.api.app import create_app
from grc_agent.config import Settings
from grc_agent.engine import RiskEngine
from grc_agent.rag.embeddings import FakeEmbedder


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(Settings(database_url=url))
    return TestClient(app)


SCENARIO = (
    "A public patient portal stores PHI. Patients log in with password only; MFA is off."
)


def test_valid_scenario_returns_200(client: TestClient) -> None:
    response = client.post("/risk-assessments", json={"scenario": SCENARIO})
    assert response.status_code == 200
    body = response.json()
    assert body["scenario"] == SCENARIO
    assert "proposal" in body
    assert body["proposal"]["risks"]
    assert body["scored_risks"]
    assert body["rationale"]
    assert "risk_score" not in body["proposal"]["risks"][0]


def test_empty_or_invalid_scenario_is_rejected(client: TestClient) -> None:
    assert client.post("/risk-assessments", json={"scenario": ""}).status_code == 422
    assert client.post("/risk-assessments", json={"scenario": "   "}).status_code == 422
    assert client.post("/risk-assessments", json={}).status_code == 422


def test_returned_score_is_calculated_by_risk_engine(client: TestClient) -> None:
    body = client.post("/risk-assessments", json={"scenario": SCENARIO}).json()
    likelihood = body["scored_risks"][0]["likelihood"]
    impact = body["scored_risks"][0]["impact"]
    expected = RiskEngine().calculate_inherent_risk(likelihood, impact)
    assert body["risk_score"] == expected.risk_score
    assert body["risk_rating"] == expected.risk_rating.value
    assert body["scored_risks"][0]["risk_score"] == expected.risk_score
    assert body["scored_risks"][0]["risk_rating"] == expected.risk_rating.value
    assert expected.risk_score == likelihood * impact


def test_caller_cannot_override_score_or_rating(client: TestClient) -> None:
    response = client.post(
        "/risk-assessments",
        json={
            "scenario": SCENARIO,
            "risk_score": 1,
            "risk_rating": "low",
        },
    )
    assert response.status_code == 422
    body = client.post("/risk-assessments", json={"scenario": SCENARIO}).json()
    assert body["risk_score"] == 20
    assert body["risk_rating"] == "critical"


def test_default_app_does_not_attach_retriever(client: TestClient) -> None:
    assert client.app.state.retriever is None
    assert isinstance(client.app.state.risk_agent, MockRiskAgent)


def test_mock_agent_ignores_rag_enabled_flag(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(Settings(database_url=url, risk_agent="mock", rag_enabled=True))
    assert app.state.retriever is None
    assert isinstance(app.state.risk_agent, MockRiskAgent)
    body = TestClient(app).post("/risk-assessments", json={"scenario": SCENARIO}).json()
    assert body["risk_score"] == 20
    assert body["risk_rating"] == "critical"


def test_ollama_without_rag_passes_empty_context(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(Settings(database_url=url, risk_agent="ollama", rag_enabled=False))
    assert app.state.retriever is None
    captured: list[dict] = []

    def fake_urlopen(request, timeout=None):
        captured.append(json.loads(request.data.decode("utf-8")))
        return _FakeHttpResponse(_ollama_http_body(_VALID_PROPOSAL))

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        response = TestClient(app).post("/risk-assessments", json={"scenario": SCENARIO})

    assert response.status_code == 200
    assert captured[0]["messages"][1]["content"] == SCENARIO
    assert "Retrieved GRC context" not in captured[0]["messages"][1]["content"]
    body = response.json()
    assert body["risk_score"] == 20
    assert body["risk_rating"] == "critical"


def test_ollama_with_rag_retrieves_and_passes_context(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(
        Settings(database_url=url, risk_agent="ollama", rag_enabled=True),
        rag_embedder=FakeEmbedder(),
    )
    assert app.state.retriever is not None
    retrieve_calls: list[str] = []
    original = app.state.retriever.retrieve

    def tracking(query: str, *args, **kwargs):
        retrieve_calls.append(query)
        return original(query, *args, **kwargs)

    app.state.retriever.retrieve = tracking  # type: ignore[method-assign]
    captured: list[dict] = []

    def fake_urlopen(request, timeout=None):
        assert request.full_url.endswith("/api/chat")
        captured.append(json.loads(request.data.decode("utf-8")))
        return _FakeHttpResponse(_ollama_http_body(_VALID_PROPOSAL))

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        response = TestClient(app).post("/risk-assessments", json={"scenario": CLOUD_SCENARIO})

    assert response.status_code == 200
    assert retrieve_calls == [CLOUD_SCENARIO]
    user = captured[0]["messages"][1]["content"]
    assert CLOUD_SCENARIO in user
    assert "Retrieved GRC context" in user
    assert "access_control.md" in user
    assert any(term in user.lower() for term in ("cloud", "bucket", "public", "confidential"))
    body = response.json()
    assert body["risk_score"] == 20
    assert body["risk_rating"] == "critical"
    assert "risk_score" not in body["proposal"]["risks"][0]


CLOUD_SCENARIO = (
    "A cloud storage bucket containing confidential financial reports is publicly "
    "accessible because of an incorrect access control configuration."
)

_VALID_PROPOSAL = {
    "assets": [
        {
            "id": "asset-1",
            "name": "Cloud storage bucket",
            "description": "Confidential financial reports",
            "criticality": "high",
        }
    ],
    "threats": [
        {
            "id": "threat-1",
            "name": "Unauthorized user",
            "description": "Public access to confidential reports",
            "category": "unauthorized_access",
            "asset_ids": ["asset-1"],
        }
    ],
    "vulnerabilities": [
        {
            "id": "vuln-1",
            "name": "Public bucket ACL",
            "description": "Incorrect access control configuration",
            "severity": "high",
            "asset_ids": ["asset-1"],
        }
    ],
    "risks": [
        {
            "id": "risk-1",
            "title": "Confidential reports exposed",
            "description": "Public bucket exposes financial reports",
            "likelihood": 4,
            "impact": 5,
            "rationale": "Public cloud storage with confidential data.",
            "asset_ids": ["asset-1"],
            "threat_ids": ["threat-1"],
            "vulnerability_ids": ["vuln-1"],
        }
    ],
}


class _FakeHttpResponse:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _ollama_http_body(content: object) -> dict:
    if isinstance(content, dict):
        content = json.dumps(content)
    return {"message": {"role": "assistant", "content": content}}
