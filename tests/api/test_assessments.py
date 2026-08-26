"""FastAPI tests against a temporary SQLite database."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from grc_agent.api.app import create_app
from grc_agent.config import Settings


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(Settings(database_url=url))
    return TestClient(app)


def test_create_and_get_assessment(client: TestClient) -> None:
    created = client.post(
        "/assessments",
        json={"title": "Customer portal", "scenario": "Internet-facing app stores PII."},
    )
    assert created.status_code == 201
    body = created.json()
    assessment_id = body["id"]
    assert body["title"] == "Customer portal"
    assert body["risks"] == []

    fetched = client.get(f"/assessments/{assessment_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == assessment_id


def test_list_assessments(client: TestClient) -> None:
    client.post("/assessments", json={"title": "One", "scenario": "Scenario one"})
    client.post("/assessments", json={"title": "Two", "scenario": "Scenario two"})
    listed = client.get("/assessments")
    assert listed.status_code == 200
    titles = {item["title"] for item in listed.json()["items"]}
    assert titles == {"One", "Two"}


def test_add_risk_scores_with_engine(client: TestClient) -> None:
    created = client.post(
        "/assessments",
        json={"title": "A", "scenario": "Scenario"},
    )
    assessment_id = created.json()["id"]
    risk = client.post(
        f"/assessments/{assessment_id}/risks",
        json={"title": "Unauthorized access", "likelihood": 4, "impact": 5},
    )
    assert risk.status_code == 201
    payload = risk.json()
    assert payload["risk_score"] == 20
    assert payload["risk_rating"] == "critical"
    assert "risk_score" in payload

    listed = client.get(f"/assessments/{assessment_id}/risks")
    assert listed.status_code == 200
    assert listed.json()[0]["risk_score"] == 20


def test_cannot_override_score_in_request(client: TestClient) -> None:
    created = client.post("/assessments", json={"title": "A", "scenario": "Scenario"})
    assessment_id = created.json()["id"]
    response = client.post(
        f"/assessments/{assessment_id}/risks",
        json={
            "title": "Unauthorized access",
            "likelihood": 4,
            "impact": 5,
            "risk_score": 1,
            "risk_rating": "low",
        },
    )
    assert response.status_code == 422


def test_invalid_likelihood(client: TestClient) -> None:
    created = client.post("/assessments", json={"title": "A", "scenario": "Scenario"})
    assessment_id = created.json()["id"]
    response = client.post(
        f"/assessments/{assessment_id}/risks",
        json={"title": "Bad scale", "likelihood": 0, "impact": 5},
    )
    assert response.status_code == 422


def test_invalid_impact(client: TestClient) -> None:
    created = client.post("/assessments", json={"title": "A", "scenario": "Scenario"})
    assessment_id = created.json()["id"]
    response = client.post(
        f"/assessments/{assessment_id}/risks",
        json={"title": "Bad scale", "likelihood": 3, "impact": 6},
    )
    assert response.status_code == 422


def test_unknown_assessment_returns_404(client: TestClient) -> None:
    response = client.get("/assessments/missing-id")
    assert response.status_code == 404
    missing_risk = client.post(
        "/assessments/missing-id/risks",
        json={"title": "R", "likelihood": 2, "impact": 2},
    )
    assert missing_risk.status_code == 404


def test_nested_create_persists_children(client: TestClient) -> None:
    response = client.post(
        "/assessments",
        json={
            "title": "Full",
            "scenario": "Described process",
            "assets": [{"name": "Portal", "criticality": "high"}],
            "risks": [{"title": "R", "likelihood": 1, "impact": 4}],
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["assets"][0]["name"] == "Portal"
    assert body["risks"][0]["risk_score"] == 4
    assert body["risks"][0]["risk_rating"] == "low"
