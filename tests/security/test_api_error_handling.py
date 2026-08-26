"""Offline security tests: API returns controlled errors, not stack traces."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from grc_agent.api.app import create_app
from grc_agent.config import Settings


def _client(tmp_path: Path) -> TestClient:
    return TestClient(
        create_app(Settings(database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}"))
    )


def test_missing_scenario_returns_422_without_traceback(tmp_path: Path) -> None:
    """Offline: missing body field → 422 FastAPI validation error."""
    response = _client(tmp_path).post("/risk-assessments", json={})
    assert response.status_code == 422
    body = response.json()
    assert "detail" in body
    assert "Traceback" not in response.text
    assert "orchestrator" not in response.text.lower()
    assert "riskengine" not in response.text.replace("_", "").lower()


def test_wrong_type_scenario_returns_422(tmp_path: Path) -> None:
    """Offline: non-string scenario → 422."""
    response = _client(tmp_path).post("/risk-assessments", json={"scenario": 12345})
    assert response.status_code == 422
    assert "Traceback" not in response.text
    assert isinstance(response.json()["detail"], list)


def test_malformed_json_body_returns_422(tmp_path: Path) -> None:
    """Offline: invalid JSON body → controlled 422."""
    response = _client(tmp_path).post(
        "/risk-assessments",
        content="{not-json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "Traceback" not in response.text


def test_unknown_assessment_returns_404_without_internals(tmp_path: Path) -> None:
    """Offline: missing assessment id → 404 with safe detail string."""
    response = _client(tmp_path).get("/assessments/does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert body == {"detail": "Assessment 'does-not-exist' was not found"}
    assert "Traceback" not in response.text
    assert "sqlalchemy" not in response.text.lower()


def test_extra_forbidden_fields_return_422(tmp_path: Path) -> None:
    """Offline: unexpected request fields are rejected without leaking stack frames."""
    response = _client(tmp_path).post(
        "/risk-assessments",
        json={
            "scenario": "Valid scenario text.",
            "mapped_controls": [{"control_id": "CTRL-CLD-001", "name": "spoof"}],
            "debug": True,
        },
    )
    assert response.status_code == 422
    dumped = json.dumps(response.json()).lower()
    assert "traceback" not in dumped
    assert 'file "' not in dumped
