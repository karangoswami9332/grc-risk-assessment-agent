"""Offline security tests: malformed LLM output fails safely."""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
from fastapi.testclient import TestClient

from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.api.app import create_app
from grc_agent.config import Settings
from grc_agent.llm.errors import OllamaResponseError, OllamaUnavailableError

from tests.security.helpers import (
    FakeHttpResponse,
    ollama_http_body,
    patch_ollama_urlopen,
    patch_ollama_urlopen_side_effect,
    proposal_dict,
)

SCENARIO = "Malformed LLM output security scenario."


def test_invalid_json_content_raises_response_error() -> None:
    """Offline: non-JSON assistant content → OllamaResponseError."""
    with patch_ollama_urlopen(ollama_http_body("not-json {{{")):
        with pytest.raises(OllamaResponseError, match="not valid JSON"):
            OllamaRiskAgent().propose(SCENARIO)


def test_empty_string_content_raises_response_error() -> None:
    """Offline: empty content fails safely."""
    with patch_ollama_urlopen(ollama_http_body("")):
        with pytest.raises(OllamaResponseError):
            OllamaRiskAgent().propose(SCENARIO)


def test_missing_required_risk_fields_rejected() -> None:
    """Offline: missing rationale / relationship ids rejected."""
    bad = proposal_dict()
    del bad["risks"][0]["rationale"]
    with patch_ollama_urlopen(ollama_http_body(bad)):
        with pytest.raises(OllamaResponseError):
            OllamaRiskAgent().propose(SCENARIO)


def test_invalid_enum_value_rejected() -> None:
    """Offline: invalid criticality enum fails validation."""
    bad = proposal_dict()
    bad["assets"][0]["criticality"] = "ultra-critical"
    with patch_ollama_urlopen(ollama_http_body(bad)):
        with pytest.raises(OllamaResponseError):
            OllamaRiskAgent().propose(SCENARIO)


def test_unexpected_top_level_structure_rejected() -> None:
    """Offline: array / non-object JSON is rejected."""
    with patch_ollama_urlopen(ollama_http_body([{"risks": []}])):
        with pytest.raises(OllamaResponseError):
            OllamaRiskAgent().propose(SCENARIO)


def test_dangling_relationship_ids_rejected() -> None:
    """Offline: risk referencing unknown threat id fails."""
    bad = proposal_dict()
    bad["risks"][0]["threat_ids"] = ["threat-does-not-exist"]
    with patch_ollama_urlopen(ollama_http_body(bad)):
        with pytest.raises(OllamaResponseError):
            OllamaRiskAgent().propose(SCENARIO)


def test_out_of_range_likelihood_rejected() -> None:
    """Offline: likelihood outside 1–5 fails."""
    bad = proposal_dict()
    bad["risks"][0]["likelihood"] = 9
    with patch_ollama_urlopen(ollama_http_body(bad)):
        with pytest.raises(OllamaResponseError):
            OllamaRiskAgent().propose(SCENARIO)


def test_url_error_is_unavailable() -> None:
    """Offline: connection failure → OllamaUnavailableError (no crash)."""
    with patch_ollama_urlopen_side_effect(URLError("connection refused")):
        with pytest.raises(OllamaUnavailableError, match="unavailable"):
            OllamaRiskAgent().propose(SCENARIO)


def test_http_error_is_unavailable() -> None:
    """Offline: HTTP 500 from Ollama → OllamaUnavailableError."""
    error = HTTPError(
        url="http://127.0.0.1:11434/api/chat",
        code=500,
        msg="Internal Server Error",
        hdrs=None,
        fp=BytesIO(b""),
    )
    with patch_ollama_urlopen_side_effect(error):
        with pytest.raises(OllamaUnavailableError, match="HTTP error 500"):
            OllamaRiskAgent().propose(SCENARIO)


def test_api_maps_malformed_llm_json_to_502(tmp_path: Path) -> None:
    """Offline: API returns controlled 502 for bad LLM JSON (no traceback)."""
    app = create_app(
        Settings(
            database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}",
            risk_agent="ollama",
            rag_enabled=False,
        )
    )
    with patch_ollama_urlopen(ollama_http_body("{{{")):
        response = TestClient(app).post("/risk-assessments", json={"scenario": SCENARIO})
    assert response.status_code == 502
    body = response.json()
    assert "detail" in body
    assert isinstance(body["detail"], str)
    assert "Traceback" not in body["detail"]
    assert "File \"" not in body["detail"]


def test_api_maps_ollama_unavailable_to_503(tmp_path: Path) -> None:
    """Offline: API returns controlled 503 when Ollama cannot be reached."""
    app = create_app(
        Settings(
            database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}",
            risk_agent="ollama",
            rag_enabled=False,
        )
    )
    with patch_ollama_urlopen_side_effect(URLError("connection refused")):
        response = TestClient(app).post("/risk-assessments", json={"scenario": SCENARIO})
    assert response.status_code == 503
    body = response.json()
    assert "detail" in body
    assert "Traceback" not in json.dumps(body)
