"""Offline security tests: responses must not leak secrets or stack traces."""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError

from fastapi.testclient import TestClient

from grc_agent.api.app import create_app
from grc_agent.config import Settings

from tests.security.helpers import (
    SECRET_MARKERS,
    ollama_http_body,
    patch_ollama_urlopen,
    patch_ollama_urlopen_side_effect,
    proposal_dict,
)

PLANTED_SECRETS = {
    "OPENAI_API_KEY": "sk-proj-SECURITYTEST-DO-NOT-LEAK-12345",
    "ANTHROPIC_API_KEY": "sk-ant-SECURITYTEST-DO-NOT-LEAK",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECURITYTEST",
    "GRC_TEST_PASSWORD": "SuperSecretPassword!99",
}


def _assert_no_secret_leak(payload: object) -> None:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    lower = text.lower()
    for value in PLANTED_SECRETS.values():
        assert value not in text
        assert value.lower() not in lower
    for marker in SECRET_MARKERS:
        assert marker.lower() not in lower
    assert "traceback (most recent call last)" not in lower
    assert 'file "' not in lower


def test_422_validation_errors_do_not_leak_planted_secrets(
    tmp_path: Path, monkeypatch
) -> None:
    """Offline: malformed request 422 bodies exclude env secrets and traces."""
    for key, value in PLANTED_SECRETS.items():
        monkeypatch.setenv(key, value)
    client = TestClient(
        create_app(
            Settings(database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}")
        )
    )
    response = client.post("/risk-assessments", json={"scenario": ""})
    assert response.status_code == 422
    _assert_no_secret_leak(response.json())


def test_502_malformed_llm_response_does_not_leak_secrets(
    tmp_path: Path, monkeypatch
) -> None:
    """Offline: 502 detail must not include planted secrets."""
    for key, value in PLANTED_SECRETS.items():
        monkeypatch.setenv(key, value)
    app = create_app(
        Settings(
            database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}",
            risk_agent="ollama",
            rag_enabled=False,
        )
    )
    with patch_ollama_urlopen(ollama_http_body("not-json")):
        response = TestClient(app).post(
            "/risk-assessments",
            json={"scenario": "Secret leakage probe for malformed LLM output."},
        )
    assert response.status_code == 502
    _assert_no_secret_leak(response.json())


def test_503_unavailable_does_not_leak_planted_secrets(
    tmp_path: Path, monkeypatch
) -> None:
    """Offline: 503 detail must not include planted API keys/passwords."""
    for key, value in PLANTED_SECRETS.items():
        monkeypatch.setenv(key, value)
    app = create_app(
        Settings(
            database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}",
            risk_agent="ollama",
            rag_enabled=False,
        )
    )
    with patch_ollama_urlopen_side_effect(URLError("connection refused")):
        response = TestClient(app).post(
            "/risk-assessments",
            json={"scenario": "Secret leakage probe for unavailable Ollama."},
        )
    assert response.status_code == 503
    _assert_no_secret_leak(response.json())


def test_503_http_error_does_not_embed_planted_secrets(
    tmp_path: Path, monkeypatch
) -> None:
    """Offline: HTTPError path 503 does not echo planted secrets."""
    for key, value in PLANTED_SECRETS.items():
        monkeypatch.setenv(key, value)
    app = create_app(
        Settings(
            database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}",
            risk_agent="ollama",
            rag_enabled=False,
        )
    )
    error = HTTPError(
        url="http://127.0.0.1:11434/api/chat",
        code=500,
        msg="Internal Server Error",
        hdrs=None,
        fp=BytesIO(b""),
    )
    with patch_ollama_urlopen_side_effect(error):
        response = TestClient(app).post(
            "/risk-assessments",
            json={"scenario": "Secret leakage probe for Ollama HTTP 500."},
        )
    assert response.status_code == 503
    _assert_no_secret_leak(response.json())


def test_successful_assessment_response_has_no_secret_markers(
    tmp_path: Path, monkeypatch
) -> None:
    """Offline: happy-path mock assessment body excludes planted secrets."""
    for key, value in PLANTED_SECRETS.items():
        monkeypatch.setenv(key, value)
    client = TestClient(
        create_app(
            Settings(database_url=f"sqlite:///{(tmp_path / 'sec.db').as_posix()}")
        )
    )
    response = client.post(
        "/risk-assessments",
        json={"scenario": "Portal stores PII without MFA."},
    )
    assert response.status_code == 200
    _assert_no_secret_leak(response.json())
    # Score fields exist only as engine outputs, not as leaked config.
    assert "risk_score" in response.json()
    assert response.json()["risk_score"] == 20
