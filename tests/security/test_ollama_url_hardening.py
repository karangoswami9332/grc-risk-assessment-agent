"""Offline security tests: Ollama URL scheme hardening (Bandit B310)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.llm.ollama_client import OllamaChatClient, ensure_http_url
from grc_agent.orchestrator import RiskOrchestrator

from tests.security.helpers import ollama_http_body, patch_ollama_urlopen, proposal_dict


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434/api/chat",
        "http://ollama.example.com:11434/api/embed",
        "https://127.0.0.1:11434/api/chat",
        "https://ollama.internal.example/api/chat",
    ],
)
def test_ensure_http_url_accepts_http_and_https(url: str) -> None:
    """Offline: http and https endpoints are accepted."""
    assert ensure_http_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/model",
        "javascript:alert(1)",
        "data:text/plain,hi",
        "gopher://example.com/1",
        "http://",
        "https://",
        "not-a-url",
        "",
        "   ",
        "/api/chat",
        "127.0.0.1:11434/api/chat",
    ],
)
def test_ensure_http_url_rejects_unsupported_or_malformed(url: str) -> None:
    """Offline: unsupported schemes and malformed URLs raise ValueError."""
    with pytest.raises(ValueError, match="Ollama URL"):
        ensure_http_url(url)


@pytest.mark.parametrize(
    "host",
    [
        "http://127.0.0.1:11434",
        "https://127.0.0.1:11434",
        "http://ollama.example.com:11434",
        "https://ollama.example.com",
    ],
)
def test_ollama_client_accepts_configurable_http_https_hosts(host: str) -> None:
    """Offline: configurable hosts with http/https still construct."""
    client = OllamaChatClient(host=host)
    assert client.host == host.rstrip("/")
    assert client.chat_url.startswith(("http://", "https://"))
    assert client.chat_url.endswith("/api/chat")


@pytest.mark.parametrize(
    "host",
    [
        "file:///tmp",
        "ftp://evil.example",
        "javascript:alert(1)",
        "not-a-host",
        "",
    ],
)
def test_ollama_client_rejects_unsafe_hosts_at_construction(host: str) -> None:
    """Offline: unsafe OLLAMA_HOST values fail before any network call."""
    with pytest.raises(ValueError, match="Ollama URL"):
        OllamaChatClient(host=host)


def test_post_json_rejects_unsafe_url_before_urlopen() -> None:
    """Offline: _post_json validates scheme and never calls urlopen for file:."""
    client = OllamaChatClient(host="http://127.0.0.1:11434")
    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen") as urlopen:
        with pytest.raises(ValueError, match="Ollama URL"):
            client._post_json("file:///etc/passwd", {"model": "x"})
    urlopen.assert_not_called()


def test_mocked_ollama_chat_still_works_with_default_http_host() -> None:
    """Offline: existing mocked Ollama path remains functional after hardening."""
    with patch_ollama_urlopen(ollama_http_body(proposal_dict())):
        result = RiskOrchestrator(OllamaRiskAgent()).assess(
            "Portal stores PII without MFA."
        )
    assert result.scored_risks[0].inherent_risk.risk_score == 20
    assert result.scored_risks[0].inherent_risk.likelihood == 4
    assert result.scored_risks[0].inherent_risk.impact == 5
