"""OllamaRiskAgent tests. HTTP is mocked; Ollama does not need to be running."""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from grc_agent.agents.factory import create_risk_agent
from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.config import Settings
from grc_agent.engine import RiskEngine
from grc_agent.llm.errors import OllamaResponseError, OllamaUnavailableError
from grc_agent.llm.ollama_client import DEFAULT_TIMEOUT_SECONDS
from grc_agent.models.enums import RiskRating, RiskTreatment
from grc_agent.orchestrator import RiskOrchestrator

SCENARIO = "A public customer portal stores PII and currently has no MFA."

VALID_PROPOSAL = {
    "assets": [
        {
            "id": "asset-1",
            "name": "PII",
            "description": "Customer personal data in the portal",
            "criticality": "high",
        }
    ],
    "threats": [
        {
            "id": "threat-1",
            "name": "Unauthorized user",
            "description": "External attacker or malicious insider",
            "category": "unauthorized_access",
            "asset_ids": ["asset-1"],
        }
    ],
    "vulnerabilities": [
        {
            "id": "vuln-1",
            "name": "Lack of MFA",
            "description": "Password-only authentication",
            "severity": "high",
            "asset_ids": ["asset-1"],
        }
    ],
    "risks": [
        {
            "id": "risk-1",
            "title": "Data breach / unauthorized access",
            "description": "Attacker accesses PII without MFA",
            "likelihood": 4,
            "impact": 5,
            "rationale": "Public portal with PII and no MFA makes unauthorized access likely and severe.",
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


def _patch_urlopen(payload: dict):
    return patch(
        "grc_agent.llm.ollama_client.urllib.request.urlopen",
        return_value=_FakeHttpResponse(payload),
    )


def test_factory_default_is_mock() -> None:
    agent = create_risk_agent(Settings())
    assert isinstance(agent, MockRiskAgent)


def test_factory_ollama_selects_ollama_agent() -> None:
    agent = create_risk_agent(Settings(risk_agent="ollama"))
    assert isinstance(agent, OllamaRiskAgent)


def test_valid_ollama_json_becomes_proposal_then_engine_score() -> None:
    with _patch_urlopen(_ollama_http_body(VALID_PROPOSAL)):
        result = RiskOrchestrator(OllamaRiskAgent()).assess(SCENARIO)

    risk = result.proposal.risks[0]
    assert risk.likelihood == 4
    assert risk.impact == 5
    assert "risk_score" not in risk.model_dump()
    inherent = result.scored_risks[0].inherent_risk
    expected = RiskEngine().calculate_inherent_risk(4, 5)
    assert inherent.risk_score == expected.risk_score == 20
    assert inherent.risk_rating == expected.risk_rating == RiskRating.CRITICAL
    assert result.proposal.threats[0].asset_ids == ["asset-1"]
    assert result.proposal.risks[0].threat_ids == ["threat-1"]
    assert result.proposal.risks[0].vulnerability_ids == ["vuln-1"]


def test_ollama_empty_relationship_ids_are_rejected() -> None:
    disconnected = json.loads(json.dumps(VALID_PROPOSAL))
    disconnected["threats"][0]["asset_ids"] = []
    disconnected["vulnerabilities"][0]["asset_ids"] = []
    disconnected["risks"][0]["asset_ids"] = []
    disconnected["risks"][0]["threat_ids"] = []
    disconnected["risks"][0]["vulnerability_ids"] = []
    with _patch_urlopen(_ollama_http_body(disconnected)):
        with pytest.raises(OllamaResponseError, match="relationship"):
            OllamaRiskAgent().propose(SCENARIO)


def test_system_prompt_requires_relationship_ids() -> None:
    from grc_agent.agents.ollama_risk_agent import SYSTEM_PROMPT

    assert "Every threat.asset_ids" in SYSTEM_PROMPT
    assert "Do not invent dangling ids" in SYSTEM_PROMPT
    assert "Do NOT include risk_score" in SYSTEM_PROMPT
    assert "treatment" in SYSTEM_PROMPT
    assert "mitigate" in SYSTEM_PROMPT
    assert "accept" in SYSTEM_PROMPT
    assert "transfer" in SYSTEM_PROMPT
    assert "avoid" in SYSTEM_PROMPT
    assert "Prefer one asset" in SYSTEM_PROMPT
    assert "Leave description fields empty" in SYSTEM_PROMPT
    assert "1–2 short sentences" in SYSTEM_PROMPT
    assert "Likelihood, impact, treatment, and relationship IDs are mandatory" in SYSTEM_PROMPT
    assert "selected_control_ids" in SYSTEM_PROMPT
    assert "Do not invent control IDs" in SYSTEM_PROMPT


@pytest.mark.parametrize("treatment", ["mitigate", "accept", "transfer", "avoid"])
def test_ollama_treatment_enum_values_are_accepted(treatment: str) -> None:
    payload = json.loads(json.dumps(VALID_PROPOSAL))
    payload["risks"][0]["treatment"] = treatment
    with _patch_urlopen(_ollama_http_body(payload)):
        proposal = OllamaRiskAgent().propose(SCENARIO)
    assert proposal.risks[0].treatment == RiskTreatment(treatment)


def test_ollama_risk_score_fields_are_rejected() -> None:
    tainted = json.loads(json.dumps(VALID_PROPOSAL))
    tainted["risks"][0]["risk_score"] = 1
    tainted["risks"][0]["risk_rating"] = "low"
    with _patch_urlopen(_ollama_http_body(tainted)):
        with pytest.raises(OllamaResponseError, match="risk_score"):
            OllamaRiskAgent().propose(SCENARIO)


def test_malformed_ollama_json_is_rejected() -> None:
    with _patch_urlopen(_ollama_http_body("this is not json {")):
        with pytest.raises(OllamaResponseError, match="not valid JSON"):
            OllamaRiskAgent().propose(SCENARIO)


def test_ollama_unavailable_raises_clear_error() -> None:
    with patch(
        "grc_agent.llm.ollama_client.urllib.request.urlopen",
        side_effect=URLError("connection refused"),
    ):
        with pytest.raises(OllamaUnavailableError, match="unavailable"):
            OllamaRiskAgent().propose(SCENARIO)


def test_ollama_http_error_is_unavailable() -> None:
    error = HTTPError(
        url="http://127.0.0.1:11434/api/chat",
        code=500,
        msg="Internal Server Error",
        hdrs=None,
        fp=BytesIO(b""),
    )
    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=error):
        with pytest.raises(OllamaUnavailableError, match="HTTP error 500"):
            OllamaRiskAgent().propose(SCENARIO)


def test_chat_request_targets_local_ollama_api() -> None:
    captured: dict = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _FakeHttpResponse(_ollama_http_body(VALID_PROPOSAL))

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        OllamaRiskAgent().propose(SCENARIO)

    assert captured["url"] == "http://127.0.0.1:11434/api/chat"
    assert captured["body"]["model"] == "llama3.1:8b"
    assert captured["body"]["stream"] is False
    assert captured["body"]["messages"][1]["content"] == SCENARIO
    assert captured["timeout"] == DEFAULT_TIMEOUT_SECONDS == 180
    assert captured["body"]["options"] == {"num_predict": 1024}
    assert "properties" in captured["body"]["format"] or "$defs" in captured["body"]["format"]
    assert "assets" in captured["body"]["format"]["properties"]
    assert "threats" in captured["body"]["format"]["properties"]
    assert "vulnerabilities" in captured["body"]["format"]["properties"]
    assert "risks" in captured["body"]["format"]["properties"]
    schema_text = json.dumps(captured["body"]["format"])
    assert "risk_score" not in schema_text
    assert "risk_rating" not in schema_text
    assert set(captured["body"].keys()) == {
        "model",
        "stream",
        "format",
        "messages",
        "options",
    }


def test_ollama_includes_retrieved_context_in_user_message() -> None:
    captured: dict = {}

    def fake_urlopen(request, timeout=None):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeHttpResponse(_ollama_http_body(VALID_PROPOSAL))

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        OllamaRiskAgent().propose(SCENARIO, context="[1] source=cis.md\nRequire MFA.")

    user = captured["body"]["messages"][1]["content"]
    assert "Scenario:" in user
    assert SCENARIO in user
    assert "Retrieved GRC context" in user
    assert "Require MFA." in user
    assert "risk_score" in user

