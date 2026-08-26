"""RAG debug logging: off by default; logs the exact propose() context when on."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.api.app import create_app
from grc_agent.config import Settings, get_settings
from grc_agent.orchestrator.pipeline import RiskOrchestrator, format_rag_debug_block
from grc_agent.rag import Chunk, FakeEmbedder, Retriever

SCENARIO = "A public cloud bucket exposes confidential reports."
LOGGER_NAME = "grc_agent.orchestrator.pipeline"


class RecordingAgent(MockRiskAgent):
    def __init__(self) -> None:
        self.last_context: str | None = None

    def propose(self, scenario: str, context: str = ""):
        self.last_context = context
        return super().propose(scenario, context=context)


def _retriever() -> Retriever:
    retriever = Retriever(FakeEmbedder())
    retriever.add_chunks(
        [
            Chunk(
                id="access_control.md:1",
                text="Public cloud storage buckets must not expose confidential reports.",
                source="access_control.md",
            )
        ]
    )
    return retriever


def test_get_settings_rag_debug_defaults_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_RAG_DEBUG", raising=False)
    monkeypatch.delenv("GRC_RAG_ENABLED", raising=False)
    settings = get_settings()
    assert settings.rag_debug is False
    assert settings.rag_enabled is False


def test_get_settings_parses_rag_debug_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_RAG_DEBUG", "true")
    assert get_settings().rag_debug is True


def test_debug_false_produces_no_debug_output(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    retriever = _retriever()
    agent = RecordingAgent()
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        result = RiskOrchestrator(agent, retriever=retriever, rag_debug=False).assess(SCENARIO)
    assert "=== RAG DEBUG ===" not in caplog.text
    assert "Retrieved context:" not in caplog.text
    captured = capsys.readouterr()
    assert "=== RAG DEBUG ===" not in captured.out
    assert "=== RAG DEBUG ===" not in captured.err
    assert agent.last_context
    assert "access_control.md" in agent.last_context
    assert result.scored_risks[0].inherent_risk.risk_score == 20


def test_debug_true_without_retriever_produces_no_debug_output(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    agent = RecordingAgent()
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        RiskOrchestrator(agent, rag_debug=True).assess(SCENARIO)
    assert "=== RAG DEBUG ===" not in caplog.text
    captured = capsys.readouterr()
    assert "=== RAG DEBUG ===" not in captured.out
    assert "=== RAG DEBUG ===" not in captured.err
    assert agent.last_context == ""


def test_debug_true_with_rag_logs_exact_context_passed_to_propose(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    retriever = _retriever()
    agent = RecordingAgent()
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        RiskOrchestrator(agent, retriever=retriever, rag_debug=True).assess(SCENARIO)

    assert agent.last_context
    assert "access_control.md" in agent.last_context
    block = format_rag_debug_block(SCENARIO, agent.last_context, hit_count=1)
    assert block in caplog.text
    printed = capsys.readouterr().out
    assert block in printed
    assert agent.last_context in printed
    assert "=== RAG DEBUG ===" in caplog.text
    assert "Retrieved hits: 1" in caplog.text
    assert "=== END RAG DEBUG ===" in caplog.text


def test_debug_true_prints_even_when_info_logs_are_filtered(
    capsys: pytest.CaptureFixture[str],
) -> None:
    retriever = _retriever()
    agent = RecordingAgent()
    pipeline = logging.getLogger(LOGGER_NAME)
    root = logging.getLogger()
    old_root = root.level
    old_pipeline = pipeline.level
    try:
        pipeline.setLevel(logging.NOTSET)
        root.setLevel(logging.WARNING)
        RiskOrchestrator(agent, retriever=retriever, rag_debug=True).assess(SCENARIO)
    finally:
        root.setLevel(old_root)
        pipeline.setLevel(old_pipeline)

    block = format_rag_debug_block(SCENARIO, agent.last_context or "", hit_count=1)
    printed = capsys.readouterr().out
    assert agent.last_context
    assert block in printed
    assert agent.last_context in printed


def test_debug_true_logs_same_context_passed_to_ollama_risk_agent(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    retriever = _retriever()
    captured: dict[str, str] = {}

    class RecordingOllama(OllamaRiskAgent):
        def propose(self, scenario: str, context: str = ""):
            captured["context"] = context
            return MockRiskAgent().propose(scenario, context=context)

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        RiskOrchestrator(RecordingOllama(), retriever=retriever, rag_debug=True).assess(SCENARIO)

    assert captured["context"]
    assert captured["context"] in caplog.text
    assert format_rag_debug_block(SCENARIO, captured["context"], 1) in caplog.text
    assert format_rag_debug_block(SCENARIO, captured["context"], 1) in capsys.readouterr().out


_VALID_PROPOSAL = {
    "assets": [
        {"id": "asset-1", "name": "Bucket", "description": "x", "criticality": "high"}
    ],
    "threats": [
        {
            "id": "threat-1",
            "name": "Public access",
            "description": "x",
            "category": "unauthorized_access",
            "asset_ids": ["asset-1"],
        }
    ],
    "vulnerabilities": [
        {
            "id": "vuln-1",
            "name": "ACL",
            "description": "x",
            "severity": "high",
            "asset_ids": ["asset-1"],
        }
    ],
    "risks": [
        {
            "id": "risk-1",
            "title": "Exposure",
            "description": "x",
            "likelihood": 4,
            "impact": 5,
            "rationale": "Public bucket.",
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


def test_rag_debug_is_not_included_in_api_response(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(
        Settings(
            database_url=url,
            risk_agent="ollama",
            rag_enabled=True,
            rag_debug=True,
        ),
        rag_embedder=FakeEmbedder(),
    )

    def fake_urlopen(request, timeout=None):
        return _FakeHttpResponse({"message": {"role": "assistant", "content": json.dumps(_VALID_PROPOSAL)}})

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        response = TestClient(app).post("/risk-assessments", json={"scenario": SCENARIO})

    assert response.status_code == 200
    body = response.json()
    dumped = json.dumps(body)
    assert "=== RAG DEBUG ===" not in dumped
    assert "Retrieved hits:" not in dumped
    assert set(body) == {
        "scenario",
        "proposal",
        "scored_risks",
        "risk_score",
        "risk_rating",
        "rationale",
        "mapped_controls",
    }
    assert body["risk_score"] == 20
    assert body["risk_rating"] == "critical"
