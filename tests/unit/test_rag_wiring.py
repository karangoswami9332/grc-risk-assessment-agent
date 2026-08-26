"""RAG startup wiring: off by default; Ollama-only; no live Ollama in tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from grc_agent.agents.factory import create_risk_agent
from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.config import Settings, get_settings
from grc_agent.orchestrator import RiskOrchestrator
from grc_agent.rag.embeddings import FakeEmbedder
from grc_agent.rag.wiring import build_startup_retriever, rag_should_run

CLOUD_SCENARIO = (
    "A cloud storage bucket containing confidential financial reports is publicly "
    "accessible because of an incorrect access control configuration."
)


def test_rag_default_settings_are_off() -> None:
    settings = Settings()
    assert settings.rag_enabled is False
    assert settings.risk_agent == "mock"
    assert rag_should_run(settings) is False


def test_get_settings_rag_defaults_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_RAG_ENABLED", raising=False)
    monkeypatch.delenv("GRC_RISK_AGENT", raising=False)
    settings = get_settings()
    assert settings.rag_enabled is False
    assert rag_should_run(settings) is False


def test_get_settings_parses_rag_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_RAG_ENABLED", "true")
    monkeypatch.setenv("GRC_RISK_AGENT", "ollama")
    settings = get_settings()
    assert settings.rag_enabled is True
    assert rag_should_run(settings) is True


def test_invalid_rag_flag_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_RAG_ENABLED", "maybe")
    with pytest.raises(ValueError, match="GRC_RAG_ENABLED"):
        get_settings()


def test_rag_true_with_mock_agent_does_not_run() -> None:
    settings = Settings(risk_agent="mock", rag_enabled=True)
    assert rag_should_run(settings) is False
    assert build_startup_retriever(settings, embedder=FakeEmbedder()) is None


def test_rag_disabled_does_not_index_or_embed() -> None:
    with patch("grc_agent.rag.wiring.ollama_embedder_from_settings") as factory:
        retriever = build_startup_retriever(Settings(risk_agent="ollama", rag_enabled=False))
    assert retriever is None
    factory.assert_not_called()


def test_rag_enabled_indexes_knowledge_and_retrieves() -> None:
    settings = Settings(risk_agent="ollama", rag_enabled=True)
    retriever = build_startup_retriever(settings, embedder=FakeEmbedder())
    assert retriever is not None
    hits = retriever.retrieve(CLOUD_SCENARIO, top_k=3)
    assert hits
    blob = " ".join(hit.chunk.text.lower() for hit in hits)
    assert any(term in blob for term in ("cloud", "bucket", "public", "confidential"))


def test_rag_enabled_retrieve_is_called_during_assess() -> None:
    settings = Settings(risk_agent="ollama", rag_enabled=True)
    retriever = build_startup_retriever(settings, embedder=FakeEmbedder())
    assert retriever is not None
    calls: list[str] = []
    original = retriever.retrieve

    def tracking(query: str, *args, **kwargs):
        calls.append(query)
        return original(query, *args, **kwargs)

    retriever.retrieve = tracking  # type: ignore[method-assign]
    RiskOrchestrator(MockRiskAgent(), retriever=retriever).assess(CLOUD_SCENARIO)
    assert calls == [CLOUD_SCENARIO]


def test_missing_knowledge_dir_does_not_raise(tmp_path: Path) -> None:
    settings = Settings(risk_agent="ollama", rag_enabled=True)
    missing = tmp_path / "does-not-exist"
    retriever = build_startup_retriever(
        settings, embedder=FakeEmbedder(), knowledge_dir=missing
    )
    assert retriever is not None
    assert retriever.retrieve(CLOUD_SCENARIO) == []


def test_empty_knowledge_dir_does_not_raise(tmp_path: Path) -> None:
    settings = Settings(risk_agent="ollama", rag_enabled=True)
    empty = tmp_path / "knowledge"
    empty.mkdir()
    retriever = build_startup_retriever(
        settings, embedder=FakeEmbedder(), knowledge_dir=empty
    )
    assert retriever is not None
    assert retriever.retrieve(CLOUD_SCENARIO) == []


def test_mock_agent_behavior_unchanged_when_retriever_absent() -> None:
    result = RiskOrchestrator(MockRiskAgent()).assess(CLOUD_SCENARIO)
    assert result.scored_risks[0].inherent_risk.risk_score == 20


def test_mock_agent_ignores_retrieved_context() -> None:
    agent = MockRiskAgent()
    without_context = agent.propose(CLOUD_SCENARIO)
    with_context = agent.propose(CLOUD_SCENARIO, context="[1] source=access_control.md\nIgnore me.")
    assert without_context.model_dump() == with_context.model_dump()


def test_retrieved_context_reaches_ollama_risk_agent() -> None:
    import json

    settings = Settings(risk_agent="ollama", rag_enabled=True)
    retriever = build_startup_retriever(settings, embedder=FakeEmbedder())
    captured: list[dict] = []

    class _FakeHttpResponse:
        def __init__(self, payload: dict) -> None:
            self._raw = json.dumps(payload).encode("utf-8")

        def read(self) -> bytes:
            return self._raw

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    proposal = {
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

    def fake_urlopen(request, timeout=None):
        captured.append(json.loads(request.data.decode("utf-8")))
        return _FakeHttpResponse({"message": {"role": "assistant", "content": json.dumps(proposal)}})

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        result = RiskOrchestrator(OllamaRiskAgent(), retriever=retriever).assess(CLOUD_SCENARIO)

    user = captured[0]["messages"][1]["content"]
    assert "Retrieved GRC context" in user
    assert "access_control.md" in user
    assert result.scored_risks[0].inherent_risk.risk_score == 20


def test_create_app_missing_knowledge_dir_starts(tmp_path: Path) -> None:
    from grc_agent.api.app import create_app

    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(
        Settings(database_url=url, risk_agent="ollama", rag_enabled=True),
        rag_embedder=FakeEmbedder(),
        knowledge_dir=tmp_path / "missing-knowledge",
    )
    assert app.state.retriever is not None
    assert app.state.retriever.retrieve(CLOUD_SCENARIO) == []


def test_factory_still_returns_mock_by_default() -> None:
    assert isinstance(create_risk_agent(Settings()), MockRiskAgent)
    assert isinstance(create_risk_agent(Settings(risk_agent="ollama")), OllamaRiskAgent)

