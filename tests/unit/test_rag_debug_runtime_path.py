"""Trace POST /risk-assessments RAG debug path. Documents why console output is missing."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from grc_agent.api.app import create_app
from grc_agent.api.dependencies import get_risk_orchestrator
from grc_agent.config import Settings
from grc_agent.rag.embeddings import FakeEmbedder
from grc_agent.rag.retriever import Retriever
from grc_agent.rag.wiring import build_startup_retriever, rag_should_run

SCENARIO = "A public cloud bucket exposes confidential reports."
PIPELINE_LOGGER = "grc_agent.orchestrator.pipeline"

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


def _enabled_settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{(tmp_path / 'api.db').as_posix()}",
        risk_agent="ollama",
        rag_enabled=True,
        rag_debug=True,
    )


def test_startup_retriever_is_created_when_ollama_and_rag_enabled() -> None:
    settings = Settings(risk_agent="ollama", rag_enabled=True, rag_debug=True)
    assert rag_should_run(settings) is True
    retriever = build_startup_retriever(settings, embedder=FakeEmbedder())
    assert retriever is not None
    assert isinstance(retriever, Retriever)


def test_create_app_stores_retriever_and_rag_debug(tmp_path: Path) -> None:
    app = create_app(_enabled_settings(tmp_path), rag_embedder=FakeEmbedder())
    assert app.state.retriever is not None
    assert app.state.settings.rag_debug is True
    assert app.state.settings.rag_enabled is True
    assert app.state.settings.risk_agent == "ollama"


def test_get_risk_orchestrator_passes_retriever_and_rag_debug(tmp_path: Path) -> None:
    app = create_app(_enabled_settings(tmp_path), rag_embedder=FakeEmbedder())
    request = type("Req", (), {"app": app})()
    orchestrator = get_risk_orchestrator(request, risk_engine=app.state.risk_engine)
    assert orchestrator._retriever is app.state.retriever
    assert orchestrator._retriever is not None
    assert orchestrator._rag_debug is True


def test_post_risk_assessments_runs_retrieve_format_and_debug_log(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    app = create_app(_enabled_settings(tmp_path), rag_embedder=FakeEmbedder())
    retrieve_calls: list[str] = []
    original_retrieve = app.state.retriever.retrieve

    def tracking(query: str, *args, **kwargs):
        retrieve_calls.append(query)
        return original_retrieve(query, *args, **kwargs)

    app.state.retriever.retrieve = tracking  # type: ignore[method-assign]
    captured_chat: list[dict] = []

    def fake_urlopen(request, timeout=None):
        captured_chat.append(json.loads(request.data.decode("utf-8")))
        return _FakeHttpResponse(
            {"message": {"role": "assistant", "content": json.dumps(_VALID_PROPOSAL)}}
        )

    caplog.set_level(logging.INFO, logger=PIPELINE_LOGGER)
    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        response = TestClient(app).post("/risk-assessments", json={"scenario": SCENARIO})

    assert response.status_code == 200
    assert retrieve_calls == [SCENARIO]
    user = captured_chat[0]["messages"][1]["content"]
    assert "Retrieved GRC context" in user
    assert "=== RAG DEBUG ===" in caplog.text
    assert "=== END RAG DEBUG ===" in caplog.text
    assert "Retrieved hits:" in caplog.text
    logged_context = caplog.text.split("Retrieved context:\n", 1)[1].split(
        "\n\n=== END RAG DEBUG ===", 1
    )[0]
    assert logged_context
    assert logged_context in user
    printed = capsys.readouterr().out
    assert "=== RAG DEBUG ===" in printed
    assert logged_context in printed
    assert response.json()["risk_score"] == 20


def test_uvicorn_default_config_has_no_root_logger_and_info_is_filtered() -> None:
    """uvicorn only configures uvicorn.* loggers. App INFO logs do not appear."""
    from uvicorn.config import LOGGING_CONFIG

    assert "root" not in LOGGING_CONFIG
    assert "grc_agent" not in LOGGING_CONFIG["loggers"]
    assert "grc_agent.orchestrator.pipeline" not in LOGGING_CONFIG["loggers"]

    pipeline = logging.getLogger(PIPELINE_LOGGER)
    root = logging.getLogger()
    old_root = root.level
    old_pipeline = pipeline.level
    try:
        pipeline.setLevel(logging.NOTSET)
        root.setLevel(logging.WARNING)
        assert pipeline.getEffectiveLevel() == logging.WARNING
        assert pipeline.isEnabledFor(logging.INFO) is False
        assert pipeline.isEnabledFor(logging.WARNING) is True
    finally:
        root.setLevel(old_root)
        pipeline.setLevel(old_pipeline)
