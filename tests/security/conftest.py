"""Security test fixtures. Offline / deterministic unless a test opts into live Ollama."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from grc_agent.api.app import create_app
from grc_agent.config import Settings


@pytest.fixture
def mock_api_client(tmp_path: Path) -> TestClient:
    """FastAPI client with MockRiskAgent (no Ollama, no RAG)."""
    url = f"sqlite:///{(tmp_path / 'sec.db').as_posix()}"
    app = create_app(Settings(database_url=url, risk_agent="mock", rag_enabled=False))
    return TestClient(app)


@pytest.fixture
def ollama_api_settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{(tmp_path / 'sec-ollama.db').as_posix()}",
        risk_agent="ollama",
        rag_enabled=False,
    )
