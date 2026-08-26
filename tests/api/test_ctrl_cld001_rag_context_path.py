"""E2E path: complete CTRL-CLD-001 chunk → format_hits → OllamaRiskAgent.propose.

Uses create_app / RiskOrchestrator production wiring. Does not implement control mapping.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.api.app import create_app
from grc_agent.config import Settings
from grc_agent.engine import RiskEngine
from grc_agent.rag.control_chunking import chunk_control_catalog
from grc_agent.rag.embeddings import FakeEmbedder, OllamaEmbedder
from grc_agent.rag.ingest import default_knowledge_dir
from grc_agent.rag.retriever import format_hits
from grc_agent.rag.types import RetrievalHit
from grc_agent.rag.wiring import build_startup_retriever, rag_should_run

CLOUD_SCENARIO = (
    "A cloud storage bucket containing confidential financial reports is publicly "
    "accessible because of an incorrect access control configuration."
)

REQUIRED_FIELDS = (
    "Control ID:",
    "Name:",
    "Objective:",
    "Control Type:",
    "Domain:",
    "Description:",
    "Example Implementation:",
)

_PROPOSAL_5X5 = {
    "assets": [
        {
            "id": "asset-1",
            "name": "Cloud storage bucket",
            "description": "",
            "criticality": "critical",
        }
    ],
    "threats": [
        {
            "id": "threat-1",
            "name": "Unauthorized public access",
            "description": "",
            "category": "unauthorized_access",
            "asset_ids": ["asset-1"],
        }
    ],
    "vulnerabilities": [
        {
            "id": "vuln-1",
            "name": "Public bucket ACL misconfiguration",
            "description": "",
            "severity": "critical",
            "asset_ids": ["asset-1"],
        }
    ],
    "risks": [
        {
            "id": "risk-1",
            "title": "Confidential financial reports exposed publicly",
            "description": "",
            "likelihood": 5,
            "impact": 5,
            "rationale": "Public cloud storage of confidential reports.",
            "asset_ids": ["asset-1"],
            "threat_ids": ["threat-1"],
            "vulnerability_ids": ["vuln-1"],
            "treatment": "mitigate",
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


def _complete_ctrl_cld001_chunk():
    text = (default_knowledge_dir() / "controls.md").read_text(encoding="utf-8")
    chunks = chunk_control_catalog(text, source="controls.md")
    matches = [c for c in chunks if "CTRL-CLD-001" in c.text]
    assert len(matches) == 1
    chunk = matches[0]
    assert all(field in chunk.text for field in REQUIRED_FIELDS)
    return chunk


def test_rag_enabled_only_for_ollama_and_flag() -> None:
    assert rag_should_run(Settings(risk_agent="mock", rag_enabled=True)) is False
    assert rag_should_run(Settings(risk_agent="ollama", rag_enabled=False)) is False
    assert rag_should_run(Settings(risk_agent="ollama", rag_enabled=True)) is True


def test_api_path_passes_complete_ctrl_cld001_context_to_propose(tmp_path: Path) -> None:
    """Production create_app → orchestrator → propose; chat HTTP mocked, retrieval forced.

    Ranking with FakeEmbedder does not surface CTRL-CLD-001 in top_k=3; this test
    proves the exact production context hand-off once that chunk is retrieved.
    """
    ctrl = _complete_ctrl_cld001_chunk()
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(
        Settings(
            database_url=url,
            risk_agent="ollama",
            rag_enabled=True,
            rag_debug=False,
        ),
        rag_embedder=FakeEmbedder(),
    )
    assert app.state.retriever is not None
    assert isinstance(app.state.risk_agent, OllamaRiskAgent)

    forced_hits = [RetrievalHit(chunk=ctrl, score=0.99)]
    expected_context = format_hits(forced_hits)
    assert "CTRL-CLD-001" in expected_context
    assert all(field in expected_context for field in REQUIRED_FIELDS)
    # ID and body are the same single formatted block (one chunk).
    assert expected_context.count("## CTRL-CLD-001") == 1

    app.state.retriever.retrieve = lambda query, top_k=3: forced_hits  # type: ignore[method-assign]

    captured: list[dict] = []

    def fake_urlopen(request, timeout=None):
        assert request.full_url.endswith("/api/chat")
        captured.append(json.loads(request.data.decode("utf-8")))
        return _FakeHttpResponse({"message": {"role": "assistant", "content": json.dumps(_PROPOSAL_5X5)}})

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        response = TestClient(app).post("/risk-assessments", json={"scenario": CLOUD_SCENARIO})

    assert response.status_code == 200
    user = captured[0]["messages"][1]["content"]
    assert "Retrieved GRC context" in user
    assert expected_context in user
    assert CLOUD_SCENARIO in user
    assert "CTRL-CLD-001" in user
    assert all(field in user for field in REQUIRED_FIELDS)

    body = response.json()
    assert set(body) == {
        "scenario",
        "proposal",
        "scored_risks",
        "risk_score",
        "risk_rating",
        "rationale",
        "mapped_controls",
    }
    assert "risk_score" not in body["proposal"]["risks"][0]
    assert "risk_rating" not in body["proposal"]["risks"][0]
    assert body["proposal"]["risks"][0]["likelihood"] == 5
    assert body["proposal"]["risks"][0]["impact"] == 5
    expected = RiskEngine().calculate_inherent_risk(5, 5)
    assert body["risk_score"] == expected.risk_score == 25
    assert body["risk_rating"] == expected.risk_rating.value == "critical"
    assert body["scored_risks"][0]["risk_score"] == 25
    assert body["scored_risks"][0]["risk_rating"] == "critical"


def _ollama_reachable() -> bool:
    try:
        OllamaEmbedder().embed("ping")
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _ollama_reachable(), reason="Local Ollama embedder not reachable")
def test_live_ollama_api_path_retrieves_complete_ctrl_cld001(tmp_path: Path) -> None:
    """Real OllamaEmbedder through create_app; chat mocked to avoid long CPU generation."""
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(
        Settings(
            database_url=url,
            risk_agent="ollama",
            rag_enabled=True,
            rag_debug=True,
        )
    )
    assert app.state.retriever is not None

    hits = app.state.retriever.retrieve(CLOUD_SCENARIO, top_k=3)
    assert hits
    ctrl_hits = [
        (rank, hit)
        for rank, hit in enumerate(hits, start=1)
        if "CTRL-CLD-001" in hit.chunk.text
    ]
    assert ctrl_hits, "CTRL-CLD-001 not in top-3 with live Ollama embeddings"
    rank, hit = ctrl_hits[0]
    assert all(field in hit.chunk.text for field in REQUIRED_FIELDS)
    assert hit.chunk.text.count("## CTRL-CLD-001") == 1

    context = format_hits(hits)
    assert hit.chunk.text in context
    assert "CTRL-CLD-001" in context

    captured: list[dict] = []
    import urllib.request

    real_urlopen = urllib.request.urlopen

    def fake_urlopen(request, timeout=None):
        if request.full_url.endswith("/api/embed"):
            return real_urlopen(request, timeout=timeout)
        assert request.full_url.endswith("/api/chat")
        captured.append(json.loads(request.data.decode("utf-8")))
        return _FakeHttpResponse(
            {"message": {"role": "assistant", "content": json.dumps(_PROPOSAL_5X5)}}
        )

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        response = TestClient(app).post("/risk-assessments", json={"scenario": CLOUD_SCENARIO})

    assert response.status_code == 200
    user = captured[0]["messages"][1]["content"]
    assert context in user
    assert "Retrieved GRC context" in user
    assert "CTRL-CLD-001" in user
    # Record rank/score for the complete control chunk in the same context string.
    assert f"source={hit.chunk.source}" in context or hit.chunk.text in context
    body = response.json()
    assert body["risk_score"] == 25
    assert body["risk_rating"] == "critical"
    # Expose verification details in assertion messages for the report.
    assert rank >= 1
    assert hit.score > 0.0
    print(
        f"LIVE_CTRL_CLD001 rank={rank} score={hit.score:.6f} "
        f"chunk_id={hit.chunk.id} complete={all(f in hit.chunk.text for f in REQUIRED_FIELDS)}"
    )


def test_build_startup_retriever_none_when_rag_off() -> None:
    assert build_startup_retriever(Settings(risk_agent="ollama", rag_enabled=False)) is None
