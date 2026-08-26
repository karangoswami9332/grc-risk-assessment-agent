"""API: RAG → LLM selected_control_ids → validated mapped_controls (assessment-level)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from grc_agent.api.app import create_app
from grc_agent.config import Settings
from grc_agent.engine import RiskEngine
from grc_agent.rag.control_chunking import chunk_control_catalog
from grc_agent.rag.embeddings import FakeEmbedder
from grc_agent.rag.ingest import default_knowledge_dir
from grc_agent.rag.types import RetrievalHit

CLOUD_SCENARIO = (
    "A cloud storage bucket containing confidential financial reports is publicly "
    "accessible because of an incorrect access control configuration."
)

_PROPOSAL_5X5_WITH_CTRL = {
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
    "selected_control_ids": ["CTRL-CLD-001", "CTRL-CLD-999"],
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


def _ctrl_cld001_hit() -> RetrievalHit:
    text = (default_knowledge_dir() / "controls.md").read_text(encoding="utf-8")
    chunk = next(c for c in chunk_control_catalog(text, source="controls.md") if "CTRL-CLD-001" in c.text)
    return RetrievalHit(chunk=chunk, score=0.9)


def test_rag_off_keeps_mapped_controls_empty(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(Settings(database_url=url, risk_agent="mock", rag_enabled=False))
    body = TestClient(app).post("/risk-assessments", json={"scenario": CLOUD_SCENARIO}).json()
    assert body["mapped_controls"] == []
    assert body["risk_score"] == 20
    assert body["risk_rating"] == "critical"


def test_ollama_rag_maps_ctrl_cld001_and_rejects_unknown(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(
        Settings(database_url=url, risk_agent="ollama", rag_enabled=True),
        rag_embedder=FakeEmbedder(),
    )
    assert app.state.retriever is not None
    hit = _ctrl_cld001_hit()
    app.state.retriever.retrieve = lambda query, top_k=3: [hit]  # type: ignore[method-assign]

    def fake_urlopen(request, timeout=None):
        assert request.full_url.endswith("/api/chat")
        return _FakeHttpResponse(
            {"message": {"role": "assistant", "content": json.dumps(_PROPOSAL_5X5_WITH_CTRL)}}
        )

    with patch("grc_agent.llm.ollama_client.urllib.request.urlopen", side_effect=fake_urlopen):
        response = TestClient(app).post("/risk-assessments", json={"scenario": CLOUD_SCENARIO})

    assert response.status_code == 200
    body = response.json()
    assert body["mapped_controls"] == [
        {
            "control_id": "CTRL-CLD-001",
            "name": "Block Public Access to Cloud Storage",
        }
    ]
    assert "CTRL-CLD-999" not in json.dumps(body["mapped_controls"])
    expected = RiskEngine().calculate_inherent_risk(5, 5)
    assert body["risk_score"] == expected.risk_score == 25
    assert body["risk_rating"] == expected.risk_rating.value == "critical"
    assert set(body) == {
        "scenario",
        "proposal",
        "scored_risks",
        "risk_score",
        "risk_rating",
        "rationale",
        "mapped_controls",
    }
    assert body["proposal"]["selected_control_ids"] == ["CTRL-CLD-001", "CTRL-CLD-999"]


def test_existing_response_fields_still_present_with_mapping(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
    app = create_app(Settings(database_url=url))
    body = TestClient(app).post(
        "/risk-assessments",
        json={"scenario": "A public portal stores PII without MFA."},
    ).json()
    for key in ("scenario", "proposal", "scored_risks", "risk_score", "risk_rating", "rationale"):
        assert key in body
    assert "mapped_controls" in body
    assert body["mapped_controls"] == []
