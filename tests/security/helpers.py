"""Shared helpers for offline security tests. No live Ollama or network."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.agents.proposals import RiskProposal
from grc_agent.controls.catalog import get_control_catalog
from grc_agent.rag.types import Chunk, RetrievalHit

CATALOG = get_control_catalog()
CTRL_CLD_001 = "CTRL-CLD-001"
CTRL_CLD_001_NAME = CATALOG[CTRL_CLD_001].name
CTRL_AC_001 = "CTRL-AC-001"
CTRL_AC_001_NAME = CATALOG[CTRL_AC_001].name

BASE_PROPOSAL: dict[str, Any] = {
    "assets": [
        {
            "id": "asset-1",
            "name": "In-scope system",
            "description": "",
            "criticality": "high",
        }
    ],
    "threats": [
        {
            "id": "threat-1",
            "name": "Unauthorized access",
            "description": "",
            "category": "unauthorized_access",
            "asset_ids": ["asset-1"],
        }
    ],
    "vulnerabilities": [
        {
            "id": "vuln-1",
            "name": "Weak access control",
            "description": "",
            "severity": "high",
            "asset_ids": ["asset-1"],
        }
    ],
    "risks": [
        {
            "id": "risk-1",
            "title": "Unauthorized access to sensitive data",
            "description": "",
            "likelihood": 4,
            "impact": 5,
            "rationale": "Security test fixture proposal.",
            "asset_ids": ["asset-1"],
            "threat_ids": ["threat-1"],
            "vulnerability_ids": ["vuln-1"],
            "treatment": "mitigate",
        }
    ],
    "selected_control_ids": [],
}


def proposal_dict(**overrides: Any) -> dict[str, Any]:
    """Deep-ish copy of a valid RiskProposal payload with optional top-level overrides."""
    payload = json.loads(json.dumps(BASE_PROPOSAL))
    payload.update(overrides)
    return payload


def control_hit(control_id: str, *, score: float = 0.95, spoofed_name: str | None = None) -> RetrievalHit:
    """Build a retrieval hit containing a catalog control ID (and optional spoofed Name line)."""
    entry = CATALOG[control_id]
    name_line = spoofed_name if spoofed_name is not None else entry.name
    text = (
        f"## {control_id} — {entry.name}\n\n"
        f"**Control ID:** {control_id}\n\n"
        f"**Name:** {name_line}\n\n"
        f"**Description:** {entry.description}\n"
    )
    return RetrievalHit(
        chunk=Chunk(id=f"controls.md:{control_id}", text=text, source="controls.md"),
        score=score,
    )


def injection_hit(text: str, *, score: float = 0.99) -> RetrievalHit:
    return RetrievalHit(
        chunk=Chunk(id="poison.md:1", text=text, source="poison.md"),
        score=score,
    )


class SelectingAgent(MockRiskAgent):
    """Mock agent that 'complies' with injected selected_control_ids."""

    def __init__(
        self,
        selected_control_ids: list[str],
        *,
        likelihood: int | None = None,
        impact: int | None = None,
    ) -> None:
        self._selected = selected_control_ids
        self._likelihood = likelihood
        self._impact = impact

    def propose(self, scenario: str, context: str = "") -> RiskProposal:
        base = super().propose(scenario, context=context)
        updates: dict[str, Any] = {"selected_control_ids": list(self._selected)}
        if self._likelihood is not None or self._impact is not None:
            risk = base.risks[0]
            risk_updates: dict[str, Any] = {}
            if self._likelihood is not None:
                risk_updates["likelihood"] = self._likelihood
            if self._impact is not None:
                risk_updates["impact"] = self._impact
            updates["risks"] = [risk.model_copy(update=risk_updates)]
        return base.model_copy(update=updates)


class ForcedRetriever:
    """Deterministic retriever that always returns the same hits."""

    def __init__(self, hits: list[RetrievalHit]) -> None:
        self._hits = hits
        self.queries: list[str] = []

    def retrieve(self, query: str, top_k: int = 5) -> list[RetrievalHit]:
        self.queries.append(query)
        return list(self._hits)[:top_k]


class FakeHttpResponse:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def ollama_http_body(content: object) -> dict:
    if isinstance(content, dict):
        content = json.dumps(content)
    return {"message": {"role": "assistant", "content": content}}


def patch_ollama_urlopen(payload: dict):
    return patch(
        "grc_agent.llm.ollama_client.urllib.request.urlopen",
        return_value=FakeHttpResponse(payload),
    )


def patch_ollama_urlopen_side_effect(side_effect):
    return patch(
        "grc_agent.llm.ollama_client.urllib.request.urlopen",
        side_effect=side_effect,
    )


SECRET_MARKERS = (
    "sk-proj-",
    "sk-live-",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "password=",
    "BEGIN PRIVATE KEY",
    "Bearer eyJ",
)
