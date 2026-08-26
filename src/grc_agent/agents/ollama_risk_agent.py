"""RiskAgent that calls local Ollama. Does not compute risk_score or risk_rating."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from grc_agent.agents.base import RiskAgent
from grc_agent.agents.proposals import RiskProposal
from grc_agent.llm.errors import OllamaResponseError
from grc_agent.llm.ollama_client import (
    DEFAULT_OLLAMA_HOST,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_TIMEOUT_SECONDS,
    OllamaChatClient,
)

SYSTEM_PROMPT = """You are a GRC risk analyst. Reply with JSON only that matches the provided schema.

Identify assets, threats, vulnerabilities, and proposed risks for the user's scenario.
Assign each entity a unique id in this JSON (for example asset-1, threat-1, vuln-1, risk-1). Choose ids that fit the entities you identified; do not copy a fixed example if it does not apply.

Keep the JSON compact for local CPU generation:
- Prefer one asset, one threat, one vulnerability, and one risk unless the scenario clearly requires more.
- Leave description fields empty when possible (use "").
- Keep each risk rationale to 1–2 short sentences (non-empty).

Relationships are mandatory:
1. Every threat.asset_ids must list one or more assets[].id values from THIS JSON that the threat targets.
2. Every vulnerability.asset_ids must list one or more assets[].id values from THIS JSON that the weakness affects.
3. Every risk must set asset_ids, threat_ids, and vulnerability_ids to ids defined in THIS JSON (the assets, threats, and vulnerabilities that make up that risk).
4. Every id you put in those lists MUST exactly match an id you defined on assets, threats, or vulnerabilities in the same JSON.
5. Do not invent dangling ids. Do not leave relationship arrays empty.

For each risk also provide:
- likelihood: integer 1-5
- impact: integer 1-5
- rationale: why those ratings apply (1–2 short sentences)
- treatment: exactly one of "mitigate", "accept", "transfer", or "avoid" — the most appropriate response to this identified risk. Choose from those four values based on the scenario; do not default to a single option.

Likelihood, impact, treatment, and relationship IDs are mandatory and must be valid.
Do NOT include risk_score or risk_rating. A separate Python engine computes those as likelihood × impact.
Use only the enum values allowed by the schema for criticality, category, and severity.

Control mapping (advisory only; does not change likelihood or impact):
- Retrieved GRC context may include candidate Internal GRC Control Catalog entries (CTRL-…).
- If such controls appear in the retrieved context, you may select relevant ones by ID only via selected_control_ids.
- Select ONLY control IDs that appear explicitly in the retrieved context. Do not invent control IDs.
- If no retrieved control is clearly relevant, set selected_control_ids to an empty list.
- Do not invent control names or descriptions; IDs only.
"""


def _parse_content(content: Any) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        raise OllamaResponseError("Ollama message.content must be a JSON object or JSON string")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise OllamaResponseError("Ollama returned content that is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise OllamaResponseError("Ollama JSON must be an object matching RiskProposal")
    return parsed


def _user_message(scenario: str, context: str) -> str:
    if not context.strip():
        return scenario
    return (
        f"Scenario:\n{scenario}\n\n"
        "Retrieved GRC context (advisory only; do not output risk_score or risk_rating):\n"
        f"{context.strip()}"
    )


class OllamaRiskAgent(RiskAgent):
    """Propose a RiskProposal via Ollama POST /api/chat. Scoring is not this class's job."""

    def __init__(
        self,
        client: OllamaChatClient | None = None,
        host: str = DEFAULT_OLLAMA_HOST,
        model: str = DEFAULT_OLLAMA_MODEL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._client = client or OllamaChatClient(
            host=host, model=model, timeout_seconds=timeout_seconds
        )

    def propose(self, scenario: str, context: str = "") -> RiskProposal:
        text = scenario.strip()
        if not text:
            raise ValueError("scenario must not be empty")

        content = self._client.chat(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_message(text, context)},
            ],
            format_schema=RiskProposal.model_json_schema(),
        )
        data = _parse_content(content)
        try:
            return RiskProposal.model_validate(data)
        except ValidationError as exc:
            raise OllamaResponseError(
                "Ollama JSON was rejected: it must match RiskProposal, include valid "
                "entity relationship ids, and must not include risk_score or risk_rating"
            ) from exc
