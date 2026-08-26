"""Choose MockRiskAgent or OllamaRiskAgent from settings."""

from __future__ import annotations

from grc_agent.agents.base import RiskAgent
from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.config import Settings

MOCK_AGENT = "mock"
OLLAMA_AGENT = "ollama"
VALID_AGENTS = frozenset({MOCK_AGENT, OLLAMA_AGENT})


def create_risk_agent(settings: Settings) -> RiskAgent:
    if settings.risk_agent == MOCK_AGENT:
        return MockRiskAgent()
    if settings.risk_agent == OLLAMA_AGENT:
        return OllamaRiskAgent(
            host=settings.ollama_host,
            model=settings.ollama_model,
            timeout_seconds=settings.ollama_timeout_seconds,
        )
    raise ValueError(
        f"Unknown GRC_RISK_AGENT={settings.risk_agent!r}; use {MOCK_AGENT!r} or {OLLAMA_AGENT!r}"
    )
