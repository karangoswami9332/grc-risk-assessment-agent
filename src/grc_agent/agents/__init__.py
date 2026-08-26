"""GRC agents. MockRiskAgent is the default; OllamaRiskAgent is opt-in."""

from grc_agent.agents.base import RiskAgent
from grc_agent.agents.mock_risk_agent import MockRiskAgent
from grc_agent.agents.ollama_risk_agent import OllamaRiskAgent
from grc_agent.agents.proposals import ProposedRisk, RiskProposal

__all__ = [
    "MockRiskAgent",
    "OllamaRiskAgent",
    "ProposedRisk",
    "RiskAgent",
    "RiskProposal",
]
