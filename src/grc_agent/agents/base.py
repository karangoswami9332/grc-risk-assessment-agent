"""Risk Agent contract. Implementations propose structure; they do not score."""

from __future__ import annotations

from abc import ABC, abstractmethod

from grc_agent.agents.proposals import RiskProposal


class RiskAgent(ABC):
    """Produces a structured GRC proposal from a natural-language scenario.

    Implementations (mock now, local LLM later) must return ``RiskProposal``.
    They must not calculate or return ``risk_score`` or ``risk_rating``.
    """

    @abstractmethod
    def propose(self, scenario: str, context: str = "") -> RiskProposal:
        """Analyze ``scenario`` (and optional retrieved context) into a proposal."""
