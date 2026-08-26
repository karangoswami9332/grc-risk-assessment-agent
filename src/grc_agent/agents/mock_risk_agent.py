"""Deterministic Risk Agent for tests and local development. No LLM calls."""

from __future__ import annotations

from grc_agent.agents.base import RiskAgent
from grc_agent.agents.proposals import ProposedRisk, RiskProposal
from grc_agent.models.entities import Asset, Threat, Vulnerability
from grc_agent.models.enums import AssetCriticality, ThreatCategory, VulnerabilitySeverity

# Fixed inputs so orchestrator tests can assert engine output (4 × 5 = 20).
_MOCK_LIKELIHOOD = 4
_MOCK_IMPACT = 5


class MockRiskAgent(RiskAgent):
    """Returns a stable, valid proposal derived from the scenario text only.

    Likelihood and impact are constants, not the product of a scoring formula.
    This class does not import or call the deterministic scoring engine.
    """

    def propose(self, scenario: str, context: str = "") -> RiskProposal:
        text = scenario.strip()
        if not text:
            raise ValueError("scenario must not be empty")

        return RiskProposal(
            assets=[
                Asset(
                    id="asset-1",
                    name="In-scope business application",
                    description="Mock asset synthesized from the assessment scenario.",
                    criticality=AssetCriticality.HIGH,
                )
            ],
            threats=[
                Threat(
                    id="threat-1",
                    name="Unauthorized access",
                    description="Mock threat of unauthorized access to in-scope data.",
                    category=ThreatCategory.UNAUTHORIZED_ACCESS,
                    asset_ids=["asset-1"],
                )
            ],
            vulnerabilities=[
                Vulnerability(
                    id="vuln-1",
                    name="Insufficient access control",
                    description="Mock weakness in authentication or authorization.",
                    severity=VulnerabilitySeverity.HIGH,
                    asset_ids=["asset-1"],
                )
            ],
            risks=[
                ProposedRisk(
                    id="risk-1",
                    title="Unauthorized access to sensitive information",
                    description="A threat actor exploits weak access control on the in-scope application.",
                    likelihood=_MOCK_LIKELIHOOD,
                    impact=_MOCK_IMPACT,
                    rationale=(
                        "Deterministic mock proposal (not an LLM). "
                        f"Scenario excerpt: {text[:240]}"
                    ),
                    asset_ids=["asset-1"],
                    threat_ids=["threat-1"],
                    vulnerability_ids=["vuln-1"],
                )
            ],
        )
