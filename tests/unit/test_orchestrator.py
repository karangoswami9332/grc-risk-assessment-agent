"""Phase 3: mock RiskAgent, proposal validation, and orchestrator scoring."""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from grc_agent.agents import MockRiskAgent, ProposedRisk, RiskProposal
from grc_agent.engine import RiskEngine
from grc_agent.models import Asset, Threat, Vulnerability
from grc_agent.models.enums import (
    AssetCriticality,
    RiskRating,
    ThreatCategory,
    VulnerabilitySeverity,
)
from grc_agent.orchestrator import RiskOrchestrator


def _valid_proposal(**risk_overrides: object) -> RiskProposal:
    risk_payload = {
        "id": "risk-1",
        "title": "Unauthorized access",
        "likelihood": 4,
        "impact": 5,
        "rationale": "Public portal without MFA.",
        "asset_ids": ["asset-1"],
        "threat_ids": ["threat-1"],
        "vulnerability_ids": ["vuln-1"],
    }
    risk_payload.update(risk_overrides)
    return RiskProposal(
        assets=[
            Asset(
                id="asset-1",
                name="Customer portal",
                criticality=AssetCriticality.HIGH,
            )
        ],
        threats=[
            Threat(
                id="threat-1",
                name="Credential stuffing",
                category=ThreatCategory.UNAUTHORIZED_ACCESS,
                asset_ids=["asset-1"],
            )
        ],
        vulnerabilities=[
            Vulnerability(
                id="vuln-1",
                name="No MFA",
                severity=VulnerabilitySeverity.HIGH,
                asset_ids=["asset-1"],
            )
        ],
        risks=[ProposedRisk.model_validate(risk_payload)],
    )


class TestValidProposal:
    def test_accepts_complete_structured_proposal(self) -> None:
        proposal = _valid_proposal()
        assert len(proposal.assets) == 1
        assert len(proposal.threats) == 1
        assert len(proposal.vulnerabilities) == 1
        assert proposal.risks[0].likelihood == 4
        assert proposal.risks[0].impact == 5
        dumped = proposal.model_dump()
        assert "risk_score" not in dumped["risks"][0]
        assert "risk_rating" not in dumped["risks"][0]


class TestInvalidProposal:
    def test_rejects_out_of_range_likelihood(self) -> None:
        with pytest.raises(ValidationError):
            _valid_proposal(likelihood=0)

    def test_rejects_out_of_range_impact(self) -> None:
        with pytest.raises(ValidationError):
            _valid_proposal(impact=6)

    def test_rejects_agent_supplied_score_fields(self) -> None:
        with pytest.raises(ValidationError):
            ProposedRisk.model_validate(
                {
                    "id": "risk-1",
                    "title": "Unauthorized access",
                    "likelihood": 4,
                    "impact": 5,
                    "rationale": "Because the model said so.",
                    "risk_score": 12,
                    "risk_rating": "low",
                }
            )

    def test_rejects_missing_rationale(self) -> None:
        with pytest.raises(ValidationError):
            _valid_proposal(rationale="")


class TestProposalRelationships:
    def test_valid_proposal_links_threats_vulns_and_risks_to_defined_ids(self) -> None:
        proposal = _valid_proposal()
        assert proposal.threats[0].asset_ids == ["asset-1"]
        assert proposal.vulnerabilities[0].asset_ids == ["asset-1"]
        assert proposal.risks[0].asset_ids == ["asset-1"]
        assert proposal.risks[0].threat_ids == ["threat-1"]
        assert proposal.risks[0].vulnerability_ids == ["vuln-1"]

    def test_rejects_empty_threat_asset_ids(self) -> None:
        proposal = _valid_proposal()
        with pytest.raises(ValidationError, match="asset_ids"):
            RiskProposal(
                assets=proposal.assets,
                threats=[
                    Threat(
                        id="threat-1",
                        name="Unauthorized access",
                        category=ThreatCategory.UNAUTHORIZED_ACCESS,
                        asset_ids=[],
                    )
                ],
                vulnerabilities=proposal.vulnerabilities,
                risks=proposal.risks,
            )

    def test_rejects_unknown_threat_asset_id(self) -> None:
        proposal = _valid_proposal()
        with pytest.raises(ValidationError, match="unknown"):
            RiskProposal(
                assets=proposal.assets,
                threats=[
                    Threat(
                        id="threat-1",
                        name="Unauthorized access",
                        category=ThreatCategory.UNAUTHORIZED_ACCESS,
                        asset_ids=["missing-asset"],
                    )
                ],
                vulnerabilities=proposal.vulnerabilities,
                risks=proposal.risks,
            )

    def test_rejects_unknown_risk_relationship_ids(self) -> None:
        with pytest.raises(ValidationError, match="unknown"):
            _valid_proposal(threat_ids=["not-a-real-threat"])

    def test_rejects_invented_vulnerability_id_on_risk(self) -> None:
        with pytest.raises(ValidationError, match="unknown"):
            _valid_proposal(vulnerability_ids=["vuln-does-not-exist"])


class TestMockAgentOrchestratorFlow:
    def test_mock_agent_to_orchestrator(self) -> None:
        orchestrator = RiskOrchestrator(MockRiskAgent(), RiskEngine())
        result = orchestrator.assess(
            "A public customer portal stores PII and currently has no MFA."
        )
        assert result.proposal.risks[0].likelihood == 4
        assert result.proposal.risks[0].impact == 5
        assert len(result.scored_risks) == 1
        scored = result.scored_risks[0].inherent_risk
        assert scored.risk_score == 20
        assert scored.risk_rating == RiskRating.CRITICAL

    def test_empty_scenario_is_rejected(self) -> None:
        orchestrator = RiskOrchestrator(MockRiskAgent())
        with pytest.raises(ValueError, match="empty"):
            orchestrator.assess("   ")


class TestEngineOwnsFinalScore:
    def test_orchestrator_uses_risk_engine_not_agent_math(self) -> None:
        result = RiskOrchestrator(MockRiskAgent()).assess("Any in-scope process.")
        inherent = result.scored_risks[0].inherent_risk
        expected = RiskEngine().calculate_inherent_risk(
            result.proposal.risks[0].likelihood,
            result.proposal.risks[0].impact,
        )
        assert inherent.risk_score == expected.risk_score == 20
        assert inherent.risk_rating == expected.risk_rating == RiskRating.CRITICAL

    def test_mock_agent_does_not_import_risk_engine(self) -> None:
        import grc_agent.agents.mock_risk_agent as mock_mod

        source = inspect.getsource(mock_mod)
        assert "from grc_agent.engine" not in source
        assert "calculate_inherent_risk" not in source

    def test_propose_signature_has_no_score_parameters(self) -> None:
        parameters = list(inspect.signature(MockRiskAgent.propose).parameters)
        assert parameters == ["self", "scenario", "context"]


class RecordingAgent(MockRiskAgent):
    def __init__(self) -> None:
        self.last_context: str | None = None

    def propose(self, scenario: str, context: str = "") -> RiskProposal:
        self.last_context = context
        return super().propose(scenario, context=context)


class TestOrchestratorOptionalRetriever:
    def test_without_retriever_context_is_empty(self) -> None:
        agent = RecordingAgent()
        RiskOrchestrator(agent).assess("A public portal stores PII.")
        assert agent.last_context == ""

    def test_with_retriever_passes_formatted_hits(self) -> None:
        from grc_agent.rag import Chunk, FakeEmbedder, Retriever

        retriever = Retriever(FakeEmbedder())
        retriever.add_chunks(
            [Chunk(id="mfa", text="Require MFA for remote access to customer systems.", source="cis.md")]
        )
        agent = RecordingAgent()
        result = RiskOrchestrator(agent, retriever=retriever).assess(
            "Customer portal has no MFA for remote users."
        )
        assert agent.last_context
        assert "cis.md" in agent.last_context
        assert "MFA" in agent.last_context
        assert result.scored_risks[0].inherent_risk.risk_score == 20

