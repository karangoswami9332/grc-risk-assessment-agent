"""Unit tests for the deterministic risk engine and domain validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from grc_agent.engine import RiskEngine
from grc_agent.engine.matrix import SCORE_MAX, SCORE_MIN
from grc_agent.models import (
    Asset,
    Control,
    GRCAssessment,
    InherentRisk,
    Risk,
    Threat,
    Vulnerability,
)
from grc_agent.models.enums import (
    AssetCriticality,
    ControlEffectiveness,
    RiskRating,
    RiskTreatment,
    ThreatCategory,
    VulnerabilitySeverity,
)

engine = RiskEngine()


def _risk(**overrides: object) -> Risk:
    payload = {
        "id": "r1",
        "title": "Unauthorized access to customer records",
        "likelihood": 4,
        "impact": 5,
    }
    payload.update(overrides)
    return Risk.model_validate(payload)


class TestScaleValidation:
    @pytest.mark.parametrize("value", [1, 2, 3, 4, 5])
    def test_valid_likelihood_and_impact(self, value: int) -> None:
        risk = _risk(likelihood=value, impact=value)
        assert risk.likelihood == value
        assert risk.impact == value
        assert engine.calculate_score(value, value) == value * value

    @pytest.mark.parametrize("field", ["likelihood", "impact"])
    @pytest.mark.parametrize("value", [0, 6, -1, 10])
    def test_out_of_range_rejected_on_risk(self, field: str, value: int) -> None:
        with pytest.raises(ValidationError):
            _risk(**{field: value})

    @pytest.mark.parametrize("field", ["likelihood", "impact"])
    @pytest.mark.parametrize("value", [0, 6, -1, 10])
    def test_out_of_range_rejected_on_engine(self, field: str, value: int) -> None:
        kwargs = {"likelihood": 3, "impact": 3, field: value}
        with pytest.raises(ValueError, match="between 1 and 5"):
            engine.calculate_score(**kwargs)

    def test_bool_is_not_a_valid_scale_value(self) -> None:
        with pytest.raises((ValidationError, ValueError)):
            _risk(likelihood=True, impact=4)
        with pytest.raises(ValueError):
            engine.calculate_score(True, 4)  # type: ignore[arg-type]

    def test_non_integer_rejected_by_engine(self) -> None:
        with pytest.raises(ValueError, match="integer"):
            engine.calculate_score(4.0, 5)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="integer"):
            engine.calculate_score("4", 5)  # type: ignore[arg-type]


class TestScoreCalculation:
    @pytest.mark.parametrize(
        ("likelihood", "impact", "expected"),
        [
            (1, 1, 1),
            (1, 5, 5),
            (4, 5, 20),
            (5, 5, 25),
        ],
    )
    def test_score_is_likelihood_times_impact(
        self, likelihood: int, impact: int, expected: int
    ) -> None:
        assert engine.calculate_score(likelihood, impact) == expected


class TestRatingBoundaries:
    """Inclusive bands: 1–4 LOW, 5–9 MEDIUM, 10–16 HIGH, 17–25 CRITICAL."""

    @pytest.mark.parametrize(
        ("score", "rating"),
        [
            (1, RiskRating.LOW),
            (4, RiskRating.LOW),
            (5, RiskRating.MEDIUM),
            (9, RiskRating.MEDIUM),
            (10, RiskRating.HIGH),
            (16, RiskRating.HIGH),
            (17, RiskRating.CRITICAL),
            (25, RiskRating.CRITICAL),
        ],
    )
    def test_rating_boundaries(self, score: int, rating: RiskRating) -> None:
        assert engine.calculate_rating(score) == rating

    @pytest.mark.parametrize(
        ("likelihood", "impact", "score", "rating"),
        [
            (1, 1, 1, RiskRating.LOW),
            (1, 4, 4, RiskRating.LOW),
            (1, 5, 5, RiskRating.MEDIUM),
            (3, 3, 9, RiskRating.MEDIUM),
            (2, 5, 10, RiskRating.HIGH),
            (4, 4, 16, RiskRating.HIGH),
            (5, 4, 20, RiskRating.CRITICAL),
            (5, 5, 25, RiskRating.CRITICAL),
        ],
    )
    def test_inherent_risk_boundaries(
        self,
        likelihood: int,
        impact: int,
        score: int,
        rating: RiskRating,
    ) -> None:
        result = engine.calculate_inherent_risk(likelihood, impact)
        assert result.risk_score == score
        assert result.risk_rating == rating
        assert result.likelihood == likelihood
        assert result.impact == impact


class TestInvalidRatingInput:
    @pytest.mark.parametrize("score", [SCORE_MIN - 1, SCORE_MAX + 1, 0, 26, -5])
    def test_score_outside_matrix(self, score: int) -> None:
        with pytest.raises(ValueError, match="between 1 and 25"):
            engine.calculate_rating(score)

    def test_non_integer_score(self) -> None:
        with pytest.raises(ValueError, match="integer"):
            engine.calculate_rating(20.0)  # type: ignore[arg-type]


class TestInherentRiskCannotBeOverridden:
    def test_mismatched_score_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="does not match"):
            InherentRisk(
                likelihood=4,
                impact=5,
                risk_score=12,
                risk_rating=RiskRating.CRITICAL,
            )

    def test_mismatched_rating_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="does not match"):
            InherentRisk(
                likelihood=4,
                impact=5,
                risk_score=20,
                risk_rating=RiskRating.LOW,
            )

    def test_engine_does_not_accept_a_supplied_score(self) -> None:
        import inspect

        result = engine.calculate_inherent_risk(4, 5)
        assert result.risk_score == 20
        assert result.risk_rating == RiskRating.CRITICAL
        parameters = list(inspect.signature(RiskEngine.calculate_inherent_risk).parameters)
        assert parameters == ["self", "likelihood", "impact"]

    def test_risk_model_has_no_score_fields(self) -> None:
        risk = _risk()
        assert not hasattr(risk, "risk_score")
        assert not hasattr(risk, "risk_rating")
        dumped = risk.model_dump()
        assert "risk_score" not in dumped
        assert "risk_rating" not in dumped


class TestDomainModels:
    def test_assessment_round_trip(self) -> None:
        assessment = GRCAssessment(
            id="a1",
            title="Customer portal review",
            scenario="A public web portal stores customer PII.",
            assets=[
                Asset(
                    id="asset-1",
                    name="Customer portal",
                    criticality=AssetCriticality.HIGH,
                )
            ],
            threats=[
                Threat(
                    id="t1",
                    name="Credential stuffing",
                    category=ThreatCategory.UNAUTHORIZED_ACCESS,
                    asset_ids=["asset-1"],
                )
            ],
            vulnerabilities=[
                Vulnerability(
                    id="v1",
                    name="No MFA",
                    severity=VulnerabilitySeverity.HIGH,
                    asset_ids=["asset-1"],
                )
            ],
            controls=[
                Control(
                    id="c1",
                    name="Multi-factor authentication",
                    effectiveness=ControlEffectiveness.EFFECTIVE,
                )
            ],
            risks=[
                Risk(
                    id="r1",
                    title="Account takeover",
                    likelihood=4,
                    impact=5,
                    asset_ids=["asset-1"],
                    threat_ids=["t1"],
                    vulnerability_ids=["v1"],
                    control_ids=["c1"],
                    treatment=RiskTreatment.MITIGATE,
                )
            ],
        )
        assert len(assessment.risks) == 1
        scored = engine.calculate_inherent_risk(
            assessment.risks[0].likelihood, assessment.risks[0].impact
        )
        assert scored.risk_score == 20

    def test_unknown_fields_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Asset.model_validate(
                {
                    "id": "a",
                    "name": "x",
                    "criticality": "high",
                    "llm_score": 99,
                }
            )
