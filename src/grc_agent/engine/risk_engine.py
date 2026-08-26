"""Deterministic risk scoring. Future AI modules must call this, not copy it.

The LLM (when added) may propose likelihood and impact. It must not supply
a final score or rating. This class is the only supported way to compute:

    risk_score = likelihood × impact
    risk_rating = matrix(risk_score)
"""

from __future__ import annotations

from grc_agent.engine.matrix import calculate_rating as matrix_rating
from grc_agent.engine.matrix import calculate_score as matrix_score
from grc_agent.models.entities import InherentRisk
from grc_agent.models.enums import RiskRating


class RiskEngine:
    """Python owner of inherent risk arithmetic and matrix lookup.

    Methods do not accept a caller-supplied score or rating to "override"
    the formula. ``calculate_inherent_risk`` always recomputes both.
    """

    def calculate_score(self, likelihood: int, impact: int) -> int:
        """Return ``likelihood * impact`` after validating the 1–5 scale."""
        return matrix_score(likelihood, impact)

    def calculate_rating(self, score: int) -> RiskRating:
        """Return the matrix band for an already-computed score (1–25)."""
        return RiskRating(matrix_rating(score))

    def calculate_inherent_risk(self, likelihood: int, impact: int) -> InherentRisk:
        """Validate inputs, compute score, look up rating, return a frozen result.

        Any ``risk_score`` or ``risk_rating`` a caller might have computed
        elsewhere is ignored because those parameters are not accepted.
        """
        score = self.calculate_score(likelihood, impact)
        rating = self.calculate_rating(score)
        return InherentRisk(
            likelihood=likelihood,
            impact=impact,
            risk_score=score,
            risk_rating=rating,
        )
