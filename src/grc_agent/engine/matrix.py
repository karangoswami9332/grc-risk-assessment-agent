"""Deterministic 5×5 likelihood × impact matrix.

This module is the single source of truth for Phase 1 scoring. It has **no**
imports from domain entity models so the engine cannot form an import cycle
with Pydantic types, and so scoring stays independent of future AI modules.

Bands (inclusive):

    1–4   LOW
    5–9   MEDIUM
    10–16 HIGH
    17–25 CRITICAL

Rating values are the lowercase strings stored on ``RiskRating``.
"""

from __future__ import annotations

SCALE_MIN = 1
SCALE_MAX = 5
SCORE_MIN = SCALE_MIN * SCALE_MIN  # 1
SCORE_MAX = SCALE_MAX * SCALE_MAX  # 25

# Inclusive upper bound → rating value (must match RiskRating).
_RATING_UPPER_BOUNDS: tuple[tuple[int, str], ...] = (
    (4, "low"),
    (9, "medium"),
    (16, "high"),
    (25, "critical"),
)


def validate_scale(name: str, value: object) -> int:
    """Require an integer likelihood/impact in 1–5. Reject bool (subclass of int)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer between {SCALE_MIN} and {SCALE_MAX}")
    if value < SCALE_MIN or value > SCALE_MAX:
        raise ValueError(
            f"{name} must be between {SCALE_MIN} and {SCALE_MAX} inclusive, got {value}"
        )
    return value


def calculate_score(likelihood: int, impact: int) -> int:
    """Return inherent risk score: likelihood × impact."""
    likelihood = validate_scale("likelihood", likelihood)
    impact = validate_scale("impact", impact)
    return likelihood * impact


def calculate_rating(score: int) -> str:
    """Map a score in 1–25 onto the Phase 1 matrix. Does not accept a rating string."""
    if isinstance(score, bool) or not isinstance(score, int):
        raise ValueError("score must be an integer")
    if score < SCORE_MIN or score > SCORE_MAX:
        raise ValueError(
            f"score must be between {SCORE_MIN} and {SCORE_MAX} inclusive, got {score}"
        )
    for upper, rating in _RATING_UPPER_BOUNDS:
        if score <= upper:
            return rating
    raise ValueError(f"score {score} is outside the risk matrix")
