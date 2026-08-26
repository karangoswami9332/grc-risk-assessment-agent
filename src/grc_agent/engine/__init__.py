"""Deterministic GRC rules. This package must not import LLM or agent code."""

from grc_agent.engine.risk_engine import RiskEngine

__all__ = ["RiskEngine"]
