"""GRC Agent — AI-powered Governance, Risk, and Compliance assessment platform.

Phase 3 adds a mock RiskAgent and orchestrator. Scoring remains in RiskEngine.
Real LLM, RAG, and UI are added in later phases.
"""

from grc_agent.engine import RiskEngine
from grc_agent.models import (
    Asset,
    Control,
    GRCAssessment,
    InherentRisk,
    Risk,
    Threat,
    Vulnerability,
)

__version__ = "0.1.0"

__all__ = [
    "Asset",
    "Control",
    "GRCAssessment",
    "InherentRisk",
    "Risk",
    "RiskEngine",
    "Threat",
    "Vulnerability",
    "__version__",
]
