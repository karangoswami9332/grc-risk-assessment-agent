"""FastAPI dependencies. Imported by routes; app.py only wires state."""

from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from grc_agent.engine.risk_engine import RiskEngine
from grc_agent.orchestrator import RiskOrchestrator


def get_session(request: Request):
    factory = request.app.state.session_factory
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_risk_engine(request: Request) -> RiskEngine:
    return request.app.state.risk_engine


def get_risk_orchestrator(
    request: Request,
    risk_engine: RiskEngine = Depends(get_risk_engine),
) -> RiskOrchestrator:
    """Phase 3 pipeline: configured RiskAgent + injected RiskEngine.

    ``app.state.retriever`` is set at startup. It is None unless Ollama RAG is on.
    """
    return RiskOrchestrator(
        request.app.state.risk_agent,
        risk_engine,
        retriever=request.app.state.retriever,
        rag_debug=request.app.state.settings.rag_debug,
    )
