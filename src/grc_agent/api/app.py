"""FastAPI application factory. Use: uvicorn grc_agent.api.app:create_app --factory"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from grc_agent.agents.factory import create_risk_agent
from grc_agent.api.middleware import CorrelationIdMiddleware
from grc_agent.api.routes import router
from grc_agent.api.service import AssessmentNotFoundError
from grc_agent.config import Settings, get_settings
from grc_agent.db.session import create_db_engine, init_db, make_session_factory
from grc_agent.engine.risk_engine import RiskEngine
from grc_agent.llm.errors import OllamaResponseError, OllamaUnavailableError
from grc_agent.rag.embeddings import Embedder
from grc_agent.rag.wiring import build_startup_retriever


def create_app(
    settings: Settings | None = None,
    *,
    rag_embedder: Embedder | None = None,
    knowledge_dir: Path | None = None,
) -> FastAPI:
    """Build an API app bound to a specific SQLite database (tests pass a temp URL).

    RAG indexing runs only when ``GRC_RISK_AGENT=ollama`` and ``GRC_RAG_ENABLED=true``.
    ``rag_embedder`` and ``knowledge_dir`` are for tests; production omits them.
    """
    resolved = settings or get_settings()
    engine = init_db(create_db_engine(resolved.database_url))
    session_factory = make_session_factory(engine)

    app = FastAPI(
        title="GRC Agent API",
        description="Assessments persist in SQLite. POST /risk-assessments uses RiskAgent + RiskEngine.",
        version="0.3.0",
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.state.settings = resolved
    app.state.db_engine = engine
    app.state.session_factory = session_factory
    app.state.risk_engine = RiskEngine()
    app.state.risk_agent = create_risk_agent(resolved)
    app.state.retriever = build_startup_retriever(
        resolved,
        embedder=rag_embedder,
        knowledge_dir=knowledge_dir,
    )
    app.include_router(router)

    @app.exception_handler(AssessmentNotFoundError)
    async def assessment_not_found(_request: Request, exc: AssessmentNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"detail": f"Assessment '{exc.assessment_id}' was not found"},
        )

    @app.exception_handler(OllamaUnavailableError)
    async def ollama_unavailable(_request: Request, exc: OllamaUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.exception_handler(OllamaResponseError)
    async def ollama_bad_response(_request: Request, exc: OllamaResponseError) -> JSONResponse:
        return JSONResponse(status_code=502, content={"detail": str(exc)})

    return app
