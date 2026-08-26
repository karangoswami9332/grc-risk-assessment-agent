"""HTTP middleware for correlation / request IDs."""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from grc_agent.observability.context import (
    CORRELATION_HEADER,
    clear_correlation_id,
    set_correlation_id,
)


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Attach ``X-Request-ID`` to the request context and response headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get(CORRELATION_HEADER, "").strip()
        correlation_id = set_correlation_id(incoming or str(uuid.uuid4()))
        request.state.correlation_id = correlation_id
        try:
            response = await call_next(request)
            response.headers[CORRELATION_HEADER] = correlation_id
            return response
        finally:
            # Prevent leakage across reused worker tasks/threads.
            clear_correlation_id()
