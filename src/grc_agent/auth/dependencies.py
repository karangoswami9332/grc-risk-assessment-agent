"""FastAPI dependencies for authentication and role checks."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from grc_agent.auth.jwt_validator import AuthenticationError, validate_access_token
from grc_agent.auth.models import LOCAL_PRINCIPAL, Principal, Role
from grc_agent.auth.policies import can_read, can_run_risk_assessment, can_write
from grc_agent.config import Settings
from grc_agent.observability.audit import (
    AUTHENTICATION_FAILED,
    AUTHENTICATION_SUCCEEDED,
    AUTHORIZATION_DENIED,
    emit_audit_event,
)
from grc_agent.observability.context import get_correlation_id

_bearer = HTTPBearer(auto_error=False)


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    """Resolve the caller. When AUTH_ENABLED is false, returns LOCAL_PRINCIPAL."""
    settings = _settings(request)
    if not settings.auth_enabled:
        return LOCAL_PRINCIPAL

    path = request.url.path
    raw_header = request.headers.get("Authorization")
    if credentials is None:
        reason = "malformed_authorization" if raw_header else "missing_authorization"
        emit_audit_event(
            AUTHENTICATION_FAILED,
            reason=reason,
            path=path,
            correlation_id=get_correlation_id(),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if credentials.scheme.lower() != "bearer":
        emit_audit_event(
            AUTHENTICATION_FAILED,
            reason="malformed_authorization",
            path=path,
            correlation_id=get_correlation_id(),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        principal = validate_access_token(credentials.credentials, settings)
    except AuthenticationError as exc:
        emit_audit_event(
            AUTHENTICATION_FAILED,
            reason=exc.reason,
            path=path,
            correlation_id=get_correlation_id(),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    emit_audit_event(
        AUTHENTICATION_SUCCEEDED,
        subject=principal.subject,
        role=principal.role.value,
        tenant_id=principal.tenant_id,
        path=path,
        correlation_id=get_correlation_id(),
    )
    return principal


def require_roles(*roles: Role) -> Callable[..., Principal]:
    """Dependency factory: authenticated principal must have one of ``roles``."""

    allowed = frozenset(roles)

    def _dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if principal.role not in allowed:
            emit_audit_event(
                AUTHORIZATION_DENIED,
                subject=principal.subject,
                role=principal.role.value,
                tenant_id=principal.tenant_id,
                required_roles=sorted(role.value for role in allowed),
                correlation_id=get_correlation_id(),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return principal

    return _dependency


require_reader = require_roles(Role.ADMIN, Role.ASSESSOR, Role.VIEWER)
require_writer = require_roles(Role.ADMIN, Role.ASSESSOR)
require_risk_assessor = require_roles(Role.ADMIN, Role.ASSESSOR)


def assert_can_read(principal: Principal) -> None:
    if not can_read(principal):
        emit_audit_event(
            AUTHORIZATION_DENIED,
            subject=principal.subject,
            role=principal.role.value,
            tenant_id=principal.tenant_id,
            action="read",
            correlation_id=get_correlation_id(),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def assert_can_write(principal: Principal) -> None:
    if not can_write(principal):
        emit_audit_event(
            AUTHORIZATION_DENIED,
            subject=principal.subject,
            role=principal.role.value,
            tenant_id=principal.tenant_id,
            action="write",
            correlation_id=get_correlation_id(),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def assert_can_run_risk_assessment(principal: Principal) -> None:
    if not can_run_risk_assessment(principal):
        emit_audit_event(
            AUTHORIZATION_DENIED,
            subject=principal.subject,
            role=principal.role.value,
            tenant_id=principal.tenant_id,
            action="risk_assessment",
            correlation_id=get_correlation_id(),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
