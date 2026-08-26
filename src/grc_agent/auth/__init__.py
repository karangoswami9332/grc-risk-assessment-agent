"""Authentication and authorization for the FastAPI API (JWT / OIDC-ready)."""

from grc_agent.auth.models import LOCAL_PRINCIPAL, Principal, Role

__all__ = ["LOCAL_PRINCIPAL", "Principal", "Role"]
