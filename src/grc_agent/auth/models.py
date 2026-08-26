"""Identity and role models used by JWT validation and route policies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    ASSESSOR = "assessor"
    VIEWER = "viewer"


VALID_ROLES = frozenset({Role.ADMIN, Role.ASSESSOR, Role.VIEWER})


@dataclass(frozen=True)
class Principal:
    """Authenticated caller. Never includes the raw access token."""

    subject: str
    role: Role
    tenant_id: str


# Used when AUTH_ENABLED is false so local/dev/tests keep working without JWTs.
LOCAL_PRINCIPAL = Principal(subject="local", role=Role.ADMIN, tenant_id="local")
