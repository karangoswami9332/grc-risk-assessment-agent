"""Authorization helpers. Fail closed with HTTP 403; never log tokens."""

from __future__ import annotations

from grc_agent.auth.models import Principal, Role
from grc_agent.db.tables import AssessmentRow

# Roles allowed to create assessments / append children / run orchestrator.
WRITE_ROLES = frozenset({Role.ADMIN, Role.ASSESSOR})
# Roles allowed to read assessments (still tenant-scoped except admin).
READ_ROLES = frozenset({Role.ADMIN, Role.ASSESSOR, Role.VIEWER})
# Roles allowed to POST /risk-assessments.
RISK_ASSESS_ROLES = frozenset({Role.ADMIN, Role.ASSESSOR})


def can_write(principal: Principal) -> bool:
    return principal.role in WRITE_ROLES


def can_read(principal: Principal) -> bool:
    return principal.role in READ_ROLES


def can_run_risk_assessment(principal: Principal) -> bool:
    return principal.role in RISK_ASSESS_ROLES


def can_access_assessment(principal: Principal, row: AssessmentRow) -> bool:
    """Tenant isolation: admin may cross tenants; others only their tenant."""
    if principal.role == Role.ADMIN:
        return True
    return row.tenant_id == principal.tenant_id


def can_modify_assessment(principal: Principal, row: AssessmentRow) -> bool:
    if not can_write(principal):
        return False
    return can_access_assessment(principal, row)
