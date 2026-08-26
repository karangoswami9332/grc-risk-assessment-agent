"""Structured security/audit event logging (stdlib logging only).

Never log secrets, Authorization headers, full prompts, full LLM responses,
or full assessment scenario text.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from grc_agent.observability.context import ensure_correlation_id

AUDIT_LOGGER_NAME = "grc_agent.observability.audit"
logger = logging.getLogger(AUDIT_LOGGER_NAME)

AUTHENTICATION_FAILED = "authentication_failed"
AUTHENTICATION_SUCCEEDED = "authentication_succeeded"
AUTHORIZATION_DENIED = "authorization_denied"

# Event names (stable for tests and operators).
ASSESSMENT_STARTED = "assessment_started"
RAG_RETRIEVAL_COMPLETED = "rag_retrieval_completed"
LLM_PROPOSAL_GENERATED = "llm_proposal_generated"
CONTROL_MAPPING_COMPLETED = "control_mapping_completed"
INVALID_CONTROL_ID_REJECTED = "invalid_control_id_rejected"
RISK_SCORED = "risk_scored"
ASSESSMENT_COMPLETED = "assessment_completed"
ASSESSMENT_FAILED = "assessment_failed"

# Never persist these keys even if a caller accidentally passes them.
_SENSITIVE_AUDIT_KEYS = frozenset(
    {
        "authorization",
        "authorization_header",
        "access_token",
        "refresh_token",
        "bearer",
        "token",
        "jwt",
        "password",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "jwt_secret",
        "jwt_public_key",
        "cookie",
        "cookies",
        "session",
        "claims",
        "payload",
    }
)


def scenario_fingerprint(scenario: str) -> str:
    """Stable non-reversible reference for a scenario (not the scenario text)."""
    digest = hashlib.sha256(scenario.encode("utf-8")).hexdigest()
    return digest[:16]


def emit_audit_event(event: str, **fields: Any) -> dict[str, Any]:
    """Emit one structured audit record as a single JSON log line."""
    payload: dict[str, Any] = {
        "event": event,
        "correlation_id": ensure_correlation_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    for key, value in fields.items():
        if value is None:
            continue
        if key.lower() in _SENSITIVE_AUDIT_KEYS:
            continue
        payload[key] = value
    logger.info("%s", json.dumps(payload, sort_keys=True, default=str))
    return payload


def parse_audit_records(caplog_text: str) -> list[dict[str, Any]]:
    """Parse JSON audit lines from a captured log blob (test helper)."""
    records: list[dict[str, Any]] = []
    for line in caplog_text.splitlines():
        text = line.strip()
        # pytest caplog may prefix logger name / level.
        if "{" in text:
            text = text[text.index("{") :]
        if not text.startswith("{"):
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "event" in payload:
            records.append(payload)
    return records
