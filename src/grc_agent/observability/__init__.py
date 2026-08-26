"""Lightweight security observability: correlation IDs, audit logs, counters.

Does not change RiskEngine scoring, RAG retrieval, or control-mapping rules.
"""

from grc_agent.observability.audit import (
    AUDIT_LOGGER_NAME,
    emit_audit_event,
    parse_audit_records,
)
from grc_agent.observability.context import (
    CORRELATION_HEADER,
    clear_correlation_id,
    ensure_correlation_id,
    get_correlation_id,
    set_correlation_id,
)
from grc_agent.observability.metrics import MetricsRegistry, get_metrics, reset_metrics

__all__ = [
    "AUDIT_LOGGER_NAME",
    "CORRELATION_HEADER",
    "MetricsRegistry",
    "clear_correlation_id",
    "emit_audit_event",
    "ensure_correlation_id",
    "get_correlation_id",
    "get_metrics",
    "parse_audit_records",
    "reset_metrics",
    "set_correlation_id",
]
