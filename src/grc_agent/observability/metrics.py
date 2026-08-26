"""In-process counters for security observability. No external metrics stack."""

from __future__ import annotations

import threading
from collections import defaultdict


class MetricsRegistry:
    """Thread-safe integer counters (process-local only)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)

    def incr(self, name: str, amount: int = 1) -> None:
        if amount == 0:
            return
        with self._lock:
            self._counters[name] += amount

    def get(self, name: str) -> int:
        with self._lock:
            return int(self._counters.get(name, 0))

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()


_METRICS = MetricsRegistry()

# Counter names used by the orchestrator / API path.
ASSESSMENTS_TOTAL = "assessments_total"
ASSESSMENTS_FAILED_TOTAL = "assessments_failed_total"
LLM_FAILURES_TOTAL = "llm_failures_total"
INVALID_CONTROL_IDS_TOTAL = "invalid_control_ids_total"
MAPPED_CONTROLS_TOTAL = "mapped_controls_total"
RAG_RETRIEVALS_TOTAL = "rag_retrievals_total"


def get_metrics() -> MetricsRegistry:
    return _METRICS


def reset_metrics() -> None:
    _METRICS.reset()
