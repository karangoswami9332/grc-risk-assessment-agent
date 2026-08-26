"""Deterministic validation of LLM-selected control IDs against the catalog."""

from __future__ import annotations

from dataclasses import dataclass

from grc_agent.controls.catalog import CatalogControl, get_control_catalog


@dataclass(frozen=True)
class MappedControl:
    """Authoritative control metadata after validation (never LLM-invented names)."""

    control_id: str
    name: str


def resolve_mapped_controls(
    selected_control_ids: list[str],
    *,
    candidate_control_ids: set[str] | list[str],
    catalog: dict[str, CatalogControl] | None = None,
) -> list[MappedControl]:
    """Accept IDs that exist in both the catalog and the retrieved candidate set.

    - Unknown IDs are rejected.
    - IDs not present in the retrieved RAG candidate set are rejected.
    - Names always come from the authoritative catalog (LLM names ignored).
    - Duplicates are removed while preserving first-seen order.
    - Empty selection yields an empty list (assessment still succeeds).
    """
    resolved_catalog = catalog if catalog is not None else get_control_catalog()
    candidates = set(candidate_control_ids)
    mapped: list[MappedControl] = []
    seen: set[str] = set()
    for raw_id in selected_control_ids:
        control_id = raw_id.strip()
        if not control_id or control_id in seen:
            continue
        seen.add(control_id)
        if control_id not in candidates:
            continue
        entry = resolved_catalog.get(control_id)
        if entry is None:
            continue
        mapped.append(MappedControl(control_id=entry.control_id, name=entry.name))
    return mapped
