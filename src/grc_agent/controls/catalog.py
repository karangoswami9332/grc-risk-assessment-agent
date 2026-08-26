"""Authoritative Internal GRC Control Catalog loader. Source of truth: controls.md."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from grc_agent.rag.ingest import CONTROL_CATALOG_FILENAME, default_knowledge_dir

_CONTROL_SECTION = re.compile(r"(?=^##\s+CTRL-[A-Z]+-\d+\b)", re.MULTILINE)
_CONTROL_ID = re.compile(r"CTRL-[A-Z]+-\d+")
_FIELD = re.compile(
    r"^\*\*(Control ID|Name|Objective|Control Type|Domain|Description|Example Implementation):\*\*\s*(.*)$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class CatalogControl:
    """One control from the Internal GRC Control Catalog."""

    control_id: str
    name: str
    objective: str = ""
    control_type: str = ""
    domain: str = ""
    description: str = ""
    example_implementation: str = ""


def default_controls_path() -> Path:
    return default_knowledge_dir() / CONTROL_CATALOG_FILENAME


def load_control_catalog(path: Path | None = None) -> dict[str, CatalogControl]:
    """Parse ``controls.md`` into ``{control_id: CatalogControl}``.

    The markdown file is the source of truth; IDs are not hard-coded in Python.
    """
    catalog_path = path or default_controls_path()
    text = catalog_path.read_text(encoding="utf-8")
    catalog: dict[str, CatalogControl] = {}
    for part in _CONTROL_SECTION.split(text):
        section = part.strip()
        section = re.sub(r"^---\s*", "", section)
        section = re.sub(r"\s*---\s*$", "", section)
        section = section.strip()
        if not section or not section.lstrip().startswith("## CTRL-"):
            continue
        entry = _parse_control_section(section)
        if entry is None:
            continue
        if entry.control_id in catalog:
            raise ValueError(f"Duplicate control id in catalog: {entry.control_id}")
        catalog[entry.control_id] = entry
    return catalog


@lru_cache(maxsize=1)
def get_control_catalog() -> dict[str, CatalogControl]:
    """Cached catalog from the default ``data/knowledge/controls.md`` path."""
    return load_control_catalog()


def extract_control_ids_from_text(text: str) -> list[str]:
    """Return unique control IDs found in text, in first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for match in _CONTROL_ID.findall(text):
        if match not in seen:
            seen.add(match)
            ordered.append(match)
    return ordered


def _parse_control_section(section: str) -> CatalogControl | None:
    fields: dict[str, str] = {}
    for match in _FIELD.finditer(section):
        key = match.group(1)
        value = match.group(2).strip()
        fields[key] = value
    control_id = fields.get("Control ID", "").strip()
    if not control_id:
        heading = _CONTROL_ID.search(section)
        if heading:
            control_id = heading.group(0)
    name = fields.get("Name", "").strip()
    if not control_id or not name:
        return None
    return CatalogControl(
        control_id=control_id,
        name=name,
        objective=fields.get("Objective", ""),
        control_type=fields.get("Control Type", ""),
        domain=fields.get("Domain", ""),
        description=fields.get("Description", ""),
        example_implementation=fields.get("Example Implementation", ""),
    )
