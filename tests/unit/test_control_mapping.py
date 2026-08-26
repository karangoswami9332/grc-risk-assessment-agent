"""Control catalog parsing and deterministic mapping validation."""

from __future__ import annotations

from grc_agent.controls.catalog import (
    extract_control_ids_from_text,
    get_control_catalog,
    load_control_catalog,
)
from grc_agent.controls.mapping import MappedControl, resolve_mapped_controls
from grc_agent.rag.ingest import default_knowledge_dir

EXPECTED_IDS = (
    "CTRL-AC-001",
    "CTRL-AC-002",
    "CTRL-AC-003",
    "CTRL-CLD-001",
    "CTRL-CLD-002",
    "CTRL-CLD-003",
    "CTRL-DAT-001",
    "CTRL-DAT-002",
    "CTRL-DAT-003",
    "CTRL-MON-001",
)


def test_catalog_parser_loads_all_ten_controls() -> None:
    catalog = load_control_catalog(default_knowledge_dir() / "controls.md")
    assert set(catalog) == set(EXPECTED_IDS)
    assert len(catalog) == 10
    assert catalog["CTRL-CLD-001"].name == "Block Public Access to Cloud Storage"
    assert catalog["CTRL-AC-002"].name == "Require Multi-Factor Authentication"


def test_get_control_catalog_matches_file() -> None:
    assert set(get_control_catalog()) == set(EXPECTED_IDS)


def test_valid_control_id_accepted() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-001"],
        candidate_control_ids={"CTRL-CLD-001", "CTRL-CLD-002"},
        catalog=get_control_catalog(),
    )
    assert mapped == [
        MappedControl(
            control_id="CTRL-CLD-001",
            name="Block Public Access to Cloud Storage",
        )
    ]


def test_unknown_control_id_rejected() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-999"],
        candidate_control_ids={"CTRL-CLD-001", "CTRL-CLD-999"},
        catalog=get_control_catalog(),
    )
    assert mapped == []


def test_authoritative_name_overrides_llm_name() -> None:
    # LLM names are never inputs to resolve_mapped_controls — only IDs.
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-001"],
        candidate_control_ids=["CTRL-CLD-001"],
        catalog=get_control_catalog(),
    )
    assert mapped[0].name == "Block Public Access to Cloud Storage"
    assert mapped[0].name != "Some invented name"


def test_catalog_id_not_in_candidates_rejected() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-AC-001"],
        candidate_control_ids={"CTRL-CLD-001"},
        catalog=get_control_catalog(),
    )
    assert mapped == []


def test_empty_selection_yields_empty_mapping() -> None:
    assert (
        resolve_mapped_controls(
            [],
            candidate_control_ids={"CTRL-CLD-001"},
            catalog=get_control_catalog(),
        )
        == []
    )


def test_multiple_valid_controls_preserved_and_deduped() -> None:
    mapped = resolve_mapped_controls(
        ["CTRL-CLD-001", "CTRL-CLD-002", "CTRL-CLD-001", "CTRL-CLD-003"],
        candidate_control_ids={
            "CTRL-CLD-001",
            "CTRL-CLD-002",
            "CTRL-CLD-003",
        },
        catalog=get_control_catalog(),
    )
    assert [item.control_id for item in mapped] == [
        "CTRL-CLD-001",
        "CTRL-CLD-002",
        "CTRL-CLD-003",
    ]


def test_extract_control_ids_from_retrieved_context() -> None:
    context = (
        "[1] source=controls.md\n"
        "## CTRL-CLD-001 — Block Public Access\n"
        "**Control ID:** CTRL-CLD-001\n\n"
        "[2] source=controls.md\n"
        "## CTRL-CLD-002 — Review Cloud IAM\n"
    )
    assert extract_control_ids_from_text(context) == ["CTRL-CLD-001", "CTRL-CLD-002"]
