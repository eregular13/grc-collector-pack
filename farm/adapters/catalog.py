"""Load farm/SLOTS.yaml. Mapping form only. No binaries."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from dropbox.yaml_lite import load_yaml

FARM_ROOT = Path(__file__).resolve().parents[1]
SLOTS_PATH = FARM_ROOT / "SLOTS.yaml"
LICENSE_CLASSES = frozenset({"use_dont_ship", "commercial_byo", "oss_byo"})
REQUIRED_FIELDS = (
    "id",
    "binary",
    "stage",
    "scope_key",
    "output_glob",
    "license_class",
    "default_batch",
)


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    data = load_yaml(SLOTS_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("SLOTS.yaml must be a mapping")
    slots = data.get("slots") or {}
    if not isinstance(slots, dict):
        raise ValueError("slots must be a mapping")
    return data


def load_slots() -> dict[str, dict[str, Any]]:
    slots = load_catalog().get("slots") or {}
    return {str(k): dict(v) for k, v in slots.items() if isinstance(v, dict)}


def wired_slots() -> dict[str, dict[str, Any]]:
    return {k: v for k, v in load_slots().items() if v.get("wired") is True}


def slot_matrix(allow_tools: list[str], which=None) -> list[dict[str, Any]]:
    """allow_tools ∩ PATH ∩ SLOTS. Never downloads."""
    import shutil

    from dropbox.orchestrator import byo

    which_fn = which or shutil.which
    slots = load_slots()
    rows = byo.tool_matrix(allow_tools, which=which_fn)
    for row in rows:
        slot = slots.get(row["tool"]) or {}
        row["in_slots"] = row["tool"] in slots
        row["wired"] = bool(slot.get("wired"))
        row["license_class"] = str(slot.get("license_class") or "")
        if not row["in_slots"]:
            row["slot_state"] = "not-in-slots"
        elif row["on_path"]:
            row["slot_state"] = "present"
        else:
            row["slot_state"] = "missing"
    return rows
