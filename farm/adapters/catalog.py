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
    out: dict[str, dict[str, Any]] = {}
    for key, raw in slots.items():
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        if "invoke" not in row:
            row["invoke"] = bool(row.get("wired")) and row.get("scope_key") == "allow_tools"
        out[str(key)] = row
    return out


def wired_slots() -> dict[str, dict[str, Any]]:
    return {k: v for k, v in load_slots().items() if v.get("wired") is True}


def invoke_slots() -> dict[str, dict[str, Any]]:
    """Wired slots that may subprocess when allowlisted + on PATH."""
    return {k: v for k, v in wired_slots().items() if v.get("invoke") is True}


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


def farm_slot_status(allow_tools: list[str] | None = None, which=None) -> list[dict[str, Any]]:
    """Full SLOTS matrix: wired / invoke / PATH / allowlist. Never downloads."""
    import shutil

    which_fn = which or shutil.which
    allow = {str(t).strip().lower() for t in (allow_tools or []) if str(t).strip()}
    rows: list[dict[str, Any]] = []
    for name, slot in load_slots().items():
        binary = str(slot.get("binary") or name).lower()
        on_path = bool(which_fn(binary))
        invoke = bool(slot.get("invoke"))
        allowlisted = name in allow or binary in allow
        if not invoke:
            state = "file_drop"
        elif allowlisted and on_path:
            state = "present"
        elif allowlisted:
            state = "missing"
        else:
            state = "not-allowlisted"
        rows.append(
            {
                "slot": name,
                "binary": binary,
                "wired": bool(slot.get("wired")),
                "invoke": invoke,
                "allowlisted": allowlisted,
                "on_path": on_path,
                "license_class": str(slot.get("license_class") or ""),
                "scope_key": str(slot.get("scope_key") or ""),
                "sensor": slot.get("sensor"),
                "output_glob": slot.get("output_glob"),
                "state": state,
            }
        )
    return rows
