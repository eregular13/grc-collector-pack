"""Load farm/SLOTS.yaml. Mapping form only. No binaries."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from dropbox.scope import FORBIDDEN_TOOLS
from dropbox.yaml_lite import load_yaml

FARM_ROOT = Path(__file__).resolve().parents[1]
SLOTS_PATH = FARM_ROOT / "SLOTS.yaml"
LICENSE_CLASSES = frozenset({"use_dont_ship", "commercial_byo", "oss_byo"})
LAYER_C_SENSORS = frozenset(
    {"cloud", "nmap", "vuln", "wazuh", "identity", "easm", "k8s", "code", "saas"}
)
FILE_DROP_ONLY = frozenset(
    {"nikto", "gobuster", "ffuf", "amass", "subfinder", "scoutsuite", "checkov"}
)
# Never live-subprocess these, even if allowlisted somehow.
LICENSE_LOCK_LIVE = frozenset(FORBIDDEN_TOOLS) | {
    "nuclei",
    "openvas",
    "gvm",
    "gvmd",
    "pingcastle",
    "purpleknight",
    "bloodhound",
    "osqueryi",
}
DISCOVER_PREFER = ("nmap", "rustscan", "naabu")
DEEPEN_PREFER = ("nessus", "nessuscli")
PLAN_STAGES = ("discover", "deepen", "external")
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
        if key in FILE_DROP_ONLY:
            row["wired"] = False
            row["invoke"] = False
            row["scope_key"] = "file_drop"
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


def refuse_live_slot(slot_id: str, binary: str | None = None) -> str | None:
    """Return a refuse reason, or None if the slot may be considered for live."""
    name = (slot_id or "").strip().lower()
    bin_name = (binary or name).strip().lower()
    if name in LICENSE_LOCK_LIVE or bin_name in LICENSE_LOCK_LIVE:
        return f"LICENSE-LOCK: never subprocess {name or bin_name}"
    if name in FILE_DROP_ONLY or bin_name in FILE_DROP_ONLY:
        return f"file_drop only: never subprocess {name or bin_name}"
    return None


def select_stage_slots(
    stage: str,
    allow_tools: list[str] | None = None,
    which=None,
) -> dict[str, Any]:
    """allow_tools ∩ wired invoke ∩ stage. Missing PATH stays selected with will_run false."""
    import shutil

    which_fn = which or shutil.which
    want = str(stage or "").strip().lower()
    allow = {str(t).strip().lower() for t in (allow_tools or []) if str(t).strip()}
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for name, slot in load_slots().items():
        cat = str(slot.get("category") or slot.get("stage") or "").lower()
        if cat != want:
            continue
        binary = str(slot.get("binary") or name).lower()
        refuse = refuse_live_slot(name, binary)
        allowlisted = name in allow or binary in allow
        invoke = bool(slot.get("invoke")) and bool(slot.get("wired"))
        if refuse:
            skipped.append(
                {
                    "slot": name,
                    "binary": binary,
                    "will_run": False,
                    "state": "file_drop",
                    "reason": refuse,
                }
            )
            continue
        if not invoke:
            skipped.append(
                {
                    "slot": name,
                    "binary": binary,
                    "will_run": False,
                    "state": "file_drop",
                    "reason": "file_drop (not a callable adapter)",
                }
            )
            continue
        if not allowlisted:
            skipped.append(
                {
                    "slot": name,
                    "binary": binary,
                    "will_run": False,
                    "state": "not-allowlisted",
                    "reason": "not in SCOPE.allow_tools",
                }
            )
            continue
        on_path = bool(which_fn(binary))
        selected.append(
            {
                "slot": name,
                "binary": binary,
                "will_run": on_path,
                "allowlisted": True,
                "on_path": on_path,
                "state": "present" if on_path else "missing",
                "reason": "" if on_path else "not on PATH — plan only (will not download)",
            }
        )
    prefer = DISCOVER_PREFER if want == "discover" else DEEPEN_PREFER if want == "deepen" else ()
    rank = {name: index for index, name in enumerate(prefer)}
    selected.sort(key=lambda row: (rank.get(row["slot"], 99), row["slot"]))
    skipped.sort(key=lambda row: row["slot"])
    ready = [row["slot"] for row in selected if row.get("will_run")]
    return {
        "stage": want,
        "selected": selected,
        "skipped": skipped,
        "ready": ready,
        "primary": ready[0] if ready else "",
    }


def plan_stage_slots(allow_tools: list[str] | None = None, which=None) -> dict[str, Any]:
    """Discover / deepen / external slot plans for orchestrate summary."""
    return {stage: select_stage_slots(stage, allow_tools, which=which) for stage in PLAN_STAGES}


def farm_slot_status(
    allow_tools: list[str] | None = None,
    which=None,
    category: str | None = None,
) -> list[dict[str, Any]]:
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
                "category": str(slot.get("category") or slot.get("stage") or ""),
                "sensor": slot.get("sensor"),
                "output_glob": slot.get("output_glob"),
                "state": state,
            }
        )
    if category:
        want = str(category).strip().lower()
        rows = [row for row in rows if str(row.get("category") or "").lower() == want]
    return rows


def audit_output_globs() -> list[str]:
    """Return slots whose output_glob is not in/<Layer-C-sensor>/…"""
    hits: list[str] = []
    for name, slot in load_slots().items():
        glob = str(slot.get("output_glob") or "")
        sensor = str(slot.get("sensor") or "")
        if sensor not in LAYER_C_SENSORS:
            hits.append(f"{name}: sensor {sensor!r} is not a Layer C dir")
            continue
        prefix = f"in/{sensor}/"
        if not glob.startswith(prefix):
            hits.append(f"{name}: output_glob {glob!r} does not land in {prefix}")
    return hits


def catalog_summary() -> dict[str, Any]:
    """Counts for conductor + SLOTS.md. No binaries."""
    slots = load_slots()
    by_category: dict[str, dict[str, int]] = {}
    wired = invoke = file_drop = 0
    for slot in slots.values():
        cat = str(slot.get("category") or slot.get("stage") or "other")
        bucket = by_category.setdefault(cat, {"total": 0, "wired": 0, "invoke": 0, "file_drop": 0})
        bucket["total"] += 1
        if slot.get("wired"):
            wired += 1
            bucket["wired"] += 1
        if slot.get("invoke"):
            invoke += 1
            bucket["invoke"] += 1
        else:
            file_drop += 1
            bucket["file_drop"] += 1
    return {
        "total": len(slots),
        "wired": wired,
        "invoke": invoke,
        "file_drop": file_drop,
        "by_category": dict(sorted(by_category.items())),
    }


BRAKES_DEFAULTS = (
    ("scope", "dropbox/SCOPE.yaml required"),
    ("deepen", "stages.deepen default false; live needs flag + allow_tools"),
    ("max_workers", "2"),
    ("deepen_batch", "3 (must be 2-5)"),
    ("host_timeout_sec", "30"),
    ("wildcard_cidr", "external named hosts only; refuse 0.0.0.0/0 and /8-/16 spray"),
    ("byo_path", "allow_tools ∩ PATH; missing → plan-only; never apt/embed"),
    ("license_lock", "never embed scanners; nuclei/openvas/osquery stay file_drop"),
    ("wrap", "push_riskready.sh review-only; never POST"),
    ("external_ingest", "file-drop inventory of in/easm|…; never probe"),
    ("layer_c", "parse-only ingest into in/<sensor>/"),
    ("compose", "scanner-free; runtime ABSENT without Docker CLI"),
)


def brakes_defaults() -> dict[str, str]:
    """Structured brakes table. Matches farm/INTEGRITY.md. No binaries."""
    return {key: value for key, value in BRAKES_DEFAULTS}


def ingest_map() -> dict[str, dict[str, int]]:
    """Slot counts by Layer C sensor dir. No theater sensors."""
    slots = load_slots()
    by_sensor: dict[str, dict[str, int]] = {
        sensor: {"total": 0, "invoke": 0, "file_drop": 0} for sensor in sorted(LAYER_C_SENSORS)
    }
    for slot in slots.values():
        sensor = str(slot.get("sensor") or "")
        bucket = by_sensor.setdefault(sensor, {"total": 0, "invoke": 0, "file_drop": 0})
        bucket["total"] += 1
        if slot.get("invoke"):
            bucket["invoke"] += 1
        else:
            bucket["file_drop"] += 1
    return by_sensor


SKIP_DROP_NAMES = frozenset({".gitkeep", "plan.json", "summary.json"})


def parse_output_glob(output_glob: str) -> tuple[str, str] | None:
    """`in/easm/*.jsonl` → (`easm`, `*.jsonl`). Refuse unknown sensors."""
    text = str(output_glob or "").strip()
    if not text.startswith("in/"):
        return None
    rest = text[3:]
    if "/" not in rest:
        return None
    sensor, pattern = rest.split("/", 1)
    if sensor not in LAYER_C_SENSORS or not pattern:
        return None
    return sensor, pattern


def dropped_file_inventory(dest_in: Path, category: str = "external") -> dict[str, Any]:
    """List operator-dropped files already in dest_in. Never probes. Never subprocess."""
    want = str(category or "").strip().lower()
    sensors: dict[str, list[str]] = {}
    for _name, slot in load_slots().items():
        cat = str(slot.get("category") or slot.get("stage") or "").lower()
        if cat != want:
            continue
        parsed = parse_output_glob(str(slot.get("output_glob") or ""))
        if not parsed:
            continue
        sensor, pattern = parsed
        folder = dest_in / sensor
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob(pattern)):
            if not path.is_file() or path.name in SKIP_DROP_NAMES:
                continue
            bucket = sensors.setdefault(sensor, [])
            if path.name not in bucket:
                bucket.append(path.name)
    files = [f"{sensor}/{name}" for sensor, names in sorted(sensors.items()) for name in names]
    return {
        "category": want,
        "file_count": len(files),
        "files": files,
        "sensors": {sensor: list(names) for sensor, names in sorted(sensors.items())},
        "will_run": False,
        "live": False,
        "probed": False,
        "note": (
            "Operator file-drop inventory only. Orchestrator does not probe. "
            "Land artifacts in in/easm|… then Layer C parses."
        ),
    }


def render_slots_md() -> str:
    summary = catalog_summary()
    lines = [
        "# Farm SLOTS catalog",
        "",
        "Private drop-box tool zoo. **No binaries in git.** Most slots are file_drop:",
        "the operator lands artifacts in `in/<sensor>/` for Layer C.",
        "",
        f"Total: {summary['total']}",
        f"Wired: {summary['wired']}",
        f"Invoke: {summary['invoke']}",
        f"File-drop: {summary['file_drop']}",
        "",
        "## By category",
        "",
        "| category | total | wired | invoke | file_drop |",
        "|---|---:|---:|---:|---:|",
    ]
    for cat, bucket in summary["by_category"].items():
        lines.append(
            f"| {cat} | {bucket['total']} | {bucket['wired']} | {bucket['invoke']} | {bucket['file_drop']} |"
        )
    lines.extend(
        [
            "",
            "## Ingest map (Layer C)",
            "",
            "Every `output_glob` lands in an existing Layer C sensor directory.",
            "`audit_output_globs()` is empty. No theater parsers.",
            "",
            "| sensor | total | invoke | file_drop |",
            "|---|---:|---:|---:|",
        ]
    )
    for sensor, bucket in ingest_map().items():
        lines.append(
            f"| in/{sensor}/ | {bucket['total']} | {bucket['invoke']} | {bucket['file_drop']} |"
        )
    lines.extend(
        [
            "",
            "File-drop only (never subprocess even if on PATH): "
            + ", ".join(sorted(FILE_DROP_ONLY))
            + ".",
            "",
            "LICENSE-LOCK names stay file_drop and are never subprocessed.",
            "See `SLOTS.yaml`, `INTEGRITY.md`, and `OPERATOR.md`.",
            "",
        ]
    )
    return "\n".join(lines)


def write_slots_md() -> Path:
    dest = FARM_ROOT / "SLOTS.md"
    dest.write_text(render_slots_md(), encoding="utf-8")
    return dest
