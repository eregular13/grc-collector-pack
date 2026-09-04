"""Callable slot stubs. Plan-only unless allowlisted + on PATH. Never download."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable

from dropbox.orchestrator import byo
from dropbox.scope import FORBIDDEN_TOOLS, GateError
from farm.adapters.catalog import load_slots

Which = Callable[[str], str | None]


def argv_for(slot_id: str, exe: str, target: str, timeout: int) -> list[str]:
    """Quiet/capture argv for a wired slot. No installer flags."""
    name = (slot_id or "").strip().lower()
    timeout = max(1, int(timeout))
    if name in FORBIDDEN_TOOLS:
        raise GateError(f"LICENSE-LOCK: farm adapter refuses {name!r}")
    if name == "nmap":
        return byo.nmap_quiet_argv(exe, target, timeout)
    if name in {"nessus", "nessuscli"}:
        return byo.nessus_batch_argv(exe, target, timeout)
    if name == "curl":
        url = target if "://" in target else f"https://{target}"
        return byo.curl_header_argv(exe, url, timeout)
    if name in {"testssl", "testssl.sh"}:
        return byo.testssl_argv(exe, target, timeout)
    if name == "lynis":
        return [exe, "audit", "system", "--quick", "--no-colors"]
    if name == "ss":
        return [exe, "-lntH"]
    if name == "ip":
        return [exe, "-br", "addr"]
    if name == "prowler":
        return [exe, "aws", "-M", "json"]
    if name == "hardeningkitty-export":
        return [exe, "--export", str(target)]
    if name == "maester":
        return [exe, "--output", str(target)]
    if name == "trivy":
        return [exe, "fs", "--format", "json", "--offline-scan", str(target)]
    raise GateError(f"no adapter argv for slot {slot_id!r}")


def run_slot(
    slot_id: str,
    dest: Path,
    allow_tools: list[str],
    target: str = ".",
    timeout: int = 8,
    live: bool = False,
    which: Which | None = None,
) -> dict[str, Any]:
    """Invoke one wired slot or stay plan-only. Forbidden tools never run."""
    which_fn = which or shutil.which
    slots = load_slots()
    name = (slot_id or "").strip().lower()
    slot = slots.get(name)
    if not slot:
        raise GateError(f"unknown farm slot {slot_id!r}")
    binary = str(slot.get("binary") or name).lower()
    if binary in FORBIDDEN_TOOLS or name in FORBIDDEN_TOOLS:
        raise GateError(f"LICENSE-LOCK: farm adapter refuses {name!r}")
    if slot.get("wired") is not True:
        return {
            "slot": name,
            "mode": "catalog",
            "ran": False,
            "tool_ready": False,
            "skip_reason": "file-drop only (not a callable adapter)",
            "sensor": slot.get("sensor"),
            "output_glob": slot.get("output_glob"),
        }
    exe, reason = byo.which_allowed(binary, allow_tools, which=which_fn)
    if not exe:
        return {
            "slot": name,
            "mode": "plan",
            "ran": False,
            "tool_ready": False,
            "skip_reason": reason,
            "sensor": slot.get("sensor"),
            "output_glob": slot.get("output_glob"),
        }
    if not live:
        return {
            "slot": name,
            "mode": "plan",
            "ran": False,
            "tool_ready": True,
            "skip_reason": "plan-only (live=false)",
            "sensor": slot.get("sensor"),
            "output_glob": slot.get("output_glob"),
        }
    argv = argv_for(name, exe, target, timeout)
    dest = Path(dest)
    rc = byo.run_allowed(argv, dest, timeout, allow_tools=allow_tools)
    return {
        "slot": name,
        "mode": "live",
        "ran": True,
        "tool_ready": True,
        "rc": rc,
        "dest": str(dest),
        "sensor": slot.get("sensor"),
        "output_glob": slot.get("output_glob"),
        "argv": argv,
    }
