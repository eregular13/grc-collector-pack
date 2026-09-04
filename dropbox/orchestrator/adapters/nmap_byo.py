from __future__ import annotations

import shutil
from pathlib import Path


def available(allow_tools: list[str]) -> tuple[bool, str]:
    if "nmap" not in allow_tools:
        return False, "nmap not in allow_tools"
    if not shutil.which("nmap"):
        return False, "nmap not on PATH (BYO only; will not install)"
    return True, "nmap present"


def run_discover(targets: list[str], out_dir: Path, allow_tools: list[str]) -> dict:
    ok, reason = available(allow_tools)
    if not ok:
        return {"adapter": "nmap_byo", "ran": False, "reason": reason, "live": []}
    # Consent + PATH still do not auto-scan from CI. Caller must opt into live.
    return {
        "adapter": "nmap_byo",
        "ran": False,
        "reason": "live nmap invoke is operator-HITL only; use noop_discover for lab",
        "live": [],
        "binary": "nmap",
        "targets": targets,
        "out": str(out_dir),
    }
