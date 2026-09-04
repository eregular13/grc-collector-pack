from __future__ import annotations

import shutil
from pathlib import Path


def available(allow_tools: list[str]) -> tuple[bool, str]:
    if "nessus" not in allow_tools:
        return False, "nessus not in allow_tools"
    if not (shutil.which("nessuscli") or shutil.which("nessus")):
        return False, "nessus/nessuscli not on PATH (BYO only; will not install)"
    return True, "nessus present"


def run_deepen(hosts: list[str], out_dir: Path, allow_tools: list[str]) -> dict:
    ok, reason = available(allow_tools)
    if not ok:
        return {"adapter": "nessus_byo", "ran": False, "reason": reason, "hosts": hosts}
    return {
        "adapter": "nessus_byo",
        "ran": False,
        "reason": "live nessus invoke is operator-HITL only; fixture deepen for lab",
        "hosts": hosts,
        "out": str(out_dir),
    }
