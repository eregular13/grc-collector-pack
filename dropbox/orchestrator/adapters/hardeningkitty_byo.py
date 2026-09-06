"""BYO HardeningKitty Audit adapter. Endpoint sample only. record_seen; no invented findings."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from dropbox.orchestrator.scope import Scope

MAX_STDOUT_BYTES = 200_000
MAX_SEEN = 20
_KITTY_CMD = "Invoke-HardeningKitty -Mode Audit -FileFindingList HardeningKitty.csv"


def on_path() -> bool:
    return shutil.which("pwsh") is not None or shutil.which("powershell") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("hardeningkitty")


def live_exec_permitted(scope: Scope) -> bool:
    return bool(scope.integrity.allow_live_exec) and os.environ.get("EVERGREEN_ORCH_LIVE", "0") == "1"


def plan_command(endpoints: list[str]) -> list[str]:
    return ["powershell", "-NoProfile", "-Command", _KITTY_CMD]


def describe(scope: Scope, endpoints: list[str] | None = None) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("hardeningkitty")
    tool_ok = allowed(scope)
    live = (
        live_exec_permitted(scope)
        and tool_ok
        and not missing
        and gate is None
        and not scope.refuse_live()
    )
    return {
        "adapter": "hardeningkitty_byo",
        "tool": "hardeningkitty",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "on_path": not missing,
        "would_exec": live,
        "command": plan_command(endpoints or scope.internal_endpoints),
        "brake": "endpoint sample only; record_seen; do not invent findings",
        "note": (
            "BYO HardeningKitty Audit on the drop box. Pack does not embed it. "
            "record_seen only; do not invent findings. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " hardeningkitty not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def parse_record_seen(blob: str) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    for line in (blob or "").splitlines():
        if "fail" not in line.lower() and "warning" not in line.lower():
            continue
        text = line.strip()[:200]
        if not text:
            continue
        seen.append({"kind": "record_seen", "text": text})
        if len(seen) >= MAX_SEEN:
            break
    return seen


def execute(scope: Scope, endpoints: list[str] | None = None, timeout: int | None = None) -> dict[str, Any]:
    """HardeningKitty Audit on the drop-box endpoint. record_seen only. Never invent findings."""
    desc = describe(scope, endpoints)
    desc["executed"] = False
    desc["findings"] = []
    desc["record_seen"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    cmd = list(desc["command"])
    if cmd != ["powershell", "-NoProfile", "-Command", _KITTY_CMD]:
        desc["shard_brake"] = "unsafe_command"
        return desc
    seconds = max(1, min(int(timeout or 60), 120))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        desc["shard_brake"] = "timeout"
        desc["label"] = "live-byo-timeout"
        return desc
    except OSError as exc:
        desc["shard_brake"] = "exec_error"
        desc["error"] = type(exc).__name__
        return desc
    blob = (proc.stdout or "")[:MAX_STDOUT_BYTES]
    desc["executed"] = True
    desc["returncode"] = proc.returncode
    desc["record_seen"] = parse_record_seen(blob)
    desc["findings"] = []
    desc["label"] = "live-byo"
    desc["stderr_bytes"] = len(proc.stderr or "")
    return desc
