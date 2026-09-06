"""BYO listening-ports adapter (ss / Get-NetTCPConnection). record_seen; never a public port scan."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

from dropbox.orchestrator.scope import Scope

MAX_STDOUT_BYTES = 100_000
MAX_SEEN = 20
_PORT_RE = re.compile(r":(\d+)\s")
_PS_PORT_RE = re.compile(r"LocalPort\s*:\s*(\d+)", re.I)


def on_path() -> bool:
    return shutil.which("ss") is not None or shutil.which("powershell") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("ss")


def live_exec_permitted(scope: Scope) -> bool:
    return bool(scope.integrity.allow_live_exec) and os.environ.get("EVERGREEN_ORCH_LIVE", "0") == "1"


def plan_command() -> list[str]:
    if shutil.which("ss") is not None:
        return ["ss", "-lnt"]
    return ["powershell", "-NoProfile", "-Command", "Get-NetTCPConnection -State Listen"]


def describe(scope: Scope, hosts: list[str] | None = None) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("ss")
    tool_ok = allowed(scope)
    live = (
        live_exec_permitted(scope)
        and tool_ok
        and not missing
        and gate is None
        and not scope.refuse_live()
    )
    return {
        "adapter": "ss_byo",
        "tool": "ss",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "on_path": not missing,
        "would_exec": live,
        "command": plan_command(),
        "hosts": list(hosts or scope.internal_hosts)[:5],
        "brake": "named internal hosts/endpoints only; not a public port scan",
        "note": (
            "BYO ss or Get-NetTCPConnection on the drop box. Pack does not embed a scanner. "
            "record_seen only; do not invent findings. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " ss not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def parse_record_seen(blob: str) -> list[dict[str, Any]]:
    ports: list[str] = []
    for line in (blob or "").splitlines():
        if "listen" not in line.lower() and "localport" not in line.lower():
            continue
        found = _PS_PORT_RE.findall(line) or _PORT_RE.findall(line)
        for port in found:
            if port not in ports:
                ports.append(port)
        if len(ports) >= MAX_SEEN:
            break
    return [{"kind": "record_seen", "port": p, "state": "listen"} for p in ports]


def execute(scope: Scope, hosts: list[str] | None = None, timeout: int | None = None) -> dict[str, Any]:
    """Local listen table on the drop box. record_seen only. Never shell=True."""
    desc = describe(scope, hosts)
    desc["executed"] = False
    desc["findings"] = []
    desc["record_seen"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    cmd = list(desc["command"])
    if not cmd or cmd[0] not in {"ss", "powershell", "powershell.exe"}:
        desc["shard_brake"] = "unsafe_command"
        return desc
    seconds = max(1, min(int(timeout or 30), 60))
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
