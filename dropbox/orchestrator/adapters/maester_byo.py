"""BYO Maester adapter. Named Entra tenants only. Same-day revoke. Never embed."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

from dropbox.orchestrator.scope import Scope

MAX_STDOUT_BYTES = 200_000
MAX_TENANTS = 5
MAX_SEEN = 20
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")
REVOKE = "same-day revoke standing keys after window_end"
_MAESTER_CMD = "Invoke-Maester -NonInteractive"


def on_path() -> bool:
    return shutil.which("maester") is not None or shutil.which("pwsh") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("maester")


def live_exec_permitted(scope: Scope) -> bool:
    return bool(scope.integrity.allow_live_exec) and os.environ.get("EVERGREEN_ORCH_LIVE", "0") == "1"


def _safe_id(raw: str) -> bool:
    t = (raw or "").strip()
    if not t or t.startswith("-") or t in {"<tenant>", "<account>"}:
        return False
    if "/" in t or "://" in t or ";" in t or "`" in t or "$" in t:
        return False
    return bool(_ID_RE.fullmatch(t))


def shard_brake(tenants: list[str]) -> str | None:
    if not tenants:
        return "empty_tenants"
    if len(tenants) > MAX_TENANTS:
        return "batch_too_large"
    if any(not _safe_id(str(t)) for t in tenants):
        return "unsafe_target"
    return None


def plan_command(tenants: list[str]) -> list[str]:
    # Tenant is recorded on the describe payload, never interpolated into -Command.
    if shutil.which("maester"):
        return ["maester", "--non-interactive"]
    return ["pwsh", "-NoProfile", "-NonInteractive", "-Command", _MAESTER_CMD]


def describe(scope: Scope, tenants: list[str] | None = None) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("maester")
    tool_ok = allowed(scope)
    named = list(tenants if tenants is not None else scope.entra_tenants)
    brake = shard_brake(named) if named else "empty_tenants"
    live = (
        live_exec_permitted(scope)
        and tool_ok
        and not missing
        and gate is None
        and brake is None
        and not scope.refuse_live()
    )
    return {
        "adapter": "maester_byo",
        "tool": "maester",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "on_path": not missing,
        "would_exec": live,
        "shard_brake": brake,
        "tenants": [t for t in named if _safe_id(t)][:MAX_TENANTS],
        "command": plan_command(named),
        "brake": "named Entra tenants only; same-day revoke; CIDR-only does not unlock Maester",
        "revoke": REVOKE,
        "note": (
            "BYO only; pack does not embed Maester. Same-day revoke after the window. "
            "record_seen only; do not invent findings. Tenant is not interpolated into -Command. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " maester not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
            + (f" brake={brake}." if brake else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def parse_record_seen(blob: str) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    for line in (blob or "").splitlines():
        low = line.lower()
        if "fail" not in low and "warning" not in low:
            continue
        text = line.strip()[:200]
        if not text:
            continue
        seen.append({"kind": "record_seen", "text": text})
        if len(seen) >= MAX_SEEN:
            break
    return seen


def execute(scope: Scope, tenants: list[str] | None = None, timeout: int | None = None) -> dict[str, Any]:
    """Named Entra tenant Maester only. record_seen. Never interpolate tenant into -Command."""
    desc = describe(scope, tenants)
    desc["executed"] = False
    desc["findings"] = []
    desc["record_seen"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    cmd = list(desc["command"])
    allowed_cmds = (
        ["maester", "--non-interactive"],
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", _MAESTER_CMD],
    )
    if cmd not in allowed_cmds:
        desc["shard_brake"] = "unsafe_command"
        return desc
    seconds = max(1, min(int(timeout or 120), 180))
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
    desc["revoke"] = REVOKE
    desc["stderr_bytes"] = len(proc.stderr or "")
    return desc
