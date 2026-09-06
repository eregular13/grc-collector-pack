"""BYO Prowler adapter. Named cloud accounts only. Read-only. Same-day revoke. Never embed."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

from dropbox.orchestrator.scope import Scope

MAX_STDOUT_BYTES = 200_000
MAX_ACCOUNTS = 5
MAX_SEEN = 20
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
REVOKE = "same-day revoke standing keys after window_end"


def on_path() -> bool:
    return shutil.which("prowler") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("prowler")


def live_exec_permitted(scope: Scope) -> bool:
    return bool(scope.integrity.allow_live_exec) and os.environ.get("EVERGREEN_ORCH_LIVE", "0") == "1"


def _safe_id(raw: str) -> bool:
    t = (raw or "").strip()
    if not t or t.startswith("-") or t in {"<account>", "<tenant>"}:
        return False
    return bool(_ID_RE.fullmatch(t))


def shard_brake(accounts: list[str]) -> str | None:
    if not accounts:
        return "empty_accounts"
    if len(accounts) > MAX_ACCOUNTS:
        return "batch_too_large"
    if any(not _safe_id(str(a)) for a in accounts):
        return "unsafe_target"
    return None


def plan_command(accounts: list[str]) -> list[str]:
    safe = [a for a in accounts if _safe_id(a)][:MAX_ACCOUNTS]
    cmd = ["prowler", "aws", "--ignore-exit-code-3", "-M", "json-ocsf"]
    if safe:
        cmd.extend(["--", safe[0]])
    return cmd


def describe(scope: Scope, accounts: list[str] | None = None) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("prowler")
    tool_ok = allowed(scope)
    named = list(accounts if accounts is not None else scope.cloud_accounts)
    brake = shard_brake(named) if named else "empty_accounts"
    live = (
        live_exec_permitted(scope)
        and tool_ok
        and not missing
        and gate is None
        and brake is None
        and not scope.refuse_live()
    )
    return {
        "adapter": "prowler_byo",
        "tool": "prowler",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "on_path": not missing,
        "would_exec": live,
        "shard_brake": brake,
        "command": plan_command(named),
        "brake": "named cloud accounts only; read-only; same-day revoke standing keys",
        "revoke": REVOKE,
        "note": (
            "BYO only; pack does not embed Prowler. Same-day revoke after the window. "
            "record_seen only; do not invent findings. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " prowler not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
            + (f" brake={brake}." if brake else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def parse_record_seen(blob: str) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    for line in (blob or "").splitlines():
        low = line.lower()
        if "fail" not in low and "critical" not in low and "high" not in low:
            continue
        text = line.strip()[:200]
        if not text:
            continue
        seen.append({"kind": "record_seen", "text": text})
        if len(seen) >= MAX_SEEN:
            break
    return seen


def execute(scope: Scope, accounts: list[str] | None = None, timeout: int | None = None) -> dict[str, Any]:
    """Named-account Prowler only. record_seen. Never download. Never shell=True. Never invent findings."""
    desc = describe(scope, accounts)
    desc["executed"] = False
    desc["findings"] = []
    desc["record_seen"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    cmd = list(desc["command"])
    if not cmd or cmd[0] != "prowler":
        desc["shard_brake"] = "unsafe_command"
        return desc
    for tok in cmd[1:]:
        if str(tok).startswith("-") or tok in {"aws", "--"}:
            continue
        if not _safe_id(str(tok)):
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
