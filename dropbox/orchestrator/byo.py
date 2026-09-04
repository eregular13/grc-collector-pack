"""BYO host-PATH adapters. Never apt, embed, or download scanners.

Discover may resolve nmap. Deepen may resolve nessus/nessuscli.
Both require the name in SCOPE.allow_tools for that stage.
Missing binary → plan-only. This module has no HTTP client and never downloads.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from dropbox.scope import DEEPEN_STAGE_TOOLS, DISCOVER_STAGE_TOOLS, GateError

# Integrity: this file must never grow a fetcher.
FORBIDDEN_IN_ADAPTER = (
    "apt-get",
    "apt install",
    "apk add",
    "curl http",
    "wget ",
    "pip install",
)

LOUD_DISCOVER_FLAGS = ("-sV", "-sC", "-A", "--script", "-p-", "--top-ports")


def which_allowed(
    name: str,
    allow_tools: list[str],
    which=shutil.which,
) -> tuple[str | None, str]:
    """Return (exe, reason). exe is set only when named in allow_tools and on PATH."""
    tool = (name or "").strip().lower()
    allow = {t.lower() for t in allow_tools}
    if tool not in allow:
        return None, "not in SCOPE.allow_tools for this stage"
    exe = which(tool)
    if not exe:
        return None, "not on PATH — plan only (will not download)"
    return exe, "on PATH"


def resolve_stage(
    stage: str,
    allow_tools: list[str],
    which=shutil.which,
) -> tuple[str | None, str, str]:
    """Pick the first allowed BYO binary for a stage. Never downloads."""
    if stage == "discover":
        names = [t for t in ("nmap",) if t in DISCOVER_STAGE_TOOLS]
    elif stage == "deepen":
        names = [t for t in ("nessus", "nessuscli") if t in DEEPEN_STAGE_TOOLS]
    else:
        raise GateError(f"unknown orchestrator stage {stage!r}")
    last = "not in SCOPE.allow_tools for this stage"
    for name in names:
        exe, reason = which_allowed(name, allow_tools, which=which)
        last = reason
        if exe:
            return exe, reason, name
    return None, last, names[0] if names else stage


def nmap_quiet_argv(exe: str, shard: str, timeout_sec: int) -> list[str]:
    argv = [exe, "-sn", "--host-timeout", f"{int(timeout_sec)}s", "-oG", "-", shard]
    joined = " ".join(argv)
    if any(flag in joined for flag in LOUD_DISCOVER_FLAGS):
        raise GateError("discover argv is not quiet")
    return argv


def nessus_batch_argv(exe: str, target: str, timeout_sec: int) -> list[str]:
    return [exe, "--batch", target, "--timeout", str(int(timeout_sec))]


def tool_matrix(allow_tools: list[str], which=shutil.which) -> list[dict]:
    """allow_tools ∩ PATH: present vs missing. Never downloads."""
    rows: list[dict] = []
    for name in allow_tools:
        tool = str(name).strip().lower()
        if not tool:
            continue
        exe = which(tool)
        rows.append(
            {
                "tool": tool,
                "allowlisted": True,
                "on_path": bool(exe),
                "state": "present" if exe else "missing",
                "path": exe or "",
            }
        )
    return rows


def run_allowed(
    argv: list[str],
    dest: Path,
    timeout: int,
    allow_tools: list[str] | None = None,
) -> int:
    """Run an allowlisted PATH binary; write stdout to dest. No download."""
    if not argv:
        raise ValueError("empty argv")
    joined = " ".join(str(a) for a in argv)
    low = joined.lower()
    for bad in FORBIDDEN_IN_ADAPTER:
        if bad in low:
            raise GateError(f"adapter refuses fetcher/installer: {bad}")
    tool = Path(str(argv[0])).name.lower()
    if allow_tools is not None:
        allow = {t.lower() for t in allow_tools}
        if tool not in allow:
            raise GateError(f"run_allowed refuses {tool}: not in SCOPE.allow_tools")
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [str(a) for a in argv],
        capture_output=True,
        text=True,
        timeout=max(1, int(timeout)),
        check=False,
    )
    dest.write_text((proc.stdout or "") or (proc.stderr or ""), encoding="utf-8")
    return int(proc.returncode)
