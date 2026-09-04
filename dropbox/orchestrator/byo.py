"""BYO host-PATH adapters. Never apt, embed, or download scanners.

Discover may resolve nmap. Deepen may resolve nessus/nessuscli.
Both require the name in SCOPE.allow_tools for that stage.
Missing binary → plan-only. This module has no HTTP client.
"""

from __future__ import annotations

import shutil

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
