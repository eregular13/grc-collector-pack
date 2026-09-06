"""BYO testssl.sh adapter. Named internet-facing hosts/URLs only. Never CIDRs."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse

from dropbox.orchestrator.scope import Scope

MAX_DEEPEN_TARGETS = 5
MAX_STDOUT_BYTES = 2_000_000
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")


def binary_name() -> str:
    if shutil.which("testssl.sh"):
        return "testssl.sh"
    if shutil.which("testssl"):
        return "testssl"
    return "testssl.sh"


def on_path() -> bool:
    return shutil.which("testssl.sh") is not None or shutil.which("testssl") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("testssl")


def live_exec_permitted(scope: Scope) -> bool:
    return bool(scope.integrity.allow_live_exec) and os.environ.get("EVERGREEN_ORCH_LIVE", "0") == "1"


def _looks_like_cidr(target: str) -> bool:
    text = target.strip()
    if "/" not in text:
        return False
    prefix, _, bits = text.partition("/")
    return bits.isdigit() and any(ch.isdigit() or ch == ":" for ch in prefix)


def _safe_external(raw: str) -> bool:
    t = (raw or "").strip()
    if not t or t.startswith("-") or t in {"<host>", "<url>"}:
        return False
    if _looks_like_cidr(t):
        return False
    if "://" in t:
        if not t.lower().startswith(("https://", "http://")):
            return False
        parsed = urlparse(t)
        host = parsed.hostname or ""
        if parsed.username or parsed.password:
            return False
        t = host
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return bool(_HOST_RE.fullmatch(t))


def shard_brake(batch: list[str]) -> str | None:
    if not batch:
        return "empty_batch"
    if len(batch) > MAX_DEEPEN_TARGETS:
        return "batch_too_large"
    cidrs = [t for t in batch if _looks_like_cidr(str(t))]
    if cidrs:
        return "cidr_refused"
    if any(not _safe_external(str(t)) for t in batch):
        return "unsafe_target"
    return None


def plan_command(targets: list[str]) -> list[str]:
    safe = [t for t in targets if _safe_external(t)][:MAX_DEEPEN_TARGETS]
    return [binary_name(), "--fast", "--quiet", *(safe or ["<host>"])]


def describe(scope: Scope, batch: list[str]) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("testssl")
    cidrs = [t for t in batch if _looks_like_cidr(str(t))]
    tool_ok = allowed(scope)
    brake = shard_brake(batch) if batch else "empty_batch"
    live = (
        live_exec_permitted(scope)
        and tool_ok
        and not missing
        and gate is None
        and brake is None
        and not scope.refuse_live()
    )
    return {
        "adapter": "testssl_byo",
        "tool": "testssl",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "cidr_refused": cidrs,
        "on_path": not missing,
        "batch_size": len(batch),
        "would_exec": live,
        "shard_brake": brake,
        "command": plan_command(batch) if batch else plan_command(["<host>"]),
        "brake": "named hostnames/URLs only; CIDR-only SCOPE does not unlock testssl",
        "note": (
            "BYO only; pack does not embed testssl. "
            "Live exec requires allow_live_exec + EVERGREEN_ORCH_LIVE=1. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " testssl not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
            + (" CIDRs refused." if cidrs else "")
            + (f" brake={brake}." if brake else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def parse_testssl_text(blob: str, host: str) -> list[dict[str, Any]]:
    """Map obvious weak-TLS lines. Do not invent findings from 'not offered'."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in (blob or "").splitlines():
        low = line.lower()
        if "not offered" in low or "not vulnerable" in low or "no matching" in low:
            continue
        name = ""
        if "sslv3" in low or "ssl 3" in low:
            name = "SSLv3 offered"
        elif "tlsv1.0" in low or "tls 1.0" in low or re.search(r"\btlsv1\b", low):
            name = "TLSv1.0 offered"
        elif "weak cipher" in low or "rc4" in low or "export cipher" in low:
            name = "Weak TLS cipher"
        elif "expired" in low and "cert" in low:
            name = "Expired TLS certificate"
        if not name or name in seen:
            continue
        seen.add(name)
        findings.append(
            {
                "host": host,
                "asset": host,
                "name": name,
                "weakness": name,
                "severity": "medium" if "cipher" in name.lower() or "expired" in name.lower() else "medium",
            }
        )
    return findings


def execute(scope: Scope, batch: list[str], timeout: int | None = None) -> dict[str, Any]:
    """Call host testssl IF allowlisted + on PATH + live flags. Never download. Never shell=True."""
    desc = describe(scope, batch)
    desc["executed"] = False
    desc["findings"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    seconds = int(timeout or scope.integrity.timeouts_seconds or 600)
    seconds = max(1, min(seconds, int(scope.integrity.timeouts_seconds or 600), 600))
    findings: list[dict[str, Any]] = []
    ran = False
    for target in [t for t in batch if _safe_external(t)][:MAX_DEEPEN_TARGETS]:
        cmd = [binary_name(), "--fast", "--quiet", "--", target]
        if cmd[0] not in {"testssl.sh", "testssl"}:
            desc["shard_brake"] = "unsafe_command"
            return desc
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
            desc["findings"] = findings
            return desc
        except OSError as exc:
            desc["shard_brake"] = "exec_error"
            desc["error"] = type(exc).__name__
            desc["findings"] = findings
            return desc
        ran = True
        blob = proc.stdout or ""
        if len(blob) > MAX_STDOUT_BYTES:
            blob = blob[:MAX_STDOUT_BYTES]
        host = urlparse(target).hostname if "://" in target else target
        findings.extend(parse_testssl_text(blob, host or target))
        desc["returncode"] = proc.returncode
        desc["stderr_bytes"] = len(proc.stderr or "")
    desc["executed"] = ran
    desc["findings"] = findings
    desc["label"] = "live-byo" if ran else "plan-only"
    return desc
