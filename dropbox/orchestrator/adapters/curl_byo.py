"""BYO curl adapter. Named internet-facing URLs only. Never CIDRs. Never spray."""
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
MAX_STDOUT_BYTES = 200_000
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")


def binary_name() -> str:
    if shutil.which("curl"):
        return "curl"
    if shutil.which("curl.exe"):
        return "curl.exe"
    return "curl"


def on_path() -> bool:
    return shutil.which("curl") is not None or shutil.which("curl.exe") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("curl")


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
    if not t or t.startswith("-") or t in {"<url>", "<host>"}:
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


def as_url(target: str) -> str:
    t = (target or "").strip()
    if t.lower().startswith(("https://", "http://")):
        return t
    return f"https://{t}"


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
    url = as_url(targets[0]) if targets and _safe_external(targets[0]) else "<url>"
    return [binary_name(), "-I", "--max-time", "10", "--max-redirs", "0", "--proto", "=http,https", url]


def describe(scope: Scope, batch: list[str]) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("curl")
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
        "adapter": "curl_byo",
        "tool": "curl",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "cidr_refused": cidrs,
        "on_path": not missing,
        "batch_size": len(batch),
        "would_exec": live,
        "shard_brake": brake,
        "command": plan_command(batch) if batch else plan_command(["https://example.invalid"]),
        "brake": "named URLs/hostnames only; never a CIDR; never the whole internet",
        "note": (
            "BYO only; pack does not embed curl scanners. HEAD-only. "
            "Live exec requires allow_live_exec + EVERGREEN_ORCH_LIVE=1. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " curl not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
            + (" CIDRs refused." if cidrs else "")
            + (f" brake={brake}." if brake else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def parse_curl_headers(blob: str, url: str) -> list[dict[str, Any]]:
    """Cleartext HTTP from the URL scheme. Missing headers only when a status line was sampled.
    Do not invent CVEs or SMBv1 from a HEAD response. Empty reply (cycle 5) is not a header sample."""
    host = urlparse(url).hostname or url
    rows: list[dict[str, Any]] = []

    def _row(name: str, severity: str) -> dict[str, Any]:
        return {
            "host": host,
            "asset": host,
            "name": name,
            "weakness": name,
            "severity": severity,
        }

    if url.lower().startswith("http://"):
        rows.append(_row("Cleartext HTTP", "medium"))
    low = (blob or "").lower()
    if "http/" not in low:
        return rows
    if "strict-transport-security:" not in low:
        rows.append(_row("Missing HSTS", "medium"))
    if "x-frame-options:" not in low:
        rows.append(_row("Missing X-Frame-Options", "low"))
    if "content-security-policy:" not in low:
        rows.append(_row("Missing CSP", "low"))
    if re.search(r"(?im)^server:", blob or ""):
        rows.append(_row("Server banner disclosure", "low"))
    return rows


def parse_curl_tls(stderr: str, url: str) -> list[dict[str, Any]]:
    """Self-signed / verify-fail on https:// only. Do not invent SMBv1."""
    if not (url or "").lower().startswith("https://"):
        return []
    low = (stderr or "").lower()
    if any(
        tok in low
        for tok in (
            "self-signed",
            "self signed certificate",
            "ssl certificate problem",
            "unable to get local issuer",
            "certificate verify failed",
            "untrusted_root",
            "sec_e_untrusted_root",
            "not trusted",
        )
    ):
        host = urlparse(url).hostname or url
        return [
            {
                "host": host,
                "asset": host,
                "name": "Untrusted TLS certificate",
                "weakness": "Untrusted TLS certificate",
                "severity": "medium",
            }
        ]
    return []


def execute(scope: Scope, batch: list[str], timeout: int | None = None) -> dict[str, Any]:
    """HEAD-only curl on named URLs. Never CIDR. Never shell=True. Never download."""
    desc = describe(scope, batch)
    desc["executed"] = False
    desc["findings"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    seconds = int(timeout or 10)
    seconds = max(1, min(seconds, 30))
    findings: list[dict[str, Any]] = []
    ran = False
    for target in [t for t in batch if _safe_external(t)][:MAX_DEEPEN_TARGETS]:
        url = as_url(target)
        cmd = [
            binary_name(),
            "-I",
            "--max-time",
            str(seconds),
            "--max-redirs",
            "0",
            "--proto",
            "=http,https",
            "--",
            url,
        ]
        if cmd[0] not in {"curl", "curl.exe"}:
            desc["shard_brake"] = "unsafe_command"
            return desc
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=seconds + 2,
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
        blob = (proc.stdout or "")[:MAX_STDOUT_BYTES]
        err = (proc.stderr or "")[:MAX_STDOUT_BYTES]
        findings.extend(parse_curl_tls(err, url))
        findings.extend(parse_curl_headers(blob, url))
        if url.lower().startswith("https://") and "http/" not in blob.lower():
            insecure = cmd[:1] + ["-k"] + cmd[1:]
            try:
                proc2 = subprocess.run(
                    insecure,
                    capture_output=True,
                    text=True,
                    timeout=seconds + 2,
                    check=False,
                    shell=False,
                )
                findings.extend(parse_curl_headers((proc2.stdout or "")[:MAX_STDOUT_BYTES], url))
            except (subprocess.TimeoutExpired, OSError):
                pass
        desc["returncode"] = proc.returncode
        desc["stderr_bytes"] = len(proc.stderr or "")
    uniq: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for row in findings:
        key = (row.get("name"), row.get("host"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(row)
    desc["executed"] = ran
    desc["findings"] = uniq
    desc["label"] = "live-byo" if ran else "plan-only"
    return desc
