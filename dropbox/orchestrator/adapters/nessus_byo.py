"""BYO Nessus adapter. Tiny deepen batches only. Never embed or download Nessus."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from dropbox.orchestrator.scope import Scope

# Louder deepen: never a /16, never more than 5 hosts on one worker.
MAX_DEEPEN_TARGETS = 5
MAX_STDOUT_BYTES = 2_000_000
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")
_SEV = {"4": "critical", "3": "high", "2": "medium", "1": "low"}


def binary_name() -> str:
    if shutil.which("nessuscli"):
        return "nessuscli"
    if shutil.which("nessus"):
        return "nessus"
    return "nessuscli"


def on_path() -> bool:
    return shutil.which("nessuscli") is not None or shutil.which("nessus") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("nessus")


def live_exec_permitted(scope: Scope) -> bool:
    return bool(scope.integrity.allow_live_exec) and os.environ.get("EVERGREEN_ORCH_LIVE", "0") == "1"


def _safe_target(raw: str) -> bool:
    t = (raw or "").strip()
    if not t or t.startswith("-") or t in {"<host>", "<shard>"}:
        return False
    if "/" in t or "://" in t:
        return False
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
    for t in batch:
        text = (t or "").strip()
        if _safe_target(text):
            continue
        if "/" in text:
            return "cidr_refused"
        return "unsafe_target"
    return None


def plan_command(batch: list[str]) -> list[str]:
    safe = [t for t in batch if _safe_target(t)][:MAX_DEEPEN_TARGETS]
    return [binary_name(), "scan", "--targets", ",".join(safe or ["<host>"])]


def describe(scope: Scope, batch: list[str]) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("nessus")
    tool_ok = allowed(scope)
    brake = shard_brake(batch) if batch else "empty_batch"
    size = len(batch)
    live = (
        live_exec_permitted(scope)
        and tool_ok
        and not missing
        and gate is None
        and brake is None
        and not scope.refuse_live()
    )
    return {
        "adapter": "nessus_byo",
        "tool": "nessus",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "on_path": not missing,
        "batch_size": size,
        "would_exec": live,
        "shard_brake": brake,
        "command": plan_command(batch) if batch else plan_command(["<host>"]),
        "brake": "deepen batch must stay 2–5; never a /16",
        "note": (
            "BYO only. Live exec requires allow_live_exec + EVERGREEN_ORCH_LIVE=1. "
            "Never a CIDR or /16 on one worker. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " nessus not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
            + (f" brake={brake}." if brake else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def _host_from_report_host(rh: ET.Element) -> str:
    fqdn = ""
    ip = ""
    props = rh.find("HostProperties")
    if props is not None:
        for tag in props.findall("tag"):
            name = (tag.get("name") or "").lower()
            val = (tag.text or "").strip()
            if name == "host-fqdn" and val:
                fqdn = val
            elif name == "host-ip" and val:
                ip = val
    return fqdn or (rh.get("name") or "").strip() or ip


def parse_nessus_xml(xml_text: str) -> list[dict[str, Any]]:
    text = (xml_text or "").strip()
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    rows: list[dict[str, Any]] = []
    hosts = root.findall(".//ReportHost")
    for rh in hosts:
        host = _host_from_report_host(rh)
        for item in rh.findall("ReportItem"):
            sev_raw = str(item.get("severity") or "0")
            if sev_raw == "0":
                continue
            plugin = (item.get("pluginName") or "").strip()
            if not plugin:
                continue
            rows.append(
                {
                    "host": host,
                    "asset": host,
                    "name": plugin,
                    "weakness": plugin,
                    "severity": _SEV.get(sev_raw, "medium"),
                    "port": item.get("port") or "",
                }
            )
    return rows


def execute(scope: Scope, batch: list[str], timeout: int | None = None) -> dict[str, Any]:
    """Call host nessuscli IF allowlisted + on PATH + live flags. Never download. Never shell=True."""
    desc = describe(scope, batch)
    desc["executed"] = False
    desc["findings"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    cmd = [c for c in desc["command"] if c != "<host>"]
    if not cmd or cmd[0] not in {"nessuscli", "nessus"} or "<host>" in cmd:
        desc["shard_brake"] = "unsafe_command"
        return desc
    seconds = int(timeout or scope.integrity.timeouts_seconds or 600)
    seconds = max(1, min(seconds, int(scope.integrity.timeouts_seconds or 600), 600))
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
    blob = proc.stdout or ""
    if len(blob) > MAX_STDOUT_BYTES:
        blob = blob[:MAX_STDOUT_BYTES]
    desc["executed"] = True
    desc["returncode"] = proc.returncode
    desc["findings"] = parse_nessus_xml(blob)
    desc["label"] = "live-byo"
    desc["stderr_bytes"] = len(proc.stderr or "")
    return desc
