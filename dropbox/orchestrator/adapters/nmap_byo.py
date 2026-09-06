"""BYO Nmap adapter. USE on drop box ≠ SHIP. Never download Nmap."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from dropbox.orchestrator.scope import Scope

# One worker ceiling. Quiet discover shards a /24; never a /16 in one argv.
MAX_LIVE_TARGETS = 256
MAX_STDOUT_BYTES = 2_000_000
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")


def binary_name() -> str:
    return "nmap"


def on_path() -> bool:
    return shutil.which("nmap") is not None


def allowed(scope: Scope) -> bool:
    return scope.tool_allowed("nmap")


def live_exec_permitted(scope: Scope) -> bool:
    return bool(scope.integrity.allow_live_exec) and os.environ.get("EVERGREEN_ORCH_LIVE", "0") == "1"


def _safe_target(raw: str) -> bool:
    t = (raw or "").strip()
    if not t or t.startswith("-") or t in {"<shard>", "<host>"}:
        return False
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return False
        return int(net.num_addresses) <= MAX_LIVE_TARGETS
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return bool(_HOST_RE.fullmatch(t))


def shard_brake(targets: list[str]) -> str | None:
    if not targets:
        return "empty_shard"
    if len(targets) > MAX_LIVE_TARGETS:
        return "shard_too_large"
    for t in targets:
        if _safe_target(t):
            continue
        text = (t or "").strip()
        if "/" in text:
            try:
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                return "unsafe_target"
            if int(net.num_addresses) > MAX_LIVE_TARGETS:
                return "cidr_too_large_for_one_worker"
        return "unsafe_target"
    return None


def plan_command(targets: list[str]) -> list[str]:
    """Quiet discover: ping-scan / host-up only. Never a /16 in one argv."""
    safe = [t for t in targets if _safe_target(t)]
    return ["nmap", "-sn", "-n", "--max-retries", "1", "-oX", "-", "--"] + list(safe or ["<shard>"])


def describe(scope: Scope, shard: list[str]) -> dict[str, Any]:
    missing = not on_path()
    gate = scope.tool_gate("nmap")
    tool_ok = allowed(scope)
    brake = shard_brake(shard) if shard else "empty_shard"
    live = (
        live_exec_permitted(scope)
        and tool_ok
        and not missing
        and gate is None
        and brake is None
        and not scope.refuse_live()
    )
    return {
        "adapter": "nmap_byo",
        "tool": "nmap",
        "allow_tools": tool_ok,
        "target_kind_gate": gate,
        "on_path": not missing,
        "would_exec": live,
        "shard_brake": brake,
        "command": plan_command(shard) if shard else plan_command(["<shard>"]),
        "note": (
            "BYO only; pack does not embed Nmap. "
            "Live exec requires SCOPE integrity.allow_live_exec and EVERGREEN_ORCH_LIVE=1. "
            + ("binary missing — plan-only." if missing else "")
            + ("" if tool_ok else " nmap not in allow_tools or target kind.")
            + (f" gate={gate}." if gate else "")
            + (f" brake={brake}." if brake else "")
        ),
        "label": "plan-only" if not live else "live-eligible",
    }


def parse_nmap_text(blob: str) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    for line in (blob or "").splitlines():
        if line.startswith("Nmap scan report for "):
            current = line.split("Nmap scan report for ", 1)[1].strip()
            ip = ""
            name = current
            if current.endswith(")") and "(" in current:
                name, rest = current.rsplit("(", 1)
                ip = rest[:-1].strip()
                name = name.strip()
            else:
                try:
                    ipaddress.ip_address(current)
                    ip = current
                except ValueError:
                    ip = ""
            hosts.append({"host": name, "ip": ip, "live": False, "in_scope": True})
        elif "Host is up" in line and hosts:
            hosts[-1]["live"] = True
    return hosts


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    text = (xml_text or "").strip()
    if not text:
        return hosts
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return parse_nmap_text(xml_text)
    for host in root.findall("host"):
        status = host.find("status")
        state = (status.get("state") if status is not None else "") or ""
        live = state.lower() == "up"
        addr = ""
        name = ""
        for address in host.findall("address"):
            if address.get("addrtype") in {"ipv4", "ipv6"}:
                addr = address.get("addr") or addr
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                label = (hn.get("name") or "").strip()
                if not label:
                    continue
                name = label
                if hn.get("type") == "user":
                    break
        hosts.append(
            {
                "host": name or addr,
                "ip": addr,
                "live": live,
                "in_scope": True,
            }
        )
    return hosts


def execute(scope: Scope, shard: list[str], timeout: int | None = None) -> dict[str, Any]:
    """Call host nmap IF allowlisted + on PATH + live flags. Never download. Never shell=True."""
    desc = describe(scope, shard)
    desc["executed"] = False
    desc["hosts"] = []
    if not desc["would_exec"]:
        desc["note"] = (desc.get("note") or "") + " execute skipped (plan-only)."
        return desc
    cmd = [c for c in desc["command"] if c != "<shard>"]
    if not cmd or cmd[0] != "nmap" or "<shard>" in cmd:
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
    xml_blob = proc.stdout or ""
    if len(xml_blob) > MAX_STDOUT_BYTES:
        xml_blob = xml_blob[:MAX_STDOUT_BYTES]
    desc["executed"] = True
    desc["returncode"] = proc.returncode
    desc["hosts"] = parse_nmap_xml(xml_blob)
    desc["label"] = "live-byo"
    desc["stderr_bytes"] = len(proc.stderr or "")
    return desc
