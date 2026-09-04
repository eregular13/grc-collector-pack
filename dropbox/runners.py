"""Allowlisted drop-box runners. No forbidden scanners. Outputs → in/<sensor>/."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

from dropbox.scope import ALLOWED_RUNNERS, FORBIDDEN_TOOLS, NEVER_EMBED, GateError, Scope
from shared.io_util import in_dir

DEMO = os.environ.get("DROPBOX_DEMO", "1") != "0"
LIVE = os.environ.get("DROPBOX_LIVE", "0") == "1"


def _sensor_dir(sensor: str) -> Path:
    dest = in_dir() / sensor
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run_cmd(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    exe = Path(argv[0]).name.lower()
    if exe in NEVER_EMBED or exe in FORBIDDEN_TOOLS:
        raise GateError(f"LICENSE-LOCK: generic runner refuses {exe}; use orchestrator shards only")
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def write_inventory(scope: Scope, demo: bool = DEMO) -> Path:
    """Local ss/ip listen table → gnmap for inventory-nmap. Never Nmap."""
    dest = _sensor_dir("nmap") / "dropbox-inventory.gnmap"
    lines = ["# dropbox local inventory (ss/ip). Not Nmap."]
    hosts: dict[str, tuple[str, list[tuple[str, str]]]] = {}

    if "ss" in scope.allow_tools or "ip" in scope.allow_tools:
        ss = _which("ss") if "ss" in scope.allow_tools else None
        if ss and not demo:
            proc = _run_cmd([ss, "-lntH"], timeout=10)
            for line in (proc.stdout or "").splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[3]
                port = local.rsplit(":", 1)[-1]
                if not port.isdigit():
                    continue
                addr = "127.0.0.1"
                hosts.setdefault("dropbox-local", (addr, []))
                pair = (port, "unknown")
                if pair not in hosts["dropbox-local"][1]:
                    hosts["dropbox-local"][1].append(pair)

    if demo or not hosts:
        for name in scope.internal_hosts:
            addr = name if _looks_ip(name) else "10.0.0.10"
            host = name if not _looks_ip(name) else socket.gethostname() or "dropbox-local"
            hosts.setdefault(host, (addr, [("22", "ssh"), ("80", "http")]))

    for name, (addr, ports) in hosts.items():
        port_s = ", ".join(f"{p}/open/tcp//{svc}///" for p, svc in ports) or "22/open/tcp//ssh///"
        lines.append(f"Host: {addr} ({name})\tPorts: {port_s}")
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def write_lynis(scope: Scope, demo: bool = DEMO) -> Path | None:
    """Lynis on this host only when SCOPE allows and the binary is already on PATH."""
    if "lynis" not in scope.allow_tools:
        return None
    dest_json = _sensor_dir("wazuh") / "dropbox-lynis-host.json"
    host = socket.gethostname() or "dropbox-local"
    lynis = _which("lynis")
    report = ""
    if lynis and not demo:
        proc = _run_cmd([lynis, "audit", "system", "--quick", "--no-colors"], timeout=120)
        report = (proc.stdout or "")[:8000]
        raw = _sensor_dir("wazuh") / "dropbox-lynis-report.txt"
        raw.write_text(report or "# lynis produced no stdout\n", encoding="utf-8")
    payload = {
        "osquery": [{"hostname": host, "status": "active", "source": "dropbox-lynis"}],
        "notes": "Lynis findings are not parsed (no Lynis collector). Host ingested via osquery shape.",
        "demo": demo or not bool(lynis),
    }
    dest_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return dest_json


def write_tls_headers(scope: Scope, demo: bool = DEMO, live: bool = LIVE) -> Path:
    """curl -I against named external SCOPE targets only. Demo writes fixtures, no network."""
    dest = _sensor_dir("easm") / "dropbox-tls.jsonl"
    targets = list(dict.fromkeys(scope.external_hosts + scope.external_ips))
    if not targets:
        targets = list(scope.external_domains)
    rows = []
    for target in targets:
        if not scope.allows_external_target(target):
            raise GateError(f"external target not in SCOPE: {target}")
        row = {
            "host": target.split("://")[-1].split("/")[0].split(":")[0],
            "url": target if "://" in target else f"https://{target}",
            "status_code": 0,
            "title": "dropbox-demo no live curl",
            "tech": ["dropbox-demo"],
        }
        if live and not demo and "curl" in scope.allow_tools:
            curl = _which("curl")
            if not curl:
                raise GateError("curl not on PATH")
            host = row["host"]
            if not scope.allows_external_target(host):
                raise GateError(f"external target not in SCOPE: {host}")
            proc = _run_cmd([curl, "-sS", "-I", "-m", "8", "--connect-timeout", "5", row["url"]], timeout=12)
            first = (proc.stdout or "").splitlines()[:1]
            code = 0
            if first and first[0].upper().startswith("HTTP"):
                bits = first[0].split()
                if len(bits) >= 2 and bits[1].isdigit():
                    code = int(bits[1])
            row["status_code"] = code
            row["title"] = "TLS header grab"
            row["tech"] = ["dropbox-tls"]
        rows.append(row)
    dest.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return dest


def write_byo(scope: Scope, demo: bool = DEMO) -> list[Path]:
    """Run PATH binaries named in SCOPE.allow_tools / byo. Never download. Never forbidden tools."""
    written: list[Path] = []
    if demo:
        return written
    for item in scope.byo:
        name = str(item.get("name") or "").strip()
        tool = name.lower()
        if tool in FORBIDDEN_TOOLS:
            raise GateError(f"LICENSE-LOCK: BYO {tool!r} is forbidden")
        if tool not in scope.allow_tools:
            raise GateError(f"BYO {name!r} is not in SCOPE.allow_tools")
        if tool not in ALLOWED_RUNNERS and tool in FORBIDDEN_TOOLS:
            raise GateError(f"LICENSE-LOCK: BYO {tool!r} is forbidden")
        exe = _which(name)
        if not exe:
            raise GateError(f"BYO {name!r} is not on PATH (will not download)")
        args = item.get("args") or []
        if not isinstance(args, list):
            args = [str(args)]
        argv = [exe] + [str(a) for a in args]
        proc = _run_cmd(argv, timeout=int(item.get("timeout") or 30))
        sensor = str(item.get("sensor") or "nmap")
        dest = _sensor_dir(sensor) / f"dropbox-byo-{tool}.txt"
        dest.write_text((proc.stdout or "") + (proc.stderr or ""), encoding="utf-8")
        written.append(dest)
    return written


def _looks_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def refuse_offscope_external(scope: Scope, target: str) -> None:
    if not scope.allows_external_target(target):
        raise GateError(f"external target not in SCOPE: {target}")
