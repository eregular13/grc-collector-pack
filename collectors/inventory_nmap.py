#!/usr/bin/env python3
"""Parse dropped Nmap, masscan, rustscan, naabu, arp-scan, fping, netdiscover, nbtscan, and smbmap exports.

Parse-only. Does not run nmap, masscan, rustscan, naabu, arp-scan, fping, netdiscover, nbtscan, or smbmap.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from shared.arp_scan import parse_arp_scan
from shared.fast_portscan import parse_fast_portscan
from shared.fping import parse_fping
from shared.io_util import iso_now, read_text, run_collector
from shared.masscan import parse_masscan
from shared.nbtscan import parse_nbtscan
from shared.netdiscover import parse_netdiscover
from shared.smbmap import parse_smbmap
from shared.schema import make_record, make_ref

SOURCE = "inventory-nmap"
LABELS = ["nmap", "inventory"]
RISKY = {
    "23": ("critical", "Telnet exposed"),
    "21": ("high", "FTP exposed"),
    "445": ("high", "SMB 445 exposed"),
    "3389": ("medium", "RDP exposed"),
    "22": ("low", "SSH exposed"),
    "80": ("low", "HTTP exposed"),
}


def _is_dropbox_demo(path: Path, raw: str) -> bool:
    name = path.name.lower()
    if name.startswith("dropbox-"):
        return True
    return "DEMO — not a client estate" in raw or "DEMO -- not a client estate" in raw


def _stamp_demo(records: list[dict], demo: bool) -> None:
    if not demo:
        return
    for rec in records:
        labels = rec.setdefault("labels", [])
        if "demo" not in labels:
            labels.append("demo")


def _emit_host(
    records: list[dict],
    now: str,
    name: str,
    addr: str,
    hostname: str,
    ports: list[tuple[str, str]],
    extra: dict[str, Any] | None = None,
    extra_labels: list[str] | None = None,
) -> None:
    extra_out: dict[str, Any] = {"asset_type": "PR", "ip": addr, "hostname": hostname}
    if extra:
        for key, value in extra.items():
            if value not in (None, ""):
                extra_out[key] = value
    labels = list(LABELS)
    for lab in extra_labels or []:
        if lab not in labels:
            labels.append(lab)
    records.append(
        make_record(
            kind="asset",
            source=SOURCE,
            ref_id=make_ref(SOURCE, f"asset-{name}"),
            name=name,
            description=f"Host {name} ({addr})".strip(),
            severity="info",
            category="host",
            assets=[name],
            labels=labels,
            collected_at=now,
            extra=extra_out,
        )
    )
    for portid, svc in ports:
        sev, title = RISKY.get(portid, ("info", f"Open port {portid}/{svc}"))
        if sev == "info" and portid not in {"80", "443"}:
            sev = "low"
            title = f"Open port {portid}/{svc or 'unknown'}"
        if portid == "443":
            continue
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"{name}-{portid}"),
                name=title,
                description=f"{name} has open TCP/{portid} ({svc or 'unknown'}).",
                severity=sev,
                category="exposure",
                assets=[name],
                labels=LABELS + [f"port-{portid}"],
                collected_at=now,
                extra={"port": portid, "service": svc, "ip": addr},
            )
        )
        if portid == "445":
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{name}-admin-share"),
                    name=f"Administrative share exposed on {name} (C$/ADMIN$)",
                    description=f"{name} has SMB open; C$/ADMIN$ administrative shares should be restricted.",
                    severity="medium",
                    category="exposure",
                    assets=[name],
                    labels=LABELS + ["admin-share"],
                    collected_at=now,
                    extra={"service": "admin-share", "ip": addr},
                )
            )


def parse_nmap_json(payload: Any, now: str) -> list[dict]:
    """Parse a dropped nmap JSON/ndjson-shaped object. No live scan."""
    hosts: list[Any] = []
    if isinstance(payload, list):
        hosts = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("hosts"), list):
            hosts = payload["hosts"]
        elif payload.get("ip") or payload.get("hostname") or payload.get("host"):
            hosts = [payload]
        else:
            nmaprun = payload.get("nmaprun")
            if isinstance(nmaprun, dict):
                raw_h = nmaprun.get("host")
                if isinstance(raw_h, list):
                    hosts = raw_h
                elif isinstance(raw_h, dict):
                    hosts = [raw_h]
    records: list[dict] = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        addr = str(host.get("ip") or host.get("addr") or host.get("address") or "")
        hostname = str(host.get("hostname") or host.get("name") or host.get("host") or "")
        name = hostname or addr or "unknown-host"
        ports: list[tuple[str, str]] = []
        for p in host.get("ports") or []:
            if not isinstance(p, dict):
                continue
            if str(p.get("state") or "open").lower() != "open":
                continue
            portid = str(p.get("port") or p.get("portid") or "")
            if not portid:
                continue
            svc = str(p.get("service") or p.get("name") or "")
            ports.append((portid, svc))
        if name or ports:
            _emit_host(records, now, name, addr, hostname, ports)
    return records


def parse_gnmap(raw: str, now: str) -> list[dict]:
    records: list[dict] = []
    for line in raw.splitlines():
        if not line.startswith("Host:"):
            continue
        if "Ports:" not in line:
            continue
        host_part = line.split("Ports:")[0]
        addr = ""
        hostname = ""
        rest = host_part[len("Host:") :].strip()
        if "(" in rest:
            addr = rest.split("(", 1)[0].strip()
            hostname = rest.split("(", 1)[1].split(")", 1)[0].strip()
        else:
            addr = rest.split()[0] if rest.split() else ""
        name = hostname or addr or "unknown-host"
        ports: list[tuple[str, str]] = []
        if "Ports:" in line:
            for chunk in line.split("Ports:", 1)[1].split(","):
                parts = chunk.strip().split("/")
                if len(parts) >= 5 and parts[1] == "open":
                    ports.append((parts[0], parts[4]))
        if "Ports:" in line or name:
            _emit_host(records, now, name, addr, hostname, ports)
    return records


def parse_file(path: Path) -> list[dict]:
    raw = read_text(path)
    now = iso_now()
    mass = parse_masscan(path, raw)
    if mass is not None:
        records: list[dict] = []
        for host in mass:
            ports = list(host.get("ports") or [])
            if not ports:
                continue
            _emit_host(
                records,
                now,
                str(host.get("name") or "unknown-host"),
                str(host.get("addr") or ""),
                str(host.get("hostname") or ""),
                ports,
            )
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    fast = parse_fast_portscan(path, raw)
    if fast is not None:
        records = []
        for host in fast:
            ports = list(host.get("ports") or [])
            if not ports:
                continue
            _emit_host(
                records,
                now,
                str(host.get("name") or "unknown-host"),
                str(host.get("addr") or ""),
                str(host.get("hostname") or ""),
                ports,
            )
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    arp = parse_arp_scan(path, raw)
    if arp is not None:
        records = []
        for host in arp:
            extra = {
                "mac": host.get("mac") or "",
                "vendor": host.get("vendor") or "",
            }
            _emit_host(
                records,
                now,
                str(host.get("name") or "unknown-host"),
                str(host.get("addr") or ""),
                str(host.get("hostname") or ""),
                [],
                extra=extra,
                extra_labels=["arp"],
            )
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    discovered = parse_netdiscover(path, raw)
    if discovered is not None:
        records = []
        for host in discovered:
            extra = {
                "mac": host.get("mac") or "",
                "vendor": host.get("vendor") or "",
            }
            _emit_host(
                records,
                now,
                str(host.get("name") or "unknown-host"),
                str(host.get("addr") or ""),
                str(host.get("hostname") or ""),
                [],
                extra=extra,
                extra_labels=["netdiscover"],
            )
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    pinged = parse_fping(path, raw)
    if pinged is not None:
        records = []
        for host in pinged:
            _emit_host(
                records,
                now,
                str(host.get("name") or "unknown-host"),
                str(host.get("addr") or ""),
                str(host.get("hostname") or ""),
                [],
                extra_labels=["fping"],
            )
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    nbt = parse_nbtscan(path, raw)
    if nbt is not None:
        records = []
        for host in nbt:
            extra = {
                "mac": host.get("mac") or "",
                "netbios": host.get("netbios") or "",
            }
            _emit_host(
                records,
                now,
                str(host.get("name") or "unknown-host"),
                str(host.get("addr") or ""),
                str(host.get("hostname") or host.get("netbios") or ""),
                [],
                extra=extra,
                extra_labels=["nbtscan"],
            )
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    mapped = parse_smbmap(path, raw)
    if mapped is not None:
        records = []
        for host in mapped:
            name = str(host.get("name") or "unknown-host")
            addr = str(host.get("addr") or "")
            hostname = str(host.get("hostname") or "")
            _emit_host(
                records,
                now,
                name,
                addr,
                hostname,
                [],
                extra_labels=["smbmap"],
            )
            for share in host.get("shares") or []:
                if not isinstance(share, dict):
                    continue
                share_name = str(share.get("name") or "").strip()
                access = str(share.get("access") or "").strip()
                up = access.upper().replace(" ", "")
                if not share_name or up in {"", "NOACCESS"}:
                    continue
                if "READ" not in up and "WRITE" not in up:
                    continue
                if share_name.upper() in {"IPC$", "PRINT$"} and "WRITE" not in up:
                    continue
                writable = "WRITE" in up
                admin = share_name.upper() in {"C$", "ADMIN$"}
                sev = "high" if writable else "medium"
                kind = "Writable" if writable else "Readable"
                title = f"{kind} SMB share {share_name} on {name}"
                desc = (
                    f"{name} smbmap export shows {share_name} as {access or 'open'}."
                )
                extra = {
                    "port": "445",
                    "service": "smb",
                    "share": share_name,
                    "access": access,
                    "ip": addr,
                }
                labels = LABELS + ["smbmap", "smb"]
                if admin:
                    labels.append("admin-share")
                records.append(
                    make_record(
                        kind="finding",
                        source=SOURCE,
                        ref_id=make_ref(SOURCE, f"{name}-share-{share_name}"),
                        name=title,
                        description=desc,
                        severity=sev,
                        category="exposure",
                        assets=[name],
                        labels=labels,
                        collected_at=now,
                        extra=extra,
                    )
                )
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    stripped = raw.lstrip("\ufeff").lstrip()
    if path.suffix.lower() == ".json" or stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            records = parse_gnmap(raw, now)
        else:
            records = parse_nmap_json(payload, now)
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    if not stripped.startswith("<"):
        records = parse_gnmap(raw, now)
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    root = ET.fromstring(raw)
    now = iso_now()
    records: list[dict] = []
    for host in root.findall("host"):
        state_el = host.find("status")
        if state_el is not None and state_el.attrib.get("state") == "down":
            continue
        addr = ""
        for address in host.findall("address"):
            if address.attrib.get("addrtype") in {None, "ipv4", "ipv6"}:
                addr = address.attrib.get("addr", addr)
        hostname = ""
        hnames = host.find("hostnames")
        if hnames is not None:
            hn = hnames.find("hostname")
            if hn is not None:
                hostname = hn.attrib.get("name", "")
        name = hostname or addr or "unknown-host"
        ports: list[tuple[str, str]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                portid = port.attrib.get("portid", "")
                service = port.find("service")
                svc = service.attrib.get("name", "") if service is not None else ""
                ports.append((portid, svc))
        _emit_host(records, now, name, addr, hostname, ports)
    _stamp_demo(records, _is_dropbox_demo(path, raw))
    return records


def main() -> None:
    run_collector(SOURCE, (".xml", ".gnmap", ".txt", ".json", ".jsonl"), parse_file)


if __name__ == "__main__":
    main()
