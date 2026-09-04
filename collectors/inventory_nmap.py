#!/usr/bin/env python3
"""Parse Nmap XML into hosts + exposure findings."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from shared.io_util import iso_now, read_text, run_collector
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


def _emit_host(records: list[dict], now: str, name: str, addr: str, hostname: str, ports: list[tuple[str, str]]) -> None:
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
            labels=LABELS,
            collected_at=now,
            extra={"asset_type": "PR", "ip": addr, "hostname": hostname},
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
    if not raw.lstrip().startswith("<"):
        return parse_gnmap(raw, now)
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
    return records


def main() -> None:
    run_collector(SOURCE, (".xml", ".gnmap", ".txt"), parse_file)


if __name__ == "__main__":
    main()
