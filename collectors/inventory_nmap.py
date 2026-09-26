#!/usr/bin/env python3
"""Parse dropped Nmap, masscan, rustscan, naabu, arp-scan, fping, netdiscover, nbtscan, smbmap, zmap, and unicornscan exports.

Parse-only. Does not run nmap, masscan, rustscan, naabu, arp-scan, fping, netdiscover, nbtscan, smbmap, zmap, or unicornscan.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from shared.arp_scan import parse_arp_scan
from shared.asset_ids import stamp_ids
from shared.fast_portscan import parse_fast_portscan
from shared.fping import parse_fping
from shared.io_util import iso_now, read_text, run_collector
from shared.masscan import parse_masscan
from shared.nbtscan import parse_nbtscan
from shared.nmap_nse import nse_findings, vulners_cves
from shared.netdiscover import parse_netdiscover
from shared.pack_drop import parse_pack_drop
from shared.smbmap import parse_smbmap
from shared.kev import KevSnapshotError, load_kev_catalog
from shared.schema import canon_severity, make_record, make_ref
from shared.unicornscan import parse_unicornscan
from shared.zmap import parse_zmap

SOURCE = "inventory-nmap"
LABELS = ["nmap", "inventory"]
_CDN_EDGE_PORTS = frozenset({"80", "443", "8080", "8443"})
_VULNERS_SOLO_CVSS = 7.0
# Keyed by (port, proto). tcp/445 is SMB; udp/445 is not.
RISKY = {
    ("23", "tcp"): ("critical", "Telnet exposed"),
    ("21", "tcp"): ("high", "FTP exposed"),
    ("445", "tcp"): ("high", "SMB 445 exposed"),
    ("3389", "tcp"): ("medium", "RDP exposed"),
    ("22", "tcp"): ("low", "SSH exposed"),
    ("80", "tcp"): ("low", "HTTP exposed"),
    ("161", "udp"): ("medium", "SNMP 161/udp exposed"),
    ("69", "udp"): ("high", "TFTP 69/udp exposed"),
}
RISKY_TCP = {port: val for (port, proto), val in RISKY.items() if proto == "tcp"}
# Confirmed-open UDP only. open|filtered never uses this table.
RISKY_UDP = {port: val for (port, proto), val in RISKY.items() if proto == "udp"}


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


def _cvss_value(hit: dict[str, Any]) -> float:
    try:
        return float(hit.get("cvss") or 0)
    except (TypeError, ValueError):
        return 0.0


def _kev_cve_ids() -> set[str]:
    try:
        catalog = load_kev_catalog()
    except KevSnapshotError:
        return set()
    if not catalog.kev_evaluated:
        return set()
    return set(catalog.by_cve)


def _vulners_solo(hit: dict[str, Any], kev_ids: set[str]) -> bool:
    cve = str(hit.get("cve") or "").upper()
    if cve and cve in kev_ids:
        return True
    return _cvss_value(hit) >= _VULNERS_SOLO_CVSS


def _emit_vulners_hits(
    records: list[dict],
    now: str,
    name: str,
    addr: str,
    portid: str,
    svc: str,
    hits: list[dict[str, Any]],
    kev_ids: set[str],
) -> None:
    """One finding per CVE when CVSS >= 7 or KEV; others roll up per host/service."""
    solo = [h for h in hits if _vulners_solo(h, kev_ids)]
    rolled = [h for h in hits if h not in solo]
    for hit in solo:
        cve = hit["cve"]
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"{name}-{portid or 'host'}-{cve}"),
                name=cve,
                description=(
                    f"{name} {svc or 'service'} on {portid or 'host'} matches {cve} "
                    f"(nmap vulners, cvss={hit.get('cvss') or 'n/a'})."
                ),
                severity=canon_severity(hit.get("severity") or "medium"),
                category="vulnerability",
                assets=[name],
                labels=LABELS + ["nse", "vulners", cve],
                collected_at=now,
                extra={
                    "port": portid,
                    "service": svc,
                    "ip": addr,
                    "cve": cve,
                    "cvss": hit.get("cvss") or "",
                    "nse_script": "vulners",
                    "tool": "nmap",
                    "check_id": cve,
                },
            )
        )
    if not rolled:
        return
    cves = [str(h.get("cve") or "") for h in rolled if h.get("cve")]
    listed = ", ".join(cves)
    top = max(rolled, key=_cvss_value)
    records.append(
        make_record(
            kind="finding",
            source=SOURCE,
            ref_id=make_ref(SOURCE, f"{name}-{portid or 'host'}-vulners-rollup"),
            name=f"Lower-severity vulners CVEs on {name} {portid or 'host'}",
            description=(
                f"{name} {svc or 'service'} on {portid or 'host'} matches "
                f"{listed} (nmap vulners; CVSS < {_VULNERS_SOLO_CVSS:.0f}, not KEV)."
            ),
            severity=canon_severity(top.get("severity") or "medium"),
            category="vulnerability",
            assets=[name],
            labels=LABELS + ["nse", "vulners"],
            collected_at=now,
            extra={
                "port": portid,
                "service": svc,
                "ip": addr,
                "cves": cves,
                "cvss": top.get("cvss") or "",
                "nse_script": "vulners",
                "tool": "nmap",
                "check_id": "vulners-rollup",
            },
        )
    )


def _emit_host(
    records: list[dict],
    now: str,
    name: str,
    addr: str,
    hostname: str,
    ports: list[Any],
    extra: dict[str, Any] | None = None,
    extra_labels: list[str] | None = None,
    samba_ports: set[str] | None = None,
) -> None:
    extra_out: dict[str, Any] = {"asset_type": "PR", "ip": addr, "hostname": hostname}
    if extra:
        for key, value in extra.items():
            if value not in (None, ""):
                extra_out[key] = value
    extra_out = stamp_ids(
        extra_out,
        ip=extra_out.get("ip") or addr,
        hostname=extra_out.get("hostname") or hostname,
        fqdn=extra_out.get("fqdn") or hostname,
        mac=extra_out.get("mac") or extra_out.get("macs") or [],
        netbios=extra_out.get("netbios") or "",
        domain=extra_out.get("domain") or "",
    )
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
    for item in ports:
        if isinstance(item, (tuple, list)) and item:
            portid = str(item[0])
            svc = str(item[1]) if len(item) > 1 else ""
            proto = str(item[2]) if len(item) > 2 else ""
            state = str(item[3]) if len(item) > 3 else "open"
        else:
            portid, svc, proto, state = str(item), "", "", "open"
        proto = proto.lower()
        if proto not in {"tcp", "udp", "sctp"}:
            proto = svc.lower() if svc.lower() in {"tcp", "udp", "sctp"} else "tcp"
        if extra and extra.get("cdn") and portid in _CDN_EDGE_PORTS:
            continue
        not_a_weakness = False
        if proto == "udp" and state == "open|filtered":
            sev, title = "info", f"UDP {portid} open|filtered (not confirmed open)"
            not_a_weakness = True
        elif proto == "udp" and state == "open":
            sev, title = RISKY.get(
                (portid, "udp"),
                RISKY_UDP.get(portid, ("info", f"Open UDP port {portid}/{svc or 'udp'}")),
            )
        elif proto == "tcp":
            sev, title = RISKY.get(
                (portid, "tcp"),
                RISKY_TCP.get(portid, ("info", f"Open port {portid}/{svc or proto}")),
            )
            if sev == "info" and portid not in {"80", "443"}:
                sev = "low"
                title = f"Open port {portid}/{svc or proto or 'unknown'}"
        else:
            sev, title = "info", f"Open port {portid}/{svc or proto}"
        if portid == "443" and proto == "tcp":
            continue
        find_labels = list(LABELS) + [f"port-{portid}"]
        for lab in extra_labels or []:
            if lab not in find_labels:
                find_labels.append(lab)
        extra_find: dict[str, Any] = {"port": portid, "service": svc, "protocol": proto, "ip": addr}
        if state and state != "open":
            extra_find["state"] = state
        if not_a_weakness:
            extra_find["not_a_weakness"] = True
            extra_find["exclude_reason"] = "not_a_weakness"
        if extra:
            if extra.get("cdn"):
                extra_find["cdn"] = True
            if extra.get("cdn_name"):
                extra_find["cdn_name"] = extra["cdn_name"]
        ref_port = f"{name}-{portid}/{proto}"
        if state == "open|filtered":
            desc = (
                f"{name} has {proto.upper()}/{portid} open|filtered "
                f"({svc or 'unknown'}); not a confirmed open port."
            )
        else:
            desc = f"{name} has open {proto.upper()}/{portid} ({svc or 'unknown'})."
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, ref_port),
                name=title,
                description=desc,
                severity=canon_severity(sev),
                category="exposure",
                assets=[name],
                labels=find_labels,
                collected_at=now,
                extra=extra_find,
            )
        )
        if (
            proto == "tcp"
            and state == "open"
            and portid == "445"
            and portid not in (samba_ports or set())
        ):
            # Samba has no C$/ADMIN$; do not infer Windows admin shares there.
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
    covey = parse_pack_drop(
        path,
        raw,
        now,
        source=SOURCE,
        labels=list(LABELS),
        host_emitter=_emit_host,
    )
    if covey is not None:
        _stamp_demo(covey, _is_dropbox_demo(path, raw))
        return covey
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
            extra = {}
            if host.get("cdn"):
                extra["cdn"] = True
            if host.get("cdn_name"):
                extra["cdn_name"] = host.get("cdn_name")
            _emit_host(
                records,
                now,
                str(host.get("name") or "unknown-host"),
                str(host.get("addr") or ""),
                str(host.get("hostname") or ""),
                ports,
                extra=extra or None,
                extra_labels=["naabu"] if extra.get("cdn") else None,
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
            session = str(host.get("session") or "")
            sess_l = session.lower()
            if "null session" in sess_l and "authenticated" not in sess_l:
                records.append(
                    make_record(
                        kind="finding",
                        source=SOURCE,
                        ref_id=make_ref(SOURCE, f"{name}-smb-anon"),
                        name=f"Anonymous SMB NULL session on {name}",
                        description=(
                            f"{name} smbmap export Status: {session}. "
                            "NULL session only when the run was unauthenticated "
                            "and the export shows it."
                        ),
                        severity=canon_severity("high"),
                        category="exposure",
                        assets=[name],
                        labels=LABELS + ["smbmap", "smb", "anonymous"],
                        collected_at=now,
                        extra={"port": "445", "service": "smb", "session": session, "ip": addr},
                    )
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
                sev = canon_severity("high" if writable else "medium")
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
    zmap_hosts = parse_zmap(path, raw)
    if zmap_hosts is not None:
        records = []
        for host in zmap_hosts:
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
                extra_labels=["zmap"],
            )
        _stamp_demo(records, _is_dropbox_demo(path, raw))
        return records
    uni_hosts = parse_unicornscan(path, raw)
    if uni_hosts is not None:
        records = []
        for host in uni_hosts:
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
                extra_labels=["unicornscan"],
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
    run_start = root.attrib.get("start", "")
    for host in root.findall("host"):
        host_start = len(records)
        scan_epoch = host.attrib.get("starttime") or run_start
        state_el = host.find("status")
        if state_el is not None and state_el.attrib.get("state") == "down":
            continue
        addr = ""
        ips: list[str] = []
        macs: list[str] = []
        mac_vendor = ""
        for address in host.findall("address"):
            atype = address.attrib.get("addrtype")
            token = address.attrib.get("addr", "")
            if atype == "mac":
                if token:
                    macs.append(token)
                mac_vendor = address.attrib.get("vendor", "") or mac_vendor
                continue
            if atype in {None, "ipv4", "ipv6"}:
                addr = token or addr
                if token:
                    ips.append(token)
        hostnames: list[str] = []
        hostname = ""
        hnames = host.find("hostnames")
        if hnames is not None:
            for hn in hnames.findall("hostname"):
                token = hn.attrib.get("name", "")
                if token:
                    hostnames.append(token)
                    if not hostname:
                        hostname = token
        smb_netbios = ""
        smb_fqdn = ""
        smb_domain = ""
        for script in host.findall("hostscript/script"):
            if script.attrib.get("id") != "smb-os-discovery":
                continue
            for elem in script.findall("elem"):
                key = str(elem.attrib.get("key") or "")
                val = (elem.text or "").strip()
                if key == "server" and val:
                    smb_netbios = val
                elif key == "fqdn" and val:
                    smb_fqdn = val
                elif key == "domain" and val:
                    smb_domain = val
        hostname = hostname or smb_fqdn
        name = hostname or addr or "unknown-host"
        ports: list[tuple[str, str, str]] = []
        samba_ports: set[str] = set()
        nse_specs: list[tuple[str, str, dict]] = []
        vuln_specs: list[tuple[str, str, dict]] = []
        smb_port = ""
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                proto = (port.attrib.get("protocol") or "tcp").lower()
                state_name = state.attrib.get("state") if state is not None else ""
                keep_state = state_name == "open" or (
                    state_name == "open|filtered" and proto == "udp"
                )
                if not keep_state:
                    continue
                portid = port.attrib.get("portid", "")
                service = port.find("service")
                svc = service.attrib.get("name", "") if service is not None else ""
                product = service.attrib.get("product", "") if service is not None else ""
                if "samba" in product.lower():
                    samba_ports.add(portid)
                if portid in {"445", "139"} and not smb_port:
                    smb_port = portid
                ports.append((portid, svc, proto, state_name))
                scripts = [
                    (sc.attrib.get("id", ""), sc.attrib.get("output", ""))
                    for sc in port.findall("script")
                ]
                for spec in nse_findings(name, addr, portid, svc, product, scripts):
                    nse_specs.append((portid, svc, spec))
                for sc in port.findall("script"):
                    if sc.attrib.get("id") != "vulners":
                        continue
                    elems = [
                        (el.attrib.get("key", ""), (el.text or "").strip())
                        for el in sc.findall(".//elem")
                    ]
                    for hit in vulners_cves(sc.attrib.get("output", ""), elems):
                        vuln_specs.append((portid, svc, hit))
        host_scripts = [
            (sc.attrib.get("id", ""), sc.attrib.get("output", ""))
            for sc in host.findall("hostscript/script")
        ]
        for spec in nse_findings(name, addr, smb_port, "microsoft-ds", "", host_scripts):
            nse_specs.append((smb_port, "microsoft-ds", spec))
        host_extra: dict[str, Any] = {
            "ip": ips or addr,
            "mac": macs[0] if macs else "",
            "macs": macs,
            "fqdn": smb_fqdn or hostname,
            "netbios": smb_netbios,
            "domain": smb_domain,
        }
        if mac_vendor:
            host_extra["vendor"] = mac_vendor
        _emit_host(
            records,
            now,
            name,
            addr,
            hostname,
            ports,
            extra=host_extra,
            samba_ports=samba_ports,
        )
        for portid, svc, spec in nse_specs:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{name}-{portid or 'host'}-{spec['check_id']}"),
                    name=spec["name"],
                    description=spec["description"],
                    severity=canon_severity(spec["severity"]),
                    category="misconfiguration",
                    assets=[name],
                    labels=LABELS + ["nse", spec["nse_script"]],
                    collected_at=now,
                    extra={
                        "port": portid,
                        "service": svc,
                        "ip": addr,
                        "check_id": spec["check_id"],
                        "nse_script": spec["nse_script"],
                        "evidence": spec["evidence"],
                        "tool": "nmap",
                    },
                )
            )
        kev_ids = _kev_cve_ids()
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for portid, svc, hit in vuln_specs:
            grouped.setdefault((portid, svc), []).append(hit)
        for (portid, svc), hits in grouped.items():
            _emit_vulners_hits(records, now, name, addr, portid, svc, hits, kev_ids)
        if scan_epoch:
            from datetime import datetime, timezone

            try:
                stamp = datetime.fromtimestamp(int(scan_epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OverflowError, OSError):
                stamp = ""
            if stamp:
                for rec in records[host_start:]:
                    rec.setdefault("extra", {}).setdefault("scan_time", stamp)
    _stamp_demo(records, _is_dropbox_demo(path, raw))
    return records


def main() -> None:
    run_collector(SOURCE, (".xml", ".gnmap", ".txt", ".json", ".jsonl", ".csv", ".md"), parse_file)


if __name__ == "__main__":
    main()
