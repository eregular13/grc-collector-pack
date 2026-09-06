from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import OrderedDict
from pathlib import Path

from shared.io_util import discover_input_files, emit
from shared.schema import asset, control_extra, evidence, finding

SOURCE = "inventory_nmap"
PREFIX = "NMAP-"

RISKY_PORTS = {
    21: ("medium", "FTP exposed", "CTL-DISABLE-FTP", "Disable cleartext FTP", "protect"),
    23: ("high", "Telnet exposed", "CTL-DISABLE-TELNET", "Disable telnet", "protect"),
    445: ("high", "SMB (445) exposed", "CTL-SMB-HARDEN", "Harden SMB / restrict 445", "protect"),
    3389: ("medium", "RDP exposed", "CTL-RDP-NLA", "Require NLA and restrict RDP", "protect"),
    9100: ("medium", "JetDirect/printer port exposed", "CTL-PRINT-SEG", "Segment printer VLAN", "protect"),
    139: ("low", "NetBIOS exposed", "CTL-NETBIOS", "Disable NetBIOS where unused", "protect"),
}

_GNMAP_HOST = re.compile(
    r"^Host:\s+(?P<ip>\S+)\s*(?:\((?P<hostname>[^)]*)\))?(?P<rest>.*)$",
    re.IGNORECASE,
)
_GNMAP_PORT = re.compile(
    r"(?P<port>\d+)/(?P<state>[^/]*)/(?P<proto>[^/]*)/[^/]*/(?P<service>[^/]*)"
)


def _hostname(host: ET.Element) -> tuple[str | None, str]:
    """Prefer nmap hostname type=user over PTR reverse-DNS."""
    user: str | None = None
    ptr: str | None = None
    other: str | None = None
    for hn in host.findall("./hostnames/hostname"):
        name = (hn.get("name") or "").strip()
        if not name:
            continue
        htype = (hn.get("type") or "").strip().lower()
        if htype == "user":
            if user is None:
                user = name
        elif htype == "ptr":
            if ptr is None:
                ptr = name
        elif other is None:
            other = name
    if user:
        return user, "user"
    if ptr:
        return ptr, "ptr"
    if other:
        return other, "other"
    return None, ""


def _ip(host: ET.Element) -> tuple[str | None, str]:
    ipv4: str | None = None
    ipv6: str | None = None
    for addr in host.findall("./address"):
        value = (addr.get("addr") or "").strip()
        if not value:
            continue
        atype = (addr.get("addrtype") or "").lower()
        if atype == "mac":
            continue
        if atype in {"", "ipv4"} and ":" not in value:
            ipv4 = ipv4 or value
        elif atype == "ipv6" or ":" in value:
            ipv6 = ipv6 or value
        elif not ipv4:
            ipv4 = value
    if ipv4:
        return ipv4, "ipv4"
    if ipv6:
        return ipv6, "ipv6"
    return None, ""


def _host_records(
    name: str,
    ip: str,
    open_ports: list[tuple[int, str]],
    *,
    via: str = "xml",
    hostname_type: str = "",
) -> list:
    records: list = []
    labels = ["nmap", "host"]
    if via == "gnmap":
        labels.append("gnmap")
    labels.append("named" if name != ip else "ip-only")
    if hostname_type:
        labels.append(f"hostname-{hostname_type}")
    if ":" in ip:
        labels.append("ipv6")
    extra: dict = {"ip": ip}
    if via == "gnmap":
        extra["format"] = "gnmap"
    if hostname_type:
        extra["hostname_type"] = hostname_type
    records.append(
        asset(
            PREFIX,
            name,
            name,
            description=f"Host {name} ({ip})",
            asset_type="SP",
            source=SOURCE,
            labels=labels,
            extra=extra,
        )
    )
    port_ids: list[int] = []
    for portid, service in open_ports:
        port_ids.append(portid)
        if portid not in RISKY_PORTS:
            continue
        sev, title, ctl_id, ctl_name, csf = RISKY_PORTS[portid]
        suffix = " [gnmap]" if via == "gnmap" else ""
        flabels = ["nmap", f"port-{portid}"]
        if via == "gnmap":
            flabels.insert(1, "gnmap")
        records.append(
            finding(
                PREFIX,
                f"{name}-{portid}",
                f"{title} on {name}",
                description=f"Open tcp/{portid} ({service or 'unknown'}) on {name} ({ip}).{suffix}",
                severity=sev,
                source=SOURCE,
                related_assets=[name],
                labels=flabels,
                extra=control_extra(ctl_id, ctl_name, csf_function=csf, priority="2"),
            )
        )
    if 445 in port_ids and ("dc" in name.lower() or name.lower().startswith("dc")):
        records.append(
            finding(
                PREFIX,
                f"{name}-DC-445",
                f"Domain controller SMB reachable: {name}",
                description=f"DC {name} has tcp/445 open. Restrict admin protocols to jump hosts.",
                severity="high",
                source=SOURCE,
                related_assets=[name],
                labels=["nmap", "dc", "smb"],
                extra=control_extra(
                    "CTL-DC-TIER0",
                    "Tier-0 network isolation for DCs",
                    csf_function="protect",
                    priority="1",
                ),
            )
        )
    return records


def _host_is_up(host: ET.Element) -> bool:
    """Skip nmap XML hosts with <status state="down"/> (case-insensitive)."""
    status = host.find("status")
    if status is None:
        return True
    state = (status.get("state") or "").strip().lower()
    if not state:
        return True
    return state != "down"


def parse_nmap_xml(path: Path) -> list:
    records: list = []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return records
    root = tree.getroot()
    for host in root.findall("host"):
        if not _host_is_up(host):
            continue
        ip, _family = _ip(host)
        if not ip:
            continue
        hostname, htype = _hostname(host)
        name = hostname or ip
        open_ports: list[tuple[int, str]] = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                portid = int(port.get("portid", "0"))
            except ValueError:
                continue
            service_el = port.find("service")
            service = service_el.get("name") if service_el is not None else ""
            product = (service_el.get("product") or "") if service_el is not None else ""
            version = (service_el.get("version") or "") if service_el is not None else ""
            open_ports.append((portid, service or ""))
            blob = f"{service} {product} {version}".lower()
            if "openssh" in blob and re.search(r"\b5\.\d", blob):
                records.append(
                    finding(
                        PREFIX,
                        f"{name}-{portid}-openssh5",
                        f"Outdated SSH server OpenSSH 5.x on {name}",
                        description=f"Open tcp/{portid} {product} {version} on {name} ({ip}).",
                        severity="high",
                        source=SOURCE,
                        related_assets=[name],
                        labels=["nmap", "ssh", "outdated"],
                        extra=control_extra(
                            "CTL-SSH-UPGRADE",
                            "Upgrade OpenSSH; restrict management SSH",
                            csf_function="protect",
                            priority="2",
                        ),
                    )
                )
        records.extend(_host_records(name, ip, open_ports, via="xml", hostname_type=htype))
    return records


def _parse_gnmap_ports(field: str) -> list[tuple[int, str]]:
    ports: list[tuple[int, str]] = []
    if not field:
        return ports
    for chunk in field.split(","):
        chunk = chunk.strip()
        match = _GNMAP_PORT.match(chunk)
        if not match or match.group("state").lower() != "open":
            continue
        try:
            portid = int(match.group("port"))
        except ValueError:
            continue
        ports.append((portid, match.group("service") or ""))
    return ports


def line_has_gnmap(text: str) -> bool:
    has_header = False
    has_host = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") and "Nmap" in stripped:
            has_header = True
        if stripped.startswith("Host:"):
            has_host = True
        if has_header and has_host:
            return True
    return has_host


def parse_nmap_gnmap(path: Path) -> list:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    hosts: OrderedDict[str, dict] = OrderedDict()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.lower().startswith("host:"):
            continue
        match = _GNMAP_HOST.match(stripped)
        if not match:
            continue
        ip = match.group("ip")
        hostname = (match.group("hostname") or "").strip()
        rest = match.group("rest") or ""
        status_m = re.search(r"\bStatus:\s*(\S+)", rest, re.IGNORECASE)
        ports_m = re.search(r"\bPorts:\s*(.*?)(?:\s+Ignored State:|$)", rest, re.IGNORECASE)
        rec = hosts.setdefault(ip, {"ip": ip, "hostname": "", "status": "", "ports": []})
        if hostname:
            rec["hostname"] = hostname
        if status_m:
            rec["status"] = status_m.group(1)
        if ports_m:
            rec["ports"].extend(_parse_gnmap_ports(ports_m.group(1)))
    records: list = []
    for rec in hosts.values():
        if str(rec["status"]).lower() == "down":
            continue
        name = rec["hostname"] or rec["ip"]
        records.extend(_host_records(name, rec["ip"], rec["ports"], via="gnmap"))
    return records


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        suffix = path.suffix.lower()
        if suffix in {".gnmap", ".grep"} or line_has_gnmap(text):
            records.extend(parse_nmap_gnmap(path))
            continue
        if suffix in {".xml", ".nmap"} or "<nmaprun" in text:
            records.extend(parse_nmap_xml(path))
    return records


def main() -> None:
    files = discover_input_files("nmap")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "NMAP",
            "Nmap demo parse",
            description="Parsed nmap XML and grepable/gnmap. GRC_LIVE_SCAN is off; nmap was not executed.",
            source=SOURCE,
        )
    )
    emit("nmap", records, files)


if __name__ == "__main__":
    main()
