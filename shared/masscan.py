"""Parse dropped masscan -oX XML or -oJ JSON. No subprocess. No live scan."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from shared.io_util import read_text


def is_masscan_text(text: str, name: str = "") -> bool:
    if "masscan" in name.lower():
        return True
    low = text[:12000].lower()
    if "scanner=\"masscan\"" in low or "scanner='masscan'" in low:
        return True
    if "<!--masscan" in low:
        return True
    return False


def _port_open(row: dict[str, Any]) -> bool:
    state = str(row.get("state") or row.get("status") or "open").lower()
    return state == "open"


def _port_id(row: dict[str, Any]) -> str:
    return str(row.get("port") or row.get("portid") or "").strip()


def _rows_from_payload(payload: Any) -> list[dict[str, Any]] | None:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return None
    if payload.get("scanner") == "masscan" or payload.get("tool") == "masscan":
        raw = payload.get("hosts") or payload.get("data") or payload.get("results")
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
        if payload.get("ip") or payload.get("addr"):
            return [payload]
        return []
    if "hosts" in payload:
        return None
    if payload.get("ip") or payload.get("addr"):
        ports = payload.get("ports")
        if isinstance(ports, list):
            return [payload]
    return None


def _looks_like_masscan_json(rows: list[dict[str, Any]]) -> bool:
    if not rows:
        return False
    row = rows[0]
    ports = row.get("ports")
    if not isinstance(ports, list):
        return False
    if not ports:
        return True
    first = ports[0]
    if not isinstance(first, dict):
        return False
    return "proto" in first or "status" in first or "reason" in first


def _hosts_from_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        addr = str(row.get("ip") or row.get("addr") or row.get("address") or "").strip()
        hostname = str(row.get("hostname") or row.get("name") or row.get("host") or "").strip()
        ports: list[tuple[str, str]] = []
        for p in row.get("ports") or []:
            if not isinstance(p, dict) or not _port_open(p):
                continue
            portid = _port_id(p)
            if not portid:
                continue
            svc = str(p.get("service") or p.get("name") or p.get("proto") or "")
            ports.append((portid, svc))
        if not ports:
            continue
        name = hostname or addr or "unknown-host"
        out.append({"name": name, "addr": addr, "hostname": hostname, "ports": ports})
    return out


def _from_xml(text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out: list[dict[str, Any]] = []
    for host in root.iter():
        tag = host.tag.split("}")[-1].lower()
        if tag != "host":
            continue
        addr = ""
        hostname = ""
        ports: list[tuple[str, str]] = []
        for child in list(host):
            ctag = child.tag.split("}")[-1].lower()
            if ctag == "address":
                if child.attrib.get("addrtype") in {None, "ipv4", "ipv6"}:
                    addr = child.attrib.get("addr", addr)
            elif ctag == "hostnames":
                hn = child.find("hostname")
                if hn is None:
                    for sub in list(child):
                        if sub.tag.split("}")[-1].lower() == "hostname":
                            hn = sub
                            break
                if hn is not None:
                    hostname = hn.attrib.get("name", "")
            elif ctag == "ports":
                for port in list(child):
                    if port.tag.split("}")[-1].lower() != "port":
                        continue
                    state_el = None
                    svc = port.attrib.get("protocol") or ""
                    for pchild in list(port):
                        ptag = pchild.tag.split("}")[-1].lower()
                        if ptag == "state":
                            state_el = pchild
                        elif ptag == "service":
                            svc = pchild.attrib.get("name") or svc
                    if state_el is not None and state_el.attrib.get("state") != "open":
                        continue
                    portid = port.attrib.get("portid") or port.attrib.get("port") or ""
                    if portid:
                        ports.append((str(portid), svc))
        if not ports:
            continue
        name = hostname or addr or "unknown-host"
        out.append({"name": name, "addr": addr, "hostname": hostname, "ports": ports})
    return out


def parse_masscan(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return hosts with open ports, or None when the file is not masscan."""
    text = raw if raw is not None else read_text(path)
    stripped = text.lstrip("\ufeff").lstrip()
    named = "masscan" in path.name.lower()
    if stripped.startswith("<") or path.suffix.lower() == ".xml":
        if not (named or is_masscan_text(text, path.name)):
            return None
        return _from_xml(stripped)
    payload: Any = None
    if stripped.startswith("{") or stripped.startswith("[") or path.suffix.lower() == ".json":
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            rows: list[dict[str, Any]] = []
            for line in stripped.splitlines():
                line = line.strip()
                if not line or line in {"[", "]", ","}:
                    continue
                try:
                    item = json.loads(line.rstrip(","))
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    rows.append(item)
            payload = rows
    if payload is None:
        if named:
            return []
        return None
    rows = _rows_from_payload(payload)
    if rows is None:
        return None
    if not (named or is_masscan_text(text, path.name) or _looks_like_masscan_json(rows)):
        return None
    return _hosts_from_rows(rows)
