"""Parse dropped rustscan / naabu JSON or JSONL. No subprocess. No live scan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.io_util import read_text


def _named(name: str) -> bool:
    low = name.lower()
    return "naabu" in low or "rustscan" in low


def _open(state: Any) -> bool:
    token = str(state or "open").strip().lower()
    return token in {"", "open", "opened"}


def _port_token(raw: Any) -> str:
    if raw is None or raw == "":
        return ""
    return str(raw).strip()


def _load_payload(text: str) -> Any:
    stripped = text.lstrip("\ufeff").lstrip()
    if not stripped:
        return []
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        rows: list[Any] = []
        for line in stripped.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in {"[", "]"}:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows


def _looks_naabu(row: dict[str, Any]) -> bool:
    if row.get("port") in (None, ""):
        return False
    if isinstance(row.get("ports"), list) and row["ports"] and isinstance(row["ports"][0], dict):
        return False
    return bool(row.get("ip") or row.get("host") or row.get("hostname") or row.get("addr"))


def _looks_rustscan(payload: Any) -> bool:
    if isinstance(payload, dict):
        if payload.get("scanner") == "rustscan" or payload.get("tool") == "rustscan":
            return True
        ports = payload.get("ports")
        if isinstance(ports, list) and (payload.get("ip") or payload.get("host") or payload.get("hostname")):
            if not ports:
                return True
            return all(isinstance(p, (int, str)) for p in ports) or (
                isinstance(ports[0], dict) and "state" not in ports[0] and "status" not in ports[0]
            )
        if ports is None and payload and all(
            isinstance(v, list) and all(isinstance(x, (int, str)) for x in v)
            for v in payload.values()
            if not isinstance(v, (str, int, float, bool, type(None)))
        ):
            keys = [k for k in payload if k not in {"scanner", "tool", "type"}]
            return bool(keys) and all(isinstance(k, str) and ("." in k or k[0].isdigit()) for k in keys)
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        row = payload[0]
        ports = row.get("ports")
        if isinstance(ports, list) and (row.get("ip") or row.get("host") or row.get("hostname")):
            if not ports:
                return True
            return all(isinstance(p, (int, str)) for p in ports)
    return False


def _is_fast_portscan(payload: Any, name: str) -> bool:
    if _named(name):
        return True
    if isinstance(payload, dict):
        for key in ("data", "results", "hosts"):
            inner = payload.get(key)
            if inner is not None and _is_fast_portscan(inner, ""):
                return True
        if _looks_naabu(payload) or _looks_rustscan(payload):
            return True
    if isinstance(payload, list):
        if not payload:
            return False
        if all(isinstance(x, dict) and _looks_naabu(x) for x in payload[:3] if isinstance(x, dict)):
            return True
        return _looks_rustscan(payload)
    return False


def _push(
    grouped: dict[str, dict[str, Any]], addr: str, hostname: str, portid: str, svc: str
) -> None:
    if not portid:
        return
    name = hostname or addr
    if not name:
        return
    key = name.lower()
    slot = grouped.setdefault(key, {"name": name, "addr": addr, "hostname": hostname, "ports": []})
    if addr and not slot.get("addr"):
        slot["addr"] = addr
    if hostname and not slot.get("hostname"):
        slot["hostname"] = hostname
        slot["name"] = hostname
    ports: list[tuple[str, str]] = slot["ports"]
    if not any(p == portid for p, _ in ports):
        ports.append((portid, svc))


def _from_naabu_row(grouped: dict[str, dict[str, Any]], row: dict[str, Any]) -> None:
    if not _open(row.get("status") or row.get("state")):
        return
    addr = str(row.get("ip") or row.get("addr") or "").strip()
    hostname = str(row.get("host") or row.get("hostname") or row.get("dns") or "").strip()
    if hostname and hostname.replace(".", "").isdigit():
        if not addr:
            addr = hostname
        hostname = ""
    _push(grouped, addr, hostname, _port_token(row.get("port") or row.get("portid")), str(row.get("proto") or "tcp"))


def _from_rustscan_ports(
    grouped: dict[str, dict[str, Any]], addr: str, hostname: str, ports: list[Any]
) -> None:
    for item in ports:
        if isinstance(item, dict):
            if not _open(item.get("status") or item.get("state")):
                continue
            _push(
                grouped,
                addr,
                hostname,
                _port_token(item.get("port") or item.get("portid")),
                str(item.get("proto") or item.get("service") or ""),
            )
            continue
        _push(grouped, addr, hostname, _port_token(item), "")


def _walk(payload: Any, grouped: dict[str, dict[str, Any]]) -> None:
    if isinstance(payload, list):
        for item in payload:
            _walk(item, grouped)
        return
    if not isinstance(payload, dict):
        return
    for key in ("data", "results"):
        inner = payload.get(key)
        if isinstance(inner, (list, dict)):
            _walk(inner, grouped)
            return
    hosts = payload.get("hosts")
    if isinstance(hosts, dict):
        for host, ports in hosts.items():
            if isinstance(ports, list):
                addr = str(host) if str(host).replace(".", "").isdigit() else ""
                hostname = "" if addr else str(host)
                _from_rustscan_ports(grouped, addr, hostname, ports)
        return
    if isinstance(hosts, list):
        _walk(hosts, grouped)
        return
    if _looks_naabu(payload):
        _from_naabu_row(grouped, payload)
        return
    ports = payload.get("ports")
    if isinstance(ports, list) and (payload.get("ip") or payload.get("host") or payload.get("hostname")):
        addr = str(payload.get("ip") or payload.get("addr") or "").strip()
        hostname = str(payload.get("hostname") or payload.get("host") or payload.get("name") or "").strip()
        _from_rustscan_ports(grouped, addr, hostname, ports)
        return
    if payload.get("scanner") == "rustscan" or payload.get("tool") == "rustscan":
        return
    keys = [k for k, v in payload.items() if isinstance(v, list) and k not in {"ports"}]
    if keys and all(isinstance(payload[k], list) and all(isinstance(x, (int, str)) for x in payload[k]) for k in keys):
        if all("." in str(k) or str(k)[0].isdigit() for k in keys):
            for host in keys:
                addr = str(host) if str(host).replace(".", "").isdigit() else ""
                hostname = "" if addr else str(host)
                _from_rustscan_ports(grouped, addr, hostname, payload[host])


def parse_fast_portscan(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return hosts with open ports, or None when the file is not rustscan/naabu."""
    if path.suffix.lower() not in {".json", ".jsonl", ".txt", ""} and not _named(path.name):
        if path.suffix.lower() in {".xml", ".gnmap"}:
            return None
    text = raw if raw is not None else read_text(path)
    stripped = text.lstrip("\ufeff").lstrip()
    if stripped.startswith("<"):
        return None
    payload = _load_payload(text)
    if not _is_fast_portscan(payload, path.name):
        if _named(path.name):
            return []
        return None
    grouped: dict[str, dict[str, Any]] = {}
    _walk(payload, grouped)
    return [slot for slot in grouped.values() if slot.get("ports")]
