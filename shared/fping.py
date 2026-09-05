"""Parse dropped fping text or JSON. No subprocess. No live ping."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shared.io_util import read_text

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
ALIVE_RE = re.compile(
    r"^\s*(\S+)\s+is\s+(alive|unreachable|unreachable\s+\([^)]+\)|down)\s*$",
    re.IGNORECASE,
)
LOOP_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*:\s*\[",
)


def _named(name: str) -> bool:
    return "fping" in name.lower()


def _has_banner(text: str) -> bool:
    low = text[:12000].lower()
    return (
        " is alive" in low
        or " is unreachable" in low
        or "fping statistics" in low
        or low.lstrip().startswith("# fping")
    )


def _hostish(token: str) -> tuple[str, str]:
    raw = token.strip().strip(",")
    if not raw:
        return "", ""
    if IP_RE.match(raw):
        return raw, ""
    if any(c.isalpha() for c in raw):
        return "", raw
    return "", ""


def _looks_fping_json_row(row: dict[str, Any]) -> bool:
    if row.get("mac") or row.get("mac_address") or row.get("hwaddr"):
        return False
    if row.get("port") not in (None, ""):
        return False
    ports = row.get("ports")
    if isinstance(ports, list) and ports:
        return False
    target = row.get("ip") or row.get("addr") or row.get("host") or row.get("hostname") or row.get("target")
    if not target:
        return False
    if any(k in row for k in ("alive", "reachable", "up", "status", "state")):
        return True
    return False


def _alive_token(row: dict[str, Any]) -> bool | None:
    if "alive" in row:
        return bool(row.get("alive"))
    if "reachable" in row:
        return bool(row.get("reachable"))
    if "up" in row:
        return bool(row.get("up"))
    state = str(row.get("status") or row.get("state") or "").strip().lower()
    if not state:
        return None
    if state in {"alive", "up", "reachable", "ok", "true", "1"}:
        return True
    if state in {"unreachable", "down", "dead", "false", "0", "timeout"}:
        return False
    return None


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


def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    if payload.get("scanner") == "fping" or payload.get("tool") == "fping":
        raw = payload.get("hosts") or payload.get("data") or payload.get("results")
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
        if _looks_fping_json_row(payload):
            return [payload]
        return []
    for key in ("hosts", "data", "results"):
        raw = payload.get(key)
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
    if _looks_fping_json_row(payload):
        return [payload]
    return []


def _host_from_row(row: dict[str, Any]) -> dict[str, Any] | None:
    if not _looks_fping_json_row(row):
        return None
    flag = _alive_token(row)
    if flag is False:
        return None
    if flag is None and not (row.get("scanner") == "fping" or row.get("tool") == "fping"):
        return None
    addr = str(row.get("ip") or row.get("addr") or row.get("address") or "").strip()
    hostname = str(row.get("hostname") or row.get("host") or row.get("name") or row.get("target") or "").strip()
    if hostname and IP_RE.match(hostname):
        if not addr:
            addr = hostname
        hostname = ""
    if addr and not IP_RE.match(addr):
        if not hostname:
            hostname = addr
        addr = ""
    name = hostname or addr
    if not name:
        return None
    return {"name": name, "addr": addr, "hostname": hostname, "ports": []}


def _host_from_line(line: str, named: bool) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    low = stripped.lower()
    if low.startswith("host:") or "ports:" in low:
        return None
    match = ALIVE_RE.match(stripped)
    if match:
        token, state = match.group(1), match.group(2).lower()
        if not state.startswith("alive"):
            return None
        addr, hostname = _hostish(token)
        name = hostname or addr
        if not name:
            return None
        return {"name": name, "addr": addr, "hostname": hostname, "ports": []}
    loop = LOOP_RE.match(stripped)
    if loop:
        addr = loop.group(1)
        return {"name": addr, "addr": addr, "hostname": "", "ports": []}
    if named and IP_RE.match(stripped):
        return {"name": stripped, "addr": stripped, "hostname": "", "ports": []}
    return None


def _from_text(text: str, named: bool) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        host = _host_from_line(line, named)
        if host is None:
            continue
        key = str(host["name"]).lower()
        grouped.setdefault(key, host)
    return list(grouped.values())


def parse_fping(path: Path, raw: str | None = None) -> list[dict[str, Any]] | None:
    """Return alive hosts (asset-only), or None when the file is not fping."""
    text = raw if raw is not None else read_text(path)
    stripped = text.lstrip("\ufeff").lstrip()
    if stripped.startswith("<"):
        return None
    named = _named(path.name)
    is_jsonish = (
        stripped.startswith("{")
        or stripped.startswith("[")
        or path.suffix.lower() in {".json", ".jsonl"}
    )
    if is_jsonish:
        payload = _load_payload(text)
        rows = _rows_from_payload(payload)
        fping_rows = [r for r in rows if _looks_fping_json_row(r)]
        if named:
            out: list[dict[str, Any]] = []
            for row in fping_rows:
                host = _host_from_row(row)
                if host is not None:
                    out.append(host)
            return out
        if not fping_rows:
            return None
        if any(
            r.get("port") not in (None, "")
            or (isinstance(r.get("ports"), list) and r.get("ports"))
            or r.get("mac")
            or r.get("mac_address")
            for r in rows[:5]
            if isinstance(r, dict)
        ):
            return None
        out = []
        for row in fping_rows:
            host = _host_from_row(row)
            if host is not None:
                out.append(host)
        return out
    if named or _has_banner(text):
        if "Host:" in text and "Ports:" in text and not named:
            return None
        return _from_text(text, named)
    return None
