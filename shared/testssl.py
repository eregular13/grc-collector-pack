"""Parse dropped testssl.sh JSON. No sockets. No live TLS probes."""

from __future__ import annotations

from typing import Any, Iterator

_SKIP_SEV = frozenset({"ok", "info", "information", "low", "debug", "warnok"})
_KEEP_SEV = frozenset({"high", "critical", "warn", "warning"})


def _host_from_row(row: dict[str, Any], default: str) -> str:
    raw = str(row.get("targetHost") or row.get("host") or row.get("ip") or default or "unknown")
    host = raw.split("/")[0].split(":")[0].strip()
    return host or default or "unknown"


def is_testssl(payload: Any) -> bool:
    if isinstance(payload, dict) and isinstance(payload.get("scanResult"), list):
        return True
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        row = payload[0]
        return "finding" in row and ("severity" in row or "id" in row)
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        rows = payload["findings"]
        return bool(rows) and isinstance(rows[0], dict) and "finding" in rows[0]
    return False


def _emit(row: dict[str, Any], host: str) -> dict[str, Any] | None:
    sev = str(row.get("severity") or row.get("Severity") or "").strip().lower()
    finding = str(row.get("finding") or row.get("Finding") or "")
    fid = str(row.get("id") or row.get("Id") or row.get("cve") or "testssl")
    blob = f"{fid} {finding} {sev}".lower()
    if "not vulnerable" in blob or "not offered" in blob:
        return None
    if sev in _SKIP_SEV:
        return None
    if sev and sev not in _KEEP_SEV:
        return None
    if not sev:
        sev = "high"
    return {
        "host": host,
        "id": fid,
        "severity": sev,
        "finding": finding or fid,
        "cve": str(row.get("cve") or row.get("CVE") or ""),
    }


def iter_testssl_findings(payload: Any) -> Iterator[dict[str, Any]]:
    """Yield high/warn testssl rows from scanResult wrapper or native array."""
    if isinstance(payload, dict) and isinstance(payload.get("scanResult"), list):
        for scan in payload["scanResult"]:
            if not isinstance(scan, dict):
                continue
            host = _host_from_row(scan, "unknown")
            rows = scan.get("vulnerabilities") or scan.get("findings") or []
            if not isinstance(rows, list):
                continue
            for row in rows:
                if isinstance(row, dict):
                    item = _emit(row, _host_from_row(row, host))
                    if item:
                        yield item
        return
    rows: list[Any] = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        rows = payload["findings"]
    default_host = "unknown"
    if isinstance(payload, dict):
        default_host = _host_from_row(payload, default_host)
    for row in rows:
        if not isinstance(row, dict):
            continue
        item = _emit(row, _host_from_row(row, default_host))
        if item:
            yield item
