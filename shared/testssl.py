"""Parse dropped testssl.sh JSON. No sockets. No live TLS probes."""

from __future__ import annotations

import re
from typing import Any, Iterator

from shared.schema import canon_severity

# Raw testssl `id` → human failure title. Scanner IDs like
# cert_expirationStatus must not become the POA&M weakness name.
TESTSSL_TITLES: dict[str, str] = {
    "cert_expirationStatus": "TLS certificate is expired or expiring",
    "cert_caIssuers": "Certificate CA Issuers URL could not be checked",
    "BREACH": "HTTPS response compression enables BREACH",
    "LUCKY13": "TLS CBC ciphers enable LUCKY13",
    "heartbleed": "TLS stack is vulnerable to Heartbleed",
    "TLS1": "TLS 1.0 is offered",
    "TLS1_1": "TLS 1.1 is offered",
    "TLS1_2": "TLS 1.2 is not offered",
    "TLS1_3": "TLS 1.3 is not offered",
    "SSLv3": "SSLv3 is offered",
    "SSLv2": "SSLv2 is offered",
    "cert_trust_wildcard": "Wildcard certificate trust is too broad",
    "DNS_CAArecord": "CAA DNS record is missing or invalid",
}

_SKIP_SEV = frozenset({"ok", "info", "information", "debug", "warnok"})
_KEEP_SEV = frozenset({"low", "medium", "high", "critical", "warn", "warning"})
_SCAN_ERROR = frozenset({"warn", "warning"})
# Pretty --jsonfile-pretty scanResult list sections (testssl 3.x).
_SKIP_SECTIONS = frozenset(
    {
        "clientpretest",
        "grease",
        "browsersimulations",
        "ciphertests",
        "rating",
    }
)


def human_title(fid: str, finding: str = "") -> str:
    """Human failure title for a testssl id. Never return raw camelCase IDs."""
    raw = str(fid or "").strip()
    if raw in TESTSSL_TITLES:
        return TESTSSL_TITLES[raw]
    for tok, title in TESTSSL_TITLES.items():
        if tok.lower() == raw.lower():
            return title
    if raw:
        spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", raw)
        spaced = spaced.replace("_", " ").strip()
        looks_like_id = "_" in raw or any(c.isupper() for c in raw[1:])
        if looks_like_id and spaced:
            return spaced[:1].upper() + spaced[1:]
    return str(finding or "").strip() or raw or "TLS finding"


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


def _emit(row: dict[str, Any], host: str, ip: str = "") -> dict[str, Any] | None:
    sev = str(row.get("severity") or row.get("Severity") or "").strip().lower()
    finding = str(row.get("finding") or row.get("Finding") or "")
    fid = str(row.get("id") or row.get("Id") or row.get("cve") or "testssl")
    blob = f"{fid} {finding} {sev}".lower()
    if "not vulnerable" in blob:
        return None
    # "not offered" is noise only when the row is already OK/INFO.
    # TLS 1.2/1.3 not offered is a real CRITICAL/HIGH/MEDIUM/LOW finding.
    if "not offered" in blob and sev in _SKIP_SEV:
        return None
    if sev in _SKIP_SEV:
        return None
    if sev and sev not in _KEEP_SEV:
        return None
    if not sev:
        sev = "high"
    labels: list[str] = []
    if sev in _SCAN_ERROR:
        labels.append("scan-error")
        sev = "info"
    sev = canon_severity(sev)
    return {
        "host": host,
        "ip": ip,
        "id": fid,
        "severity": sev,
        "finding": finding or fid,
        "cve": str(row.get("cve") or row.get("CVE") or ""),
        "labels": labels,
    }


def _section_rows(scan: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for key, val in scan.items():
        if not isinstance(val, list):
            continue
        if str(key).lower() in _SKIP_SECTIONS:
            continue
        for row in val:
            if isinstance(row, dict) and (row.get("id") or row.get("finding") or row.get("Finding")):
                yield row


def iter_testssl_findings(payload: Any) -> Iterator[dict[str, Any]]:
    """Yield LOW+ testssl rows from every scanResult list section or a native array."""
    if isinstance(payload, dict) and isinstance(payload.get("scanResult"), list):
        for scan in payload["scanResult"]:
            if not isinstance(scan, dict):
                continue
            host = _host_from_row(scan, "unknown")
            ip = str(scan.get("ip") or "").split("/")[0].strip()
            for row in _section_rows(scan):
                item = _emit(row, _host_from_row(row, host), ip)
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
        item = _emit(row, _host_from_row(row, default_host), str(row.get("ip") or ""))
        if item:
            yield item
