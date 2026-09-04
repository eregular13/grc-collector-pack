"""Parse dropped Nikto text / XML / JSON. No subprocess. No live HTTP."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterator

from shared.io_util import read_json, read_jsonl, read_text

_SKIP = (
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "x-xss-protection",
    "content-security-policy",
    "referrer-policy",
    "httponly",
    "secure flag",
)
_INTERESTING = (
    "admin",
    "login",
    "phpmyadmin",
    "wp-admin",
    ".git",
    ".env",
    "phpinfo",
    "server-status",
    "server-info",
    "directory index",
    "directory listing",
    "indexing found",
    "default password",
    "default credential",
    "backup",
    "cve-",
)


def _tag(el: ET.Element) -> str:
    return el.tag.split("}")[-1].lower()


def is_interesting(url: str, msg: str) -> bool:
    blob = f"{url} {msg}".lower()
    if any(skip in blob for skip in _SKIP) and not any(
        tok in blob for tok in ("admin", "login", ".git", ".env", "phpmyadmin")
    ):
        return False
    return any(tok in blob for tok in _INTERESTING)


def is_nikto_payload(payload: Any) -> bool:
    if isinstance(payload, dict):
        if payload.get("template-id") or payload.get("template_id") or payload.get("templateID"):
            return False
        if payload.get("nvt"):
            return False
        raw = payload.get("vulnerabilities") or payload.get("items")
        if isinstance(raw, list):
            if not raw:
                return True
            row = raw[0]
            if not isinstance(row, dict):
                return False
            if row.get("template-id") or row.get("nvt"):
                return False
            return bool(
                row.get("msg")
                or row.get("OSVDB") is not None
                or row.get("osvdbid")
                or row.get("namelink")
            )
        return False
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        row = payload[0]
        if row.get("template-id") or row.get("nvt") or "finding" in row:
            return False
        return bool(row.get("msg") and (row.get("url") is not None or row.get("OSVDB") is not None))
    return False


def is_nikto_text(text: str, name: str = "") -> bool:
    if not text or not text.strip():
        return "nikto" in name.lower()
    low = text[:8000].lower()
    if "nessusclientdata" in low:
        return False
    if "nikto" in name.lower():
        return True
    return (
        "- nikto" in low
        or "nikto v" in low
        or "+ target hostname" in low
        or "<niktoscan" in low
        or "<scandetails" in low
    )


def _host_from(row: dict[str, Any], default: str) -> str:
    host = str(
        row.get("host")
        or row.get("hostname")
        or row.get("targethostname")
        or row.get("ip")
        or default
        or "unknown"
    ).strip()
    return host or default or "unknown"


def _rows_from_payload(payload: Any, default_host: str = "unknown") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(payload, list):
        host = default_host
        for row in payload:
            if isinstance(row, dict):
                out.append(
                    {
                        "host": _host_from(row, host),
                        "url": str(row.get("url") or row.get("uri") or "/"),
                        "msg": str(row.get("msg") or row.get("description") or row.get("message") or ""),
                        "id": str(row.get("id") or row.get("OSVDB") or row.get("osvdbid") or "nikto"),
                    }
                )
        return out
    if not isinstance(payload, dict):
        return out
    host = _host_from(payload, default_host)
    raw = payload.get("vulnerabilities") or payload.get("items") or []
    if not isinstance(raw, list):
        return out
    for row in raw:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "host": _host_from(row, host),
                "url": str(row.get("url") or row.get("uri") or "/"),
                "msg": str(row.get("msg") or row.get("description") or row.get("message") or ""),
                "id": str(row.get("id") or row.get("OSVDB") or row.get("osvdbid") or "nikto"),
            }
        )
    return out


def iter_nikto_text_rows(text: str) -> Iterator[dict[str, Any]]:
    host = "unknown"
    for line in text.splitlines():
        raw = line.strip()
        if not raw.startswith("+"):
            continue
        rest = raw[1:].strip()
        low = rest.lower()
        if low.startswith("target hostname"):
            host = rest.split(":", 1)[-1].strip() or host
            continue
        if low.startswith("target ip") and host in {"unknown", ""}:
            host = rest.split(":", 1)[-1].strip() or host
            continue
        if ":" not in rest:
            continue
        left, msg = rest.split(":", 1)
        left, msg = left.strip(), msg.strip()
        url = left
        if left.upper().startswith("OSVDB") or left.upper().startswith("CVE"):
            token = msg.strip()
            if token.startswith("/"):
                url, _, tail = token.partition(":")
                msg = tail.strip() or token
            else:
                url = "/"
        elif not left.startswith("/"):
            continue
        yield {"host": host, "url": url, "msg": msg, "id": left}


def iter_nikto_xml_rows(text: str) -> Iterator[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return
    for details in root.iter():
        if _tag(details) != "scandetails":
            continue
        host = (
            details.attrib.get("targethostname")
            or details.attrib.get("targetip")
            or "unknown"
        )
        for item in list(details):
            if _tag(item) != "item":
                continue
            desc = ""
            uri = ""
            for child in list(item):
                ctag = _tag(child)
                if ctag == "description":
                    desc = (child.text or "").strip()
                elif ctag == "uri":
                    uri = (child.text or "").strip()
            yield {
                "host": host,
                "url": uri or "/",
                "msg": desc,
                "id": item.attrib.get("id") or item.attrib.get("osvdbid") or "nikto",
            }


def parse_nikto(path: Path) -> list[dict[str, Any]] | None:
    """Return nikto rows, or None when the file is not a nikto export."""
    text = read_text(path)
    name = path.name
    if path.suffix.lower() in {".json", ".jsonl"}:
        payload: Any = None
        try:
            payload = read_json(path)
        except Exception:
            payload = None
        if payload is not None and is_nikto_payload(payload):
            return _rows_from_payload(payload)
        if payload is None:
            rows = [r for r in read_jsonl(path) if isinstance(r, dict)]
            if rows and is_nikto_payload(rows):
                return _rows_from_payload(rows)
            if rows and is_nikto_payload(rows[0]):
                return _rows_from_payload(rows)
        if is_nikto_text(text, name):
            return list(iter_nikto_text_rows(text))
        return None
    if "<niktoscan" in text.lower() or "<scandetails" in text.lower() or path.suffix.lower() == ".xml":
        if is_nikto_text(text, name):
            return list(iter_nikto_xml_rows(text))
        return None
    if is_nikto_text(text, name):
        return list(iter_nikto_text_rows(text))
    return None
