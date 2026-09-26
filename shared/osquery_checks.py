"""Parse osquery check/query exports. Failed/failing only. No osqueryi."""

from __future__ import annotations

from typing import Any

_INVENTORY_NAMES = frozenset(
    {
        "system_info",
        "os_version",
        "processes",
        "process_snapshot",
        "listening_ports",
        "users",
        "logged_in_users",
        "uptime",
        "osquery_info",
        "interface_addresses",
        "packs",
    }
)
_CHECK_HINTS = (
    "encrypt",
    "firewall",
    "permitroot",
    "ssh",
    "gatekeeper",
    "compliance",
    "cis",
    "check",
    "sharing",
    "password",
    "sip",
    "alf",
    "screenlock",
    "mdm",
    "disk_encryption",
)


def _fail_status(value: Any) -> bool:
    return str(value or "").lower() in {"fail", "failed", "error"}


def _is_check_query(name: str, cols: dict[str, Any]) -> bool:
    low = name.lower()
    if any(tok in low for tok in _CHECK_HINTS):
        return True
    if any(k in cols for k in ("encrypted", "permitrootlogin", "firewall", "disk_encryption")):
        return True
    return False


def _host_from(row: dict[str, Any], default: str) -> str:
    cols = row.get("columns") if isinstance(row.get("columns"), dict) else {}
    return str(
        row.get("hostIdentifier")
        or row.get("hostname")
        or row.get("host")
        or cols.get("hostname")
        or cols.get("hostIdentifier")
        or default
        or "osquery-host"
    )


def _expand_native(row: dict[str, Any]) -> list[dict[str, Any]]:
    """osquery 5.x event / snapshot / batch envelopes → row dicts."""
    name = str(row.get("name") or row.get("query") or "")
    if isinstance(row.get("snapshot"), list):
        return [
            {**item, "name": name, "hostIdentifier": row.get("hostIdentifier") or row.get("hostname")}
            for item in row["snapshot"]
            if isinstance(item, dict)
        ]
    diff = row.get("diffResults")
    if isinstance(diff, dict):
        out: list[dict[str, Any]] = []
        for key in ("added", "removed"):
            raw = diff.get(key)
            if isinstance(raw, list):
                for item in raw:
                    if isinstance(item, dict):
                        out.append(
                            {
                                **item,
                                "name": name,
                                "hostIdentifier": row.get("hostIdentifier") or row.get("hostname"),
                            }
                        )
        return out
    if row.get("action") and isinstance(row.get("columns"), dict):
        return [
            {
                **row["columns"],
                "name": name,
                "hostIdentifier": row.get("hostIdentifier") or row.get("hostname"),
                "columns": row["columns"],
            }
        ]
    return [row]


def iter_osquery_failures(payload: Any) -> list[dict[str, str]]:
    """Return failed osquery check rows. Inventory/pass/empty invent nothing."""
    rows: list[dict[str, Any]] = []
    host_default = ""
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                rows.extend(_expand_native(item))
    elif isinstance(payload, dict):
        host_default = str(
            payload.get("hostIdentifier") or payload.get("hostname") or payload.get("host") or ""
        )
        if payload.get("action") or payload.get("snapshot") or payload.get("diffResults"):
            rows.extend(_expand_native(payload))
        if isinstance(payload.get("queries"), list):
            rows.extend(r for r in payload["queries"] if isinstance(r, dict))
        elif isinstance(payload.get("queries"), dict):
            for qname, q in payload["queries"].items():
                if isinstance(q, dict):
                    rows.append({**q, "name": q.get("name") or qname})
                elif isinstance(q, list):
                    for item in q:
                        if isinstance(item, dict):
                            rows.append({**item, "name": item.get("name") or qname})
        osq = payload.get("osquery")
        if isinstance(osq, list):
            rows.extend(r for r in osq if isinstance(r, dict))
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        cols = row.get("columns") if isinstance(row.get("columns"), dict) else {}
        name = str(row.get("name") or row.get("query") or cols.get("name") or "osquery")
        status_hit = _fail_status(row.get("status") or row.get("result") or row.get("outcome"))
        native = bool(row.get("hostIdentifier") or row.get("action") or row.get("snapshot") or "encrypted" in row)
        checkish = _is_check_query(name, {**cols, **{k: row.get(k) for k in ("encrypted", "permitrootlogin", "firewall") if k in row}})
        if name.lower() in _INVENTORY_NAMES and not checkish:
            continue
        if not status_hit and not (native and checkish):
            continue
        if not status_hit and not checkish:
            continue
        host = _host_from(row, host_default)
        title = str(row.get("title") or row.get("description") or name.replace("_", " "))
        key = (name, host)
        if key in seen:
            continue
        seen.add(key)
        out.append({"id": name, "title": title, "host": host, "result": "fail"})
    return out
