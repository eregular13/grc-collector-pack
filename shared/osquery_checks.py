"""Parse osquery check/query exports. Failed/failing only. No osqueryi.

A query name that happens to contain 'check' / 'compliance' / 'ssh' is
not a failure. Only query-defined pass/fail columns, or an explicit
allowlist of failure-shaped queries, emit findings. Everything else is
inventory.
"""

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

# Query-defined result columns. Presence means the query scored itself.
_STATUS_KEYS = ("status", "result", "outcome")
_BOOL_PASS_KEYS = ("passed", "compliant")

_FAIL_STATUS = frozenset({"fail", "failed", "error", "not ok", "notok"})
_FALSE = frozenset({"0", "false", "no", "off", "unencrypted", "disabled", "none"})

# Explicit failure-shaped queries: name suffix → (column, fail values).
# Official it-compliance pack queries that are not in this map stay inventory.
_ALLOWLIST_FAIL_COL: dict[str, tuple[str, frozenset[str]]] = {
    "disk_encryption": ("encrypted", _FALSE),
    "filevault": ("encrypted", _FALSE),
    "bitlocker": ("encrypted", _FALSE),
}


def _fail_status(value: Any) -> bool:
    return str(value or "").lower().replace(" ", "") in {s.replace(" ", "") for s in _FAIL_STATUS}


def _as_false(value: Any) -> bool:
    return str(value or "").strip().lower().replace(" ", "").replace("_", "") in {
        t.replace(" ", "").replace("_", "") for t in _FALSE
    }


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


def _allowlist_fail(name: str, row: dict[str, Any], cols: dict[str, Any]) -> bool | None:
    low = name.lower()
    for suffix, (col, fail_vals) in _ALLOWLIST_FAIL_COL.items():
        if suffix in low or low.endswith(suffix):
            if col in row or col in cols:
                raw = row.get(col) if col in row else cols.get(col)
                token = str(raw or "").strip().lower().replace(" ", "").replace("_", "")
                fail_c = {t.replace(" ", "").replace("_", "") for t in fail_vals}
                return token in fail_c
            return False
    return None


def _row_is_failure(name: str, row: dict[str, Any], cols: dict[str, Any]) -> bool:
    """True only when the query defined a fail, or an allowlisted column failed."""
    for key in _STATUS_KEYS:
        if key in row or key in cols:
            raw = row.get(key) if key in row else cols.get(key)
            return _fail_status(raw)
    for key in _BOOL_PASS_KEYS:
        if key in row or key in cols:
            raw = row.get(key) if key in row else cols.get(key)
            return _as_false(raw)
    allow = _allowlist_fail(name, row, cols)
    if allow is not None:
        return allow
    return False


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
        if name.lower() in _INVENTORY_NAMES and not _row_is_failure(name, row, cols):
            continue
        if not _row_is_failure(name, row, cols):
            continue
        host = _host_from(row, host_default)
        title = str(row.get("title") or row.get("description") or name.replace("_", " "))
        key = (name, host)
        if key in seen:
            continue
        seen.add(key)
        out.append({"id": name, "title": title, "host": host, "result": "fail"})
    return out
