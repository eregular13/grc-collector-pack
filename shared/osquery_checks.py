"""Parse osquery check/query exports. Failed/failing only. No osqueryi."""

from __future__ import annotations

from typing import Any


def _fail_status(value: Any) -> bool:
    return str(value or "").lower() in {"fail", "failed", "error"}


def iter_osquery_failures(payload: Any) -> list[dict[str, str]]:
    """Return failed osquery check rows. Inventory/pass/empty invent nothing."""
    rows: list[dict[str, Any]] = []
    if isinstance(payload, list):
        rows = [r for r in payload if isinstance(r, dict)]
    elif isinstance(payload, dict):
        if isinstance(payload.get("queries"), list):
            rows = [r for r in payload["queries"] if isinstance(r, dict)]
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
    host_default = ""
    if isinstance(payload, dict):
        host_default = str(payload.get("hostname") or payload.get("host") or "")
    out: list[dict[str, str]] = []
    for row in rows:
        if not _fail_status(row.get("status") or row.get("result") or row.get("outcome")):
            continue
        cols = row.get("columns") if isinstance(row.get("columns"), dict) else {}
        name = str(row.get("name") or row.get("query") or cols.get("name") or "osquery")
        # system_info inventory is not a check even if someone stamped fail
        if name.lower() in {"system_info", "os_version"} and not (
            cols.get("permitrootlogin") or cols.get("disk_encryption") or cols.get("firewall")
        ):
            continue
        host = str(
            row.get("hostname")
            or row.get("host")
            or cols.get("hostname")
            or host_default
            or "osquery-host"
        )
        title = str(row.get("title") or row.get("description") or name.replace("_", " "))
        out.append({"id": name, "title": title, "host": host, "result": "fail"})
    return out
