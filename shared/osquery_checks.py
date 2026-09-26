"""Parse osquery check/query exports. Failed/failing only. No osqueryi.

Routing is by content (JSON lines with name/hostIdentifier/columns, or
snapshot/diffResults), not by file extension.

A query name that happens to contain 'check' / 'compliance' / 'ssh' is
not a failure. Known it-compliance queries have an explicit pass/fail
predicate. Inventory-type rows are counted and never emitted. Unknown
queries are excluded as unmapped, not failed. Repeated scheduled runs
of the same query/host collapse to one row.
"""

from __future__ import annotations

import json
import re
from typing import Any

_PACK_QUERY = re.compile(r"^pack_[^_]+_(.+)$", re.I)
_PACK_TOKEN = re.compile(r"pack_[A-Za-z0-9][A-Za-z0-9_.-]*", re.I)
_PACK_TITLE = re.compile(
    r"(?:^|\b)osquery\s+pack_[^:]+:\s*pack\s+\S+\s+(\S+)\s*$",
    re.I,
)

# Official osquery packs/it-compliance.conf names (plus common inventory).
# These are counted and never emitted unless a fail predicate matches.
_INVENTORY_NAMES = frozenset(
    {
        "system_info",
        "os_version",
        "osquery_info",
        "processes",
        "process_snapshot",
        "listening_ports",
        "users",
        "logged_in_users",
        "uptime",
        "interface_addresses",
        "packs",
        "ad_config",
        "kernel_info",
        "alf_exceptions",
        "alf_services",
        "alf_explicit_auths",
        "mounts",
        "nfs_shares",
        "windows_shared_resources",
        "browser_plugins",
        "safari_extensions",
        "chrome_extensions",
        "firefox_addons",
        "homebrew_packages",
        "windows_programs",
        "windows_patches",
        "package_receipts",
        "usb_devices",
        "keychain_items",
        "keychain_acls",
        "deb_packages",
        "apt_sources",
        "portage_packages",
        "kernel_modules",
        "windows_drivers",
        "rpm_packages",
        "installed_applications",
        "launchd",
        "iptables",
        "crontab",
        "apps",
        "app_schemes",
        "cruft",
        "gatekeeper",
        "kextstat",
        "nvram",
        "sharing",
        "sharing_preferences",
        "startup_items",
        "xprotect_entries",
        "xprotect_reports",
        "suid_bins",
        "kernel_integrity",
    }
)

# Query-defined *check* result columns. Table columns named status (e.g.
# kernel_modules.status=Live) are ignored unless the value is a check word.
_STATUS_KEYS = ("status", "result", "outcome")
_BOOL_PASS_KEYS = ("passed", "compliant")
_FAIL_STATUS = frozenset({"fail", "failed", "error", "not ok", "notok"})
_PASS_STATUS = frozenset({"pass", "passed", "ok", "compliant", "success", "succeed"})
_FALSE = frozenset({"0", "false", "no", "off", "unencrypted", "disabled", "none"})

# Short query name → predicate kind.
_FAIL_PREDICATE = {
    "disk_encryption": "disk_encryption",
    "filevault": "disk_encryption",
    "bitlocker": "disk_encryption",
    "alf": "alf",
    "sip": "sip",
    "sip_config": "sip",
}

_OSQUERY_ACTIONS = frozenset({"added", "removed", "snapshot"})


def _fail_status(value: Any) -> bool:
    return str(value or "").lower().replace(" ", "") in {s.replace(" ", "") for s in _FAIL_STATUS}


def _pass_status(value: Any) -> bool:
    return str(value or "").lower().replace(" ", "") in {s.replace(" ", "") for s in _PASS_STATUS}


def _as_false(value: Any) -> bool:
    return str(value or "").strip().lower().replace(" ", "").replace("_", "") in {
        t.replace(" ", "").replace("_", "") for t in _FALSE
    }


def _query_key(name: str) -> str:
    low = str(name or "").strip().lower()
    match = _PACK_QUERY.match(low)
    if match:
        return match.group(1)
    return low


def query_key(name: str) -> str:
    """Short query id. ``pack_<pack>_<query>`` → ``<query>``."""
    return _query_key(name)


def normalize_osquery_pack_name(text: str) -> str:
    """Legacy pack spelling → current query id.

    ``pack_it-compliance_alf`` and
    ``osquery pack_it-compliance_alf: pack it-compliance alf`` both become
    ``alf``. Already-short names (``alf``) pass through.
    """
    raw = str(text or "").strip()
    if not raw:
        return ""
    for token in _PACK_TOKEN.findall(raw):
        q = _query_key(token)
        if q and q != token.lower():
            return q
    titled = _PACK_TITLE.search(raw)
    if titled:
        return titled.group(1).strip().lower()
    return _query_key(raw)


def _host_from(row: dict[str, Any], default: str) -> str:
    cols = row.get("columns") if isinstance(row.get("columns"), dict) else {}
    return str(
        row.get("hostIdentifier")
        or row.get("hostname")
        or row.get("host")
        or cols.get("hostname")
        or cols.get("hostIdentifier")
        or default
        or ""
    )


def _cols(row: dict[str, Any]) -> dict[str, Any]:
    return row.get("columns") if isinstance(row.get("columns"), dict) else {}


def _cell(row: dict[str, Any], cols: dict[str, Any], key: str) -> Any:
    if key in row:
        return row.get(key)
    return cols.get(key)


def _entry_is_pack_sql(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    query = obj.get("query")
    if not isinstance(query, str) or "select" not in query.lower():
        return False
    if obj.get("hostIdentifier") or isinstance(obj.get("columns"), dict):
        return False
    if isinstance(obj.get("snapshot"), list) or isinstance(obj.get("diffResults"), dict):
        return False
    return True


def is_osquery_pack_config(payload: Any) -> bool:
    """Official pack CONFIG (SQL + interval), not osqueryd results."""
    if not isinstance(payload, dict) or payload.get("hostIdentifier"):
        return False
    queries = payload.get("queries")
    if isinstance(queries, dict) and queries:
        vals = [v for v in queries.values() if isinstance(v, dict)]
        return bool(vals) and all(_entry_is_pack_sql(v) for v in vals)
    vals = [v for v in payload.values() if isinstance(v, dict)]
    return bool(vals) and all(_entry_is_pack_sql(v) for v in vals)


def looks_osquery_obj(obj: Any) -> bool:
    """True for an osquery result / snapshot / diff envelope."""
    if not isinstance(obj, dict):
        return False
    if is_osquery_pack_config(obj):
        return False
    if obj.get("hostIdentifier") and (obj.get("name") or obj.get("query") or obj.get("snapshot") or obj.get("diffResults")):
        return True
    if obj.get("snapshot") or obj.get("diffResults"):
        return True
    if isinstance(obj.get("columns"), dict) and (obj.get("name") or obj.get("action") in _OSQUERY_ACTIONS):
        return True
    if obj.get("hostIdentifier") and isinstance(obj.get("queries"), (list, dict)):
        return True
    return False


def looks_osquery_text(text: str) -> bool:
    """Detect osquery by content, not extension."""
    if not text or not str(text).strip():
        return False
    raw = str(text).lstrip("\ufeff")
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            break
        if looks_osquery_obj(obj):
            return True
        if isinstance(obj, list) and obj and looks_osquery_obj(obj[0]):
            return True
        return False
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if looks_osquery_obj(obj):
        return True
    if isinstance(obj, list) and obj and looks_osquery_obj(obj[0]):
        return True
    return False


def load_osquery_payload(text: str) -> Any:
    """JSONL results log or a JSON document. None if unreadable."""
    raw = str(text or "").lstrip("\ufeff")
    lines: list[dict[str, Any]] = []
    saw_non_json = False
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            saw_non_json = True
            break
        if isinstance(obj, dict):
            lines.append(obj)
        elif isinstance(obj, list):
            return [x for x in obj if isinstance(x, dict)]
    if lines and not saw_non_json:
        return lines
    if lines:
        return lines
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def is_osquery_results_payload(payload: Any) -> bool:
    """Pure osqueryd results / pack snapshot — not a Wazuh agent wrap."""
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        row = payload[0]
        return bool(
            row.get("hostIdentifier")
            or row.get("snapshot")
            or row.get("diffResults")
            or (row.get("name") and isinstance(row.get("columns"), dict))
        )
    if isinstance(payload, dict):
        if payload.get("osquery") or payload.get("agents") or (
            isinstance(payload.get("data"), dict) and payload["data"].get("affected_items")
        ):
            return False
        if is_osquery_pack_config(payload):
            return False
        return bool(
            payload.get("hostIdentifier")
            or payload.get("snapshot")
            or payload.get("diffResults")
            or (
                isinstance(payload.get("queries"), (list, dict))
                and not is_osquery_pack_config({"queries": payload.get("queries")})
            )
        )
    return False


def _expand_native(row: dict[str, Any]) -> list[dict[str, Any]]:
    """osquery 5.x event / snapshot / batch envelopes → row dicts."""
    name = str(row.get("name") or row.get("query") or "")
    host = row.get("hostIdentifier") or row.get("hostname")
    if isinstance(row.get("snapshot"), list):
        return [
            {**item, "name": name or item.get("name"), "hostIdentifier": host}
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
                                "name": name or item.get("name"),
                                "hostIdentifier": host,
                            }
                        )
        return out
    if row.get("action") and isinstance(row.get("columns"), dict):
        return [
            {
                **row["columns"],
                "name": name,
                "hostIdentifier": host,
                "columns": row["columns"],
            }
        ]
    return [row]


def _iter_source_rows(payload: Any) -> tuple[list[dict[str, Any]], str]:
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
                    if not q:
                        rows.append({"name": qname})
                    for item in q:
                        if isinstance(item, dict):
                            rows.append({**item, "name": item.get("name") or qname})
        osq = payload.get("osquery")
        if isinstance(osq, list):
            rows.extend(r for r in osq if isinstance(r, dict))
    return rows, host_default


def _check_column_verdict(row: dict[str, Any], cols: dict[str, Any]) -> bool | None:
    """True=fail, False=pass, None=no check column."""
    for key in _STATUS_KEYS:
        if key in row or key in cols:
            raw = _cell(row, cols, key)
            if _fail_status(raw):
                return True
            if _pass_status(raw):
                return False
            # Table column (Live, active, …) is not a check result.
    for key in _BOOL_PASS_KEYS:
        if key in row or key in cols:
            raw = _cell(row, cols, key)
            return _as_false(raw)
    return None


def _is_loop_device(row: dict[str, Any], cols: dict[str, Any]) -> bool:
    name = str(_cell(row, cols, "name") or "")
    device = str(_cell(row, cols, "device") or "")
    typ = str(_cell(row, cols, "type") or "")
    blob = f"{name} {device} {typ}".lower()
    return (
        name.lower().startswith("loop")
        or device.lower().startswith("/dev/loop")
        or "loop" in typ.lower()
        or "/dev/loop" in blob
        or re.search(r"\bloop\d*\b", blob) is not None
    )


def _disk_encryption_off(row: dict[str, Any], cols: dict[str, Any]) -> bool:
    if _is_loop_device(row, cols):
        return False
    if "encrypted" not in row and "encrypted" not in cols:
        return False
    return _as_false(_cell(row, cols, "encrypted"))


def _alf_disabled(row: dict[str, Any], cols: dict[str, Any]) -> bool:
    if "global_state" not in row and "global_state" not in cols:
        return False
    raw = _cell(row, cols, "global_state")
    return str(raw).strip() in {"0", "false", "off", "disabled"}


def _sip_fail(row: dict[str, Any], cols: dict[str, Any]) -> bool:
    merged: dict[str, Any] = {}
    merged.update(row)
    merged.update(cols)
    flag = str(merged.get("config_flag") or merged.get("name") or "").lower()
    enabled = merged.get("enabled")
    if flag in {"sip", "csr_config", "sip_status", ""} and enabled is not None:
        if flag in {"sip", "sip_status", ""} and _as_false(enabled):
            return True
    if flag.startswith("allow_") and enabled is not None and not _as_false(enabled):
        token = str(enabled).strip().lower()
        if token not in {"", "0", "false", "off", "no"}:
            return True
    for key, value in merged.items():
        k = str(key).lower()
        if k.startswith("allow_") and value is not None and not _as_false(value):
            token = str(value).strip().lower()
            if token not in {"", "0", "false", "off", "no"}:
                return True
    return False


def _predicate_fail(kind: str, row: dict[str, Any], cols: dict[str, Any]) -> bool:
    if kind == "disk_encryption":
        return _disk_encryption_off(row, cols)
    if kind == "alf":
        return _alf_disabled(row, cols)
    if kind == "sip":
        return _sip_fail(row, cols)
    return False


def classify_osquery_rows(payload: Any) -> list[dict[str, str]]:
    """Classify expanded rows: fail | inventory | unmapped. Collapses repeats."""
    rows, host_default = _iter_source_rows(payload)
    # disk_encryption is per-host: off only when no non-loop device is encrypted.
    enc_hosts: dict[str, dict[str, bool]] = {}
    classified: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    inventory_count = 0

    for row in rows:
        cols = _cols(row)
        name = str(row.get("name") or row.get("query") or cols.get("name") or "osquery")
        key = _query_key(name)
        host = _host_from(row, host_default)
        display = _query_key(name)
        titles = {
            "alf": "Application firewall is disabled",
            "disk_encryption": "Disk encryption is disabled",
            "filevault": "Disk encryption is disabled",
            "bitlocker": "Disk encryption is disabled",
            "sip": "SIP is disabled or relaxed",
            "sip_config": "SIP is disabled or relaxed",
        }
        title = titles.get(key) or str(
            row.get("title") or row.get("description") or display.replace("_", " ")
        )
        if title.lower().startswith("pack "):
            title = display.replace("_", " ")
        verdict = _check_column_verdict(row, cols)
        pred = _FAIL_PREDICATE.get(key)

        if pred == "disk_encryption":
            state = enc_hosts.setdefault(host, {"seen": False, "any_on": False, "check_fail": False})
            if verdict is True:
                state["check_fail"] = True
            if _is_loop_device(row, cols):
                continue
            if "encrypted" in row or "encrypted" in cols:
                state["seen"] = True
                if not _as_false(_cell(row, cols, "encrypted")):
                    state["any_on"] = True
            continue

        if verdict is False:
            inventory_count += 1
            continue
        if verdict is True:
            slot = ("fail", name, host)
            if slot in seen:
                continue
            seen.add(slot)
            classified.append({"id": display, "title": title, "host": host, "result": "fail"})
            continue

        if pred:
            if _predicate_fail(pred, row, cols):
                slot = ("fail", display, host)
                if slot in seen:
                    continue
                seen.add(slot)
                classified.append({"id": display, "title": title, "host": host, "result": "fail"})
            else:
                inventory_count += 1
            continue

        if key in _INVENTORY_NAMES or name.lower() in _INVENTORY_NAMES:
            inventory_count += 1
            continue

        slot = ("unmapped", name, host)
        if slot in seen:
            continue
        seen.add(slot)
        classified.append(
            {
                "id": display,
                "title": title,
                "host": host,
                "result": "unmapped",
            }
        )

    for host, state in enc_hosts.items():
        failed = bool(state.get("check_fail") or (state.get("seen") and not state.get("any_on")))
        if not failed:
            inventory_count += 1
            continue
        slot = ("fail", "disk_encryption", host)
        if slot in seen:
            continue
        seen.add(slot)
        classified.append(
            {
                "id": "disk_encryption",
                "title": "Disk encryption is disabled",
                "host": host,
                "result": "fail",
            }
        )

    # inventory_count is the "counted but never emitted" tally.
    if classified:
        classified[0]["_inventory_count"] = str(inventory_count)
    return classified


def osquery_hosts(payload: Any) -> list[str]:
    """Host identifiers seen in the payload (inventory counted, always emitted as assets)."""
    rows, host_default = _iter_source_rows(payload)
    out: list[str] = []
    seen: set[str] = set()
    if host_default:
        out.append(host_default)
        seen.add(host_default)
    for row in rows:
        host = _host_from(row, host_default)
        if host and host != "osquery-host" and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def iter_osquery_failures(payload: Any) -> list[dict[str, str]]:
    """Return failed osquery check rows. Inventory/pass/empty invent nothing."""
    return [row for row in classify_osquery_rows(payload) if row.get("result") == "fail"]


def iter_osquery_unmapped(payload: Any) -> list[dict[str, str]]:
    """Unknown queries — excluded as unmapped, not failed."""
    return [row for row in classify_osquery_rows(payload) if row.get("result") == "unmapped"]
