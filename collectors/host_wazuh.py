#!/usr/bin/env python3
"""Parse Wazuh / osquery / Fleet JSON into coverage gaps + incidents.

Parse-only. Does not run Wazuh, osquery, Fleet, or a live agent query.
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from shared.asset_ids import stamp_ids
from shared.cis_cat import is_cis_cat, iter_cis_failures
from shared.hardening_dedup import dedupe_hardening
from shared.hardening_map import extra_control_fields, lynis_control
from shared.io_util import UnrecognizedShape, iso_now, read_json, read_jsonl, read_text, run_collector
from shared.lab_stamp import SKIP_INPUT_NAMES, path_is_lab, stamp_lab_labels
from shared.mdm_inventory import parse_mdm_file, parse_mdm_inventory
from shared.openscap import is_openscap, iter_openscap_failures
from shared.osquery_checks import (
    is_osquery_pack_config,
    is_osquery_results_payload,
    iter_osquery_failures,
    iter_osquery_unmapped,
    load_osquery_payload,
    looks_osquery_text,
    osquery_hosts,
)
from shared.schema import canon_severity, make_record, make_ref

SOURCE = "host-wazuh"
LABELS = ["wazuh", "host"]
UNKNOWN_AGENT = "unknown-agent"
_SCA_PATH_SKIP = frozenset(
    {
        "wazuh",
        "host-wazuh",
        "host_wazuh",
        "in",
        "samples",
        "fixtures",
        "demo",
        "lab-drop",
        "keep-samples",
    }
)
_SCA_SEV_PATTERNS = (
    (re.compile(r"\bcritical\b", re.I), "critical"),
    (re.compile(r"\bhigh\b", re.I), "high"),
    (re.compile(r"\bmedium\b|\bmoderate\b", re.I), "medium"),
    (re.compile(r"\blow\b", re.I), "low"),
)


def _normalize_host(row: dict[str, Any]) -> dict[str, Any] | None:
    if row.get("action") or row.get("snapshot") or row.get("diffResults") or row.get("hostIdentifier"):
        name = row.get("hostIdentifier") or row.get("hostname")
    else:
        name = row.get("name") or row.get("hostname") or row.get("computer_name") or row.get("display_name")
    if not name and row.get("id") not in (None, ""):
        name = row.get("id")
    if not name:
        return None
    status = str(row.get("status") or "online").lower()
    if status in {"offline", "mia"}:
        status = "disconnected"
    mdm = row.get("mdm") if isinstance(row.get("mdm"), dict) else {}
    manager = str(row.get("manager") or row.get("manager_name") or row.get("node_name") or "default")
    agent_id = row.get("id")
    agent = ""
    if agent_id not in (None, ""):
        agent = f"wazuh:{manager}:{agent_id}"
    return {
        "name": name,
        "status": status,
        "ip": row.get("primary_ip") or row.get("ip") or "",
        "disk_encryption_enabled": row.get("disk_encryption_enabled"),
        "mdm": mdm,
        "platform": row.get("platform") or "",
        "agent_id": agent_id,
        "manager": manager,
        "agent": agent,
        "uuid": row.get("uuid") or row.get("board_serial") or "",
        "register_ip": row.get("registerIP") or row.get("register_ip") or "",
    }


def _host_rows(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict) and isinstance(raw.get("hosts"), list):
        rows = raw["hosts"]
    else:
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = _normalize_host(row)
        if host:
            out.append(host)
    return out


def _is_alert_row(row: dict[str, Any]) -> bool:
    if not isinstance(row, dict):
        return False
    if row.get("CheckID") or row.get("benchmark"):
        return False
    rule = row.get("rule")
    return isinstance(rule, dict) or "full_log" in row


def _alert_level(rule: dict[str, Any]) -> int:
    try:
        return int(rule.get("level") or 0)
    except (TypeError, ValueError):
        return 0


# Wazuh's own rule.level table (docs.wazuh.com / ruleset). Vendor severity
# words on the alert are ignored — a missing level is info, never High.
_COMPROMISE_RULE_IDS = frozenset(
    {
        "510",
        "511",
        "520",
        "521",
        "550",
        "551",
        "591",
        "592",
    }
)
_COMPROMISE_GROUPS = frozenset(
    {
        "attack_success",
        "malware",
        "rootkit",
        "trojan",
        "virus",
        "web_scan_success",
    }
)
_COMPROMISE_TITLE = re.compile(
    r"\b(rootkit|malware detected|attack successful|integrity checksum changed|"
    r"trojan(?:ed)?|shell spawned)\b",
    re.I,
)


def _alert_severity(alert: dict[str, Any], rule: dict[str, Any]) -> tuple[str, bool]:
    """Map Wazuh by rule.level only: 0-3 info, 4-7 low, 8-11 medium, 12-14 high, 15+ critical.

    Missing / unparsable level is info — never default High. Vendor `severity`
    on the alert is ignored so a fixture word cannot promote a level-5 flood.
    """
    del alert  # level table only; vendor severity is not a band.
    if rule.get("level") in (None, ""):
        return "info", False
    level = _alert_level(rule)
    if level <= 3:
        return "info", False
    if level <= 7:
        return "low", False
    if level <= 11:
        return "medium", False
    if level >= 15:
        return "critical", False
    return "high", False


def _alert_groups(rule: dict[str, Any]) -> list[str]:
    raw = rule.get("groups") or rule.get("gdpr") or []
    if isinstance(raw, str):
        return [part.strip() for part in raw.replace(",", " ").split() if part.strip()]
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if item]
    return []


def _is_compromise_rule(rule: dict[str, Any], title: str) -> bool:
    rid = str(rule.get("id") or "").strip()
    if rid in _COMPROMISE_RULE_IDS:
        return True
    groups = {g.lower() for g in _alert_groups(rule)}
    if groups & _COMPROMISE_GROUPS:
        return True
    return bool(_COMPROMISE_TITLE.search(str(title or "")))


def _alert_agent(alert: dict[str, Any]) -> str:
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    return str(agent.get("name") or agent.get("id") or "unknown")


def _alert_time(alert: dict[str, Any]) -> str:
    return str(alert.get("timestamp") or alert.get("time") or alert.get("@timestamp") or "")


def _aggregate_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One finding per (rule.id, agent) with count and first/last seen."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        rid = str(rule.get("id") or alert.get("id") or "alert")
        groups[(rid, _alert_agent(alert))].append(alert)
    out: list[dict[str, Any]] = []
    for (rid, agent), rows in groups.items():
        rule = rows[0].get("rule") if isinstance(rows[0].get("rule"), dict) else {}
        times = [t for t in (_alert_time(a) for a in rows) if t]
        times.sort()
        title = str(rule.get("description") or rows[0].get("id") or "wazuh alert")
        sev, unmapped = _alert_severity(rows[0], rule)
        out.append(
            {
                "rule_id": rid,
                "agent": agent,
                "title": title,
                "severity": sev,
                "severity_unmapped": unmapped,
                "level": rule.get("level"),
                "compromise": _is_compromise_rule(rule, title),
                "count": len(rows),
                "first_seen": times[0] if times else "",
                "last_seen": times[-1] if times else "",
            }
        )
    return out


def _extract_alerts(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        if payload and isinstance(payload[0], dict) and (
            payload[0].get("action")
            or payload[0].get("snapshot")
            or payload[0].get("diffResults")
            or payload[0].get("hostIdentifier")
        ):
            return []
        return [a for a in payload if isinstance(a, dict) and _is_alert_row(a)]
    if not isinstance(payload, dict):
        return []
    raw = payload.get("alerts")
    if raw is None:
        raw = payload.get("hits")
    if isinstance(raw, dict):
        inner = raw.get("hits") if isinstance(raw.get("hits"), list) else []
        out: list[dict[str, Any]] = []
        for hit in inner:
            if not isinstance(hit, dict):
                continue
            src = hit.get("_source") if isinstance(hit.get("_source"), dict) else hit
            if isinstance(src, dict) and _is_alert_row(src):
                out.append(src)
        return out
    if isinstance(raw, list):
        return [a for a in raw if isinstance(a, dict) and _is_alert_row(a)]
    return []


def _affected_items(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("affected_items"), list):
        return [a for a in data["affected_items"] if isinstance(a, dict)]
    return []


def _is_sca_item(row: dict[str, Any]) -> bool:
    result = str(row.get("result") or "").lower().replace(" ", "")
    if result not in {"passed", "failed", "notapplicable"}:
        return False
    return bool(row.get("policy_id") or row.get("title"))


def _is_sca_payload(payload: Any) -> bool:
    items = _affected_items(payload)
    return bool(items) and all(_is_sca_item(row) for row in items)


def _sca_failures(payload: Any) -> list[dict[str, Any]]:
    return [row for row in _affected_items(payload) if _is_sca_item(row) and str(row.get("result") or "").lower() == "failed"]


def _agent_from_obj(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("name") or obj.get("id") or obj.get("agent_name") or "").strip()
    if obj not in (None, ""):
        return str(obj).strip()
    return ""


def _sca_agent(payload: Any, path: Path, row: dict[str, Any] | None = None) -> tuple[str, str]:
    """Agent from the check, enclosing export, path, or operator hint. Never invent a host."""
    if isinstance(row, dict):
        named = _agent_from_obj(row.get("agent")) or str(
            row.get("agent_name") or row.get("agent_id") or ""
        ).strip()
        if named:
            return named, "row"
    data = payload.get("data") if isinstance(payload, dict) else {}
    if isinstance(data, dict):
        named = _agent_from_obj(data.get("agent")) or str(
            data.get("agent_name") or data.get("agent_id") or ""
        ).strip()
        if named:
            return named, "export"
    if isinstance(payload, dict):
        named = _agent_from_obj(payload.get("agent")) or str(
            payload.get("agent_name") or payload.get("agent_id") or ""
        ).strip()
        if named:
            return named, "export"
    hint = str(os.environ.get("WAZUH_SCA_AGENT") or os.environ.get("GRC_WAZUH_AGENT") or "").strip()
    if hint:
        return hint, "hint"
    parent = path.parent.name if path else ""
    if parent and parent.lower() not in _SCA_PATH_SKIP:
        return parent, "path"
    stem = path.stem if path else ""
    match = re.match(r"(?:sca[-_])(.+)|(.+)[-_]sca(?:[-_].+)?$", stem, re.I)
    if match:
        token = str(match.group(1) or match.group(2) or "").strip()
        if token and token.lower() not in {"checks", "check", "results", "export", "policy"}:
            return token, "path"
    return UNKNOWN_AGENT, "unknown"


def _sca_severity(row: dict[str, Any]) -> tuple[str, str]:
    raw = row.get("severity")
    if raw not in (None, ""):
        return str(raw).strip(), "field"
    parts: list[str] = []
    for key in ("rationale", "compliance", "description", "title", "reason", "remediation"):
        val = row.get(key)
        if isinstance(val, (list, dict)):
            parts.append(str(val))
        elif val not in (None, ""):
            parts.append(str(val))
    blob = " ".join(parts)
    for pat, sev in _SCA_SEV_PATTERNS:
        if pat.search(blob):
            source = "rationale" if row.get("rationale") and pat.search(str(row.get("rationale"))) else "compliance"
            return sev, source
    return "medium", "default"


def _agents(payload: Any) -> list[dict[str, Any]]:
    if _is_sca_payload(payload):
        return []
    if isinstance(payload, list):
        return [a for a in payload if isinstance(a, dict) and not _is_alert_row(a)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("affected_items"), list):
        return [a for a in data["affected_items"] if isinstance(a, dict) and not _is_sca_item(a)]
    if isinstance(payload.get("agents"), list):
        return [a for a in payload["agents"] if isinstance(a, dict)]
    osq = payload.get("osquery")
    if isinstance(osq, list):
        out = []
        for row in osq:
            if not isinstance(row, dict):
                continue
            cols = row.get("columns") if isinstance(row.get("columns"), dict) else row
            name = cols.get("hostname") or cols.get("name") or row.get("hostname")
            if name:
                out.append(
                    {
                        "name": name,
                        "status": row.get("status") or "active",
                        "ip": cols.get("local_hostname") or "",
                        "uuid": cols.get("uuid") or row.get("uuid") or "",
                    }
                )
        return out
    if isinstance(data, dict) and (data.get("hosts") is not None):
        rows = _host_rows(data.get("hosts"))
        if rows:
            return rows
    rows = _host_rows(payload.get("hosts"))
    if rows:
        return rows
    if isinstance(payload.get("host"), dict):
        host = _normalize_host(payload["host"])
        return [host] if host else []
    if payload.get("hostIdentifier") or payload.get("action") or payload.get("snapshot"):
        host = _normalize_host(payload)
        return [host] if host else []
    return []


def _failing_policies(payload: Any) -> list[dict[str, Any]]:
    """Fleet policies. Fail only. Pass/empty invent nothing."""
    raw: list[Any] = []
    if isinstance(payload, dict):
        if isinstance(payload.get("policies"), list):
            raw = list(payload["policies"])
        data = payload.get("data")
        if isinstance(data, dict) and isinstance(data.get("policies"), list):
            raw = list(data["policies"])
        host = payload.get("host")
        if isinstance(host, dict) and isinstance(host.get("policies"), list):
            raw.extend(p for p in host["policies"] if isinstance(p, dict))
    out: list[dict[str, Any]] = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or row.get("query_name") or row.get("id") or "")
        if not name:
            continue
        result = str(row.get("response") or row.get("result") or row.get("status") or "").lower()
        if result in {"pass", "passed", "ok", "compliant"}:
            continue
        try:
            failing = int(row.get("failing_host_count") or 0)
        except (TypeError, ValueError):
            failing = 0
        if result in {"fail", "failed", "error"} or failing > 0:
            out.append(row)
    return out


_LYNIS_BANG = re.compile(r"^!\s+(.+?)\s+\[([A-Z]+-\d+)\]\s*$")
_LYNIS_STAR = re.compile(r"^\*\s+(.+?)\s+\[([A-Z]+-\d+)\]\s*$")
_LYNIS_DAT = re.compile(r"^(warning|suggestion)\[\]=([^|]+)\|(.+)$", re.I)
_LYNIS_HOST = re.compile(r"(?im)^(?:hostname\s*[:=]\s*|hostname\s+)(\S+)")
_LYNIS_INDEX = re.compile(r"(?im)^hardening_index\s*[:=]\s*(\d+)")


def parse_lynis_report(text: str, now: str, path: Path | None = None) -> list[dict]:
    """Parse a Lynis report or report.dat.

    Warnings and suggestions become findings only when they have a clear
    control mapping. Hardening index is a score on the asset, not a finding.
    No invented hosts.
    """
    host = "lynis-host"
    mhost = _LYNIS_HOST.search(text)
    if mhost:
        host = mhost.group(1).strip().strip("\"'")
    index_match = _LYNIS_INDEX.search(text)
    hardening_index = int(index_match.group(1)) if index_match else None
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        raw = line.strip()
        bang = _LYNIS_BANG.match(raw)
        if bang:
            rows.append(("warning", bang.group(2), bang.group(1)))
            continue
        star = _LYNIS_STAR.match(raw)
        if star:
            rows.append(("suggestion", star.group(2), star.group(1)))
            continue
        dat = _LYNIS_DAT.match(raw)
        if dat:
            title = dat.group(3).split("|", 1)[0].strip()
            rows.append((dat.group(1).lower(), dat.group(2).strip(), title))
    mapped: list[tuple[str, str, str, str]] = []
    for kind, cid, title in rows:
        control = lynis_control(cid, title)
        if not control:
            continue
        mapped.append((kind, cid, title, control))
    if not mapped and hardening_index is None:
        return []
    if not mapped:
        # Score-only report: asset with index, no invented findings.
        extra = {"asset_type": "PR", "hardening_index": hardening_index, "tool": "lynis"}
        records = [
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{host}"),
                name=host,
                description=f"Lynis-audited host {host} (hardening_index={hardening_index})",
                category="host",
                assets=[host],
                labels=LABELS + ["lynis"],
                collected_at=now,
                extra=extra,
            )
        ]
        return stamp_lab_labels(records, lab=path_is_lab(path))
    extra_asset: dict = {"asset_type": "PR", "tool": "lynis"}
    if hardening_index is not None:
        extra_asset["hardening_index"] = hardening_index
    records = [
        make_record(
            kind="asset",
            source=SOURCE,
            ref_id=make_ref(SOURCE, f"asset-{host}"),
            name=host,
            description=f"Lynis-audited host {host}",
            category="host",
            assets=[host],
            labels=LABELS + ["lynis"],
            collected_at=now,
            extra=extra_asset,
        )
    ]
    seen: set[str] = set()
    for kind, cid, title, control in mapped:
        key = f"{cid}-{host}"
        if key in seen:
            continue
        seen.add(key)
        extra = extra_control_fields(control)
        extra.update({"check_id": cid, "id": cid, "lynis_kind": kind, "tool": "lynis"})
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"lynis-{key}"),
                name=f"Lynis {cid}: {title}",
                description=title,
                severity="high",
                category="host-posture",
                assets=[host],
                labels=LABELS + ["lynis"],
                collected_at=now,
                extra=extra,
            )
        )
    return stamp_lab_labels(records, lab=path_is_lab(path))


def _emit_openscap_rows(rows: list[dict], now: str, path: Path | None = None) -> list[dict]:
    records: list[dict] = []
    seen_hosts: set[str] = set()
    for row in rows:
        host = str(row.get("host") or "openscap-host")
        hid = str(row.get("id") or row.get("short_id") or "oscap")
        title = str(row.get("title") or hid)
        if host not in seen_hosts:
            seen_hosts.add(host)
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"OpenSCAP-audited host {host}",
                    category="host",
                    assets=[host],
                    labels=LABELS + ["openscap", "ssg"],
                    collected_at=now,
                    extra=stamp_ids(
                        {"asset_type": "PR", "tool": "openscap"},
                        **{
                            **(row.get("ids") if isinstance(row.get("ids"), dict) else {}),
                            "fqdn": host,
                            "hostname": host,
                        },
                    ),
                )
            )
        extra = dict(row.get("extra") or {})
        extra.setdefault("rule_id", hid)
        extra.setdefault("id", hid)
        extra.setdefault("check_id", row.get("short_id") or hid)
        extra.setdefault("ssg_references", row.get("references") or [])
        extra.setdefault("tool", "openscap")
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"oscap-{hid}-{host}"),
                name=f"OpenSCAP {row.get('short_id') or hid}: {title}",
                description=title,
                severity=str(row.get("severity") or "medium"),
                category="host-posture",
                assets=[host],
                labels=LABELS + ["openscap", "ssg"],
                collected_at=now,
                extra=extra,
            )
        )
    return stamp_lab_labels(records, lab=path_is_lab(path))


def _emit_check_rows(
    rows: list[dict[str, str]],
    now: str,
    *,
    prefix: str,
    labels: list[str],
    title_fmt: str,
) -> list[dict]:
    records: list[dict] = []
    seen_hosts: set[str] = set()
    for row in rows:
        host = row.get("host") or "host"
        hid = row.get("id") or prefix
        title = row.get("title") or hid
        if host not in seen_hosts:
            seen_hosts.add(host)
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"Host {host}",
                    category="host",
                    assets=[host],
                    labels=LABELS + labels,
                    collected_at=now,
                    extra={"asset_type": "PR"},
                )
            )
        extra = {"id": hid, "name": title, "check_id": hid}
        for key in ("severity_source", "agent_source"):
            if row.get(key):
                extra[key] = row[key]
        if host == UNKNOWN_AGENT:
            extra["agent_unknown"] = True
        raw_sev = row.get("severity") or "high"
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"{prefix}-{hid}-{host}"),
                name=title_fmt.format(title=title, id=hid),
                description=title,
                severity=raw_sev,
                category="host-posture",
                assets=[host],
                labels=LABELS + labels,
                collected_at=now,
                extra=extra,
            )
        )
    return records


_ASSESS = (
    "This is an endpoint-posture assessment finding from a dropped MDM export, "
    "not evidence of a breach or a live Intune/Jamf/osquery query."
)


def _emit_mdm_inventory(inv: dict, now: str) -> list[dict]:
    records: list[dict] = []
    provider = str(inv.get("provider") or "mdm")
    extra_labels = [provider, "mdm", "inventory"]
    seen: set[str] = set()

    def add_asset(name: str, ids: dict | None = None) -> None:
        key = name.lower()
        if key in seen:
            return
        seen.add(key)
        fields = dict(ids or {})
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=f"{provider} endpoint {name}",
                category="host",
                assets=[name],
                labels=LABELS + extra_labels,
                collected_at=now,
                extra=stamp_ids(
                    {"asset_type": "PR", "provider": provider},
                    hostname=name,
                    uuid=str(fields.get("uuid") or ""),
                    fqdn=name if "." in name else "",
                ),
            )
        )

    pct = inv.get("encryption_pct")
    measured = int(inv.get("measured_count") or 0)
    if pct is not None and measured and pct < 100:
        estate = f"{provider}-estate"
        add_asset(estate)
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"enc-compliance-{provider}"),
                name=f"{provider} encryption compliance {pct}%",
                description=(
                    f"Export shows {inv.get('encrypted_count')}/{measured} measured devices encrypted "
                    f"({pct}% compliance). {_ASSESS}"
                ),
                severity="high",
                category="host-posture",
                assets=[estate],
                labels=LABELS + extra_labels + ["disk-encryption"],
                collected_at=now,
                extra={"encryption_pct": pct, "measured_count": measured},
            )
        )
    for device in inv.get("devices") or []:
        if not isinstance(device, dict):
            continue
        name = str(device.get("name") or "")
        if not name:
            continue
        add_asset(name, {"uuid": device.get("uuid") or ""})
        if device.get("encrypted") is False:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"diskenc-{provider}-{name}"),
                    name=f"Disk encryption disabled on {name}",
                    description=(
                        f"{name} export lists disk encryption as not enabled. {_ASSESS}"
                    ),
                    severity="high",
                    category="host-posture",
                    assets=[name],
                    labels=LABELS + extra_labels + ["disk-encryption"],
                    collected_at=now,
                    extra={"disk_encryption_enabled": False, "provider": provider},
                )
            )
        elif device.get("encryption_collected") is False and provider == "jamf":
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"enc-gap-{provider}-{name}"),
                    name=f"encryption not collected on {name}",
                    description=(
                        f"{name} Jamf section=GENERAL export has no diskEncryption / "
                        f"FileVault state; encryption not collected. {_ASSESS}"
                    ),
                    severity="medium",
                    category="coverage-gap",
                    assets=[name],
                    labels=LABELS + extra_labels + ["disk-encryption", "coverage"],
                    collected_at=now,
                    extra={"encryption_collected": False, "provider": provider},
                )
            )
        if device.get("mdm_enrolled") is False:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"mdm-{provider}-{name}"),
                    name=f"MDM enrollment off on {name}",
                    description=(
                        f"{name} is not enrolled in MDM according to the dropped {provider} export. "
                        f"{_ASSESS}"
                    ),
                    severity="high",
                    category="host-posture",
                    assets=[name],
                    labels=LABELS + extra_labels,
                    collected_at=now,
                    extra={"mdm_enrollment": "unenrolled", "provider": provider},
                )
            )
        if device.get("edr_present") is False:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"edr-{provider}-{name}"),
                    name=f"Missing EDR on {name}",
                    description=(
                        f"{name} export lists endpoint detection / antivirus as missing. {_ASSESS}"
                    ),
                    severity="high",
                    category="coverage-gap",
                    assets=[name],
                    labels=LABELS + extra_labels + ["edr"],
                    collected_at=now,
                    extra={"edr_present": False, "provider": provider},
                )
            )
    return records


def _emit_osquery_records(payload: Any, now: str, path: Path | None = None) -> list[dict]:
    records = _emit_check_rows(
        iter_osquery_failures(payload),
        now,
        prefix="osquery",
        labels=["osquery"],
        title_fmt="osquery {id}: {title}",
    )
    seen_hosts = {r["name"] for r in records if r.get("kind") == "asset"}
    for host in osquery_hosts(payload):
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{host}"),
                name=host,
                description=f"Host {host}",
                category="host",
                assets=[host],
                labels=LABELS + ["osquery"],
                collected_at=now,
                extra=stamp_ids({"asset_type": "PR"}, hostname=host, fqdn=host if "." in host else ""),
            )
        )
    for row in iter_osquery_unmapped(payload):
        host = str(row.get("host") or "").strip()
        if not host:
            # Wazuh alert wraps can classify as unmapped with no host.
            # Only invent account-less "unknown" on real osquery results.
            if not is_osquery_results_payload(payload):
                continue
            host = "unknown"
        if host not in seen_hosts:
            seen_hosts.add(host)
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"Host {host}",
                    category="host",
                    assets=[host],
                    labels=LABELS + ["osquery"],
                    collected_at=now,
                    extra=stamp_ids({"asset_type": "PR"}, hostname=host, fqdn=host if "." in host else ""),
                )
            )
        hid = row.get("id") or "osquery"
        records.append(
            {
                "kind": "excluded",
                "source": SOURCE,
                "ref_id": make_ref(SOURCE, f"osquery-unmapped-{hid}-{host}"),
                "name": f"osquery unmapped: {hid}",
                "description": row.get("title") or hid,
                "severity": "info",
                "category": "excluded",
                "assets": [host],
                "labels": LABELS + ["osquery", "unmapped"],
                "collected_at": now,
                "extra": {
                    "exclude_reason": "unmapped",
                    "id": hid,
                    "check_id": hid,
                    "host": host,
                },
            }
        )
    return stamp_lab_labels(records, lab=path_is_lab(path)) if path is not None else records


def parse_file(path: Path) -> list[dict]:
    if path.name in SKIP_INPUT_NAMES:
        return []
    text = read_text(path)
    try:
        maybe_osq = json.loads(text.lstrip("\ufeff"))
    except Exception:
        maybe_osq = None
    if is_osquery_pack_config(maybe_osq):
        raise UnrecognizedShape(
            "unrecognized shape; osquery pack config is not results",
            file=path.name,
        )
    # osqueryd results logs are JSON lines — never Lynis, even when suffix is .log.
    if looks_osquery_text(text):
        osq_payload = load_osquery_payload(text)
        wazuh_wrap = isinstance(osq_payload, dict) and (
            osq_payload.get("osquery") or osq_payload.get("agents")
        )
        if osq_payload is not None and not wazuh_wrap and (
            path.suffix.lower() in {".log", ".txt", ".dat", ".jsonl"}
            or is_osquery_results_payload(osq_payload)
        ):
            return _emit_osquery_records(osq_payload, iso_now(), path=path)
    if path.suffix.lower() in {".txt", ".log", ".dat"}:
        return parse_lynis_report(text, iso_now(), path=path)
    now = iso_now()
    if path.suffix.lower() == ".csv":
        mdm = parse_mdm_file(path)
        return _emit_mdm_inventory(mdm, now) if mdm else []
    if path.suffix.lower() == ".xml" or text.lstrip().startswith("<"):
        if is_openscap(name=path.name, text=text):
            return _emit_openscap_rows(iter_openscap_failures(text), now, path=path)
        if is_cis_cat(name=path.name, text=text):
            return _emit_check_rows(
                iter_cis_failures(text=text),
                now,
                prefix="cis",
                labels=["cis-cat"],
                title_fmt="CIS-CAT {id}: {title}",
            )
        return []
    if path.suffix.lower() == ".jsonl":
        payload = read_jsonl(path)
        if not payload:
            return []
    else:
        try:
            payload = read_json(path)
        except Exception:
            payload = read_jsonl(path)
            if not payload:
                return []
    records: list[dict] = []
    if is_openscap(payload, name=path.name, text=text):
        return _emit_openscap_rows(iter_openscap_failures(text), now, path=path)
    if is_cis_cat(payload, name=path.name, text=text):
        records.extend(
            _emit_check_rows(
                iter_cis_failures(payload),
                now,
                prefix="cis",
                labels=["cis-cat"],
                title_fmt="CIS-CAT {id}: {title}",
            )
        )
        return records
    if _is_sca_payload(payload):
        sca_rows: list[dict[str, str]] = []
        for row in _sca_failures(payload):
            hid = str(row.get("id") or row.get("policy_id") or "sca")
            title = str(row.get("title") or hid)
            host, agent_source = _sca_agent(payload, path, row)
            sev, sev_source = _sca_severity(row)
            sca_rows.append(
                {
                    "id": hid,
                    "title": title,
                    "host": host,
                    "result": "fail",
                    "severity": sev,
                    "severity_source": sev_source,
                    "agent_source": agent_source,
                }
            )
        return _emit_check_rows(
            sca_rows,
            now,
            prefix="sca",
            labels=["sca"],
            title_fmt="Wazuh SCA {id}: {title}",
        )
    for agent in _agents(payload):
        name = str(agent.get("name") or agent.get("id") or "agent")
        status = str(agent.get("status") or "unknown").lower()
        ip = str(agent.get("ip") or "")
        agent_key = str(agent.get("agent") or "")
        if not agent_key and agent.get("id") not in (None, ""):
            mgr = str(agent.get("manager") or agent.get("manager_name") or "default")
            agent_key = f"wazuh:{mgr}:{agent.get('id')}"
        extra = stamp_ids(
            {"asset_type": "PR", "agent_status": status, "ip": ip},
            ip=ip,
            agent=agent_key,
            uuid=str(agent.get("uuid") or ""),
            hostname=name,
        )
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=f"Wazuh agent {name} status={status} ip={ip}",
                category="host",
                assets=[name],
                labels=LABELS,
                collected_at=now,
                extra=extra,
            )
        )
        if status in {"disconnected", "never_connected", "pending"}:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"coverage-{name}"),
                    name=f"Wazuh agent disconnected: {name}",
                    description=f"Endpoint {name} is {status}; coverage gap.",
                    severity="high",
                    category="coverage-gap",
                    assets=[name],
                    labels=LABELS + ["coverage"],
                    collected_at=now,
                    extra={"agent_status": status},
                )
            )
        enc = agent.get("disk_encryption_enabled")
        if enc is False or str(enc).lower() in {"false", "0", "no"}:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"diskenc-{name}"),
                    name=f"Disk encryption disabled on {name}",
                    description=f"{name} reports disk_encryption_enabled=false.",
                    severity="high",
                    category="host-posture",
                    assets=[name],
                    labels=LABELS + ["fleet", "disk-encryption"],
                    collected_at=now,
                    extra={"disk_encryption_enabled": False},
                )
            )
        mdm = agent.get("mdm") if isinstance(agent.get("mdm"), dict) else {}
        enroll = str(mdm.get("enrollment_status") or mdm.get("enrollment") or "").lower()
        if enroll in {"off", "unenrolled", "never", "not enrolled"}:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"mdm-{name}"),
                    name=f"MDM enrollment off on {name}",
                    description=f"{name} is not enrolled in MDM (enrollment_status={enroll}).",
                    severity="high",
                    category="host-posture",
                    assets=[name],
                    labels=LABELS + ["fleet", "mdm"],
                    collected_at=now,
                    extra={"mdm_enrollment": enroll},
                )
            )
    for policy in _failing_policies(payload):
        pname = str(policy.get("name") or policy.get("query_name") or policy.get("id") or "policy")
        host = "fleet"
        if isinstance(payload, dict) and isinstance(payload.get("host"), dict):
            host = str(
                payload["host"].get("hostname")
                or payload["host"].get("computer_name")
                or host
            )
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"fleet-policy-{pname}-{host}"),
                name=f"Fleet policy failed: {pname}",
                description=f"{pname} failed on {host}.",
                severity="high",
                category="host-posture",
                assets=[host],
                labels=LABELS + ["fleet", "policy"],
                collected_at=now,
                extra={"policy": pname, "name": pname},
            )
        )
    for alert in _aggregate_alerts(_extract_alerts(payload)):
        aname = str(alert["agent"])
        title = str(alert["title"])
        sev = canon_severity(alert["severity"])
        extra = {
            "rule_id": alert["rule_id"],
            "rule_level": alert["level"],
            "count": alert["count"],
            "first_seen": alert["first_seen"],
            "last_seen": alert["last_seen"],
            "telemetry": True,
        }
        if alert.get("compromise"):
            extra["compromise"] = True
        if alert.get("severity_unmapped"):
            extra["severity_unmapped"] = True
            extra.setdefault("severity_raw", str(alert["severity"]))
        records.append(
            make_record(
                kind="incident",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"inc-{alert['rule_id']}-{aname}"),
                name=title,
                description=title,
                severity=sev,
                category="incident",
                assets=[aname],
                labels=LABELS + ["alert"],
                collected_at=now,
                extra=extra,
            )
        )
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"alert-{alert['rule_id']}-{aname}"),
                name=title,
                description=title,
                severity=sev,
                category="incident",
                assets=[aname],
                labels=LABELS + ["alert"],
                collected_at=now,
                extra=extra,
            )
        )
    records.extend(_emit_osquery_records(payload, now, path=path))
    mdm = parse_mdm_inventory(payload, name=path.name, text=text)
    if mdm:
        records.extend(_emit_mdm_inventory(mdm, now))
    return records


def main() -> None:
    run_collector(
        SOURCE,
        (".json", ".jsonl", ".xml", ".txt", ".log", ".dat", ".csv"),
        parse_file,
        finalize=dedupe_hardening,
    )


if __name__ == "__main__":
    main()
