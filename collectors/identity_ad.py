#!/usr/bin/env python3
"""Parse BloodHound / PingCastle-like JSON into privileged identity findings."""

from __future__ import annotations

import csv
from io import StringIO
from pathlib import Path
from typing import Any

import xml.etree.ElementTree as ET

from shared.io_util import iso_now, read_json, read_text, run_collector
from shared.schema import make_record, make_ref

SOURCE = "identity-ad"
LABELS = ["identity", "ad"]


def _nodes(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [n for n in payload if isinstance(n, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("nodes"), list):
        return [n for n in data["nodes"] if isinstance(n, dict)]
    if isinstance(payload.get("nodes"), list):
        return [n for n in payload["nodes"] if isinstance(n, dict)]
    # PingCastle-like
    if isinstance(payload.get("PrivilegedAccounts"), list):
        return [n for n in payload["PrivilegedAccounts"] if isinstance(n, dict)]
    return []


def _edges(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("edges"), list):
        return [e for e in data["edges"] if isinstance(e, dict)]
    if isinstance(payload.get("edges"), list):
        return [e for e in payload["edges"] if isinstance(e, dict)]
    return []


_EDGE_FINDINGS = {
    "HASESSION": ("high", "BloodHound HasSession", "Session edge can enable credential theft."),
    "ADMINTO": ("high", "BloodHound AdminTo", "Principal has local admin on the target."),
    "GENERICALL": ("critical", "BloodHound GenericAll", "Full control over the object."),
    "GENERICWRITE": ("high", "BloodHound GenericWrite", "Write access can plant a backdoor."),
    "DCSYNC": ("critical", "BloodHound DCSync", "Principal can replicate directory secrets."),
    "ALLOWEDTODELEGATE": ("high", "BloodHound constrained delegation", "Constrained delegation path."),
    "ADDMEMBER": ("medium", "BloodHound AddMember", "Can add members to a privileged group."),
}


def _pingcastle_xml_nodes(path: Path) -> list[dict[str, Any]]:
    raw = read_text(path)
    root = ET.fromstring(raw)
    nodes: list[dict[str, Any]] = []
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in {"HealthcheckGroupData", "Group", "PrivilegedGroup"}:
            name = (
                el.findtext("GroupName")
                or el.findtext("Name")
                or el.attrib.get("name")
                or ""
            )
            if name:
                nodes.append(
                    {
                        "kind": "Group",
                        "label": name,
                        "properties": {
                            "name": name,
                            "highvalue": "BACKUP" in name.upper() or "ADMIN" in name.upper(),
                            "description": el.findtext("Description") or f"PingCastle group {name}",
                        },
                    }
                )
        if tag in {"Account", "PrivilegedAccount", "User"}:
            name = el.findtext("Name") or el.findtext("SamAccountName") or el.attrib.get("name") or ""
            if name:
                props = {
                    "name": name,
                    "hasspn": (el.findtext("HasSPN") or "").lower() in {"true", "1"},
                    "dontreqpreauth": (el.findtext("DontReqPreAuth") or "").lower() in {"true", "1"},
                    "description": el.findtext("Description") or "",
                }
                spn = el.findtext("SPN") or el.findtext("ServicePrincipalName")
                if spn:
                    props["serviceprincipalnames"] = [spn]
                    props["hasspn"] = True
                nodes.append({"kind": "User", "label": name, "properties": props})
    return nodes


def parse_hardeningkitty_csv(text: str, now: str) -> list[dict]:
    """Parse HardeningKitty Audit CSV. Failed/warning rows only. Actual values redacted."""
    records: list[dict] = []
    sample = text[:4000]
    dialect = csv.excel
    if "," in sample or ";" in sample or "\t" in sample:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
    reader = csv.DictReader(StringIO(text), dialect=dialect)
    host = "windows-host"
    seen_hosts: set[str] = set()
    for row in reader:
        if not row:
            continue
        lower = {str(k).strip().lower().replace(" ", ""): (v or "").strip() for k, v in row.items() if k}
        host = (
            lower.get("computername")
            or lower.get("hostname")
            or lower.get("computer")
            or lower.get("system")
            or host
        )
        result = (lower.get("result") or lower.get("status") or lower.get("outcome") or "").lower()
        if result in {"passed", "pass", "ok", "true", "compliant", "notapplicable", "n/a", "na"}:
            continue
        if result not in {"failed", "fail", "warning", "warn", "noncompliant", "error", ""}:
            continue
        hid = lower.get("id") or lower.get("number") or lower.get("name") or "hk"
        name = lower.get("name") or lower.get("title") or hid
        sev = lower.get("severity") or ("medium" if result in {"warning", "warn"} else "high")
        recommended = (
            lower.get("recommended")
            or lower.get("recommendedvalue")
            or lower.get("expected")
            or ""
        )
        if host not in seen_hosts:
            seen_hosts.add(host)
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"Windows host {host}",
                    category="host",
                    assets=[host],
                    labels=LABELS + ["windows", "hardeningkitty"],
                    collected_at=now,
                    extra={"asset_type": "PR"},
                )
            )
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"hk-{hid}-{host}"),
                name=f"HardeningKitty {name}",
                description=f"{name} result={result or 'failed'} recommended={recommended or '[n/a]'} actual=[REDACTED]",
                severity=sev,
                category="identity-gap",
                assets=[host],
                labels=LABELS + ["hardeningkitty"],
                collected_at=now,
                extra={"id": hid, "result": result or "failed", "name": name},
            )
        )
    return records


def parse_file(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    payload: Any = {}
    if path.suffix.lower() == ".csv" or ("," in text[:200] and "Severity" in text[:400]):
        return parse_hardeningkitty_csv(text, iso_now())
    if path.suffix.lower() == ".xml" or text.startswith("<"):
        nodes = _pingcastle_xml_nodes(path)
    else:
        payload = read_json(path)
        nodes = _nodes(payload)
    now = iso_now()
    records: list[dict] = []
    for node in nodes:
        props = node.get("properties") if isinstance(node.get("properties"), dict) else node
        name = str(props.get("name") or node.get("label") or node.get("objectid") or "identity")
        kind = str(node.get("kind") or node.get("type") or "User")
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=str(props.get("description") or f"{kind} {name}"),
                category="identity",
                assets=[name],
                labels=LABELS + [kind.lower()],
                collected_at=now,
                extra={"asset_type": "SP", "kind": kind, "objectid": node.get("objectid")},
            )
        )
        findings: list[tuple[str, str, str]] = []
        uname = name.upper()
        if "BACKUP OPERATORS" in uname or (props.get("highvalue") and "BACKUP" in uname):
            findings.append(("high", "Backup Operators privileged group", "Members can dump SAM / seize privileged files."))
        if props.get("hasspn") or props.get("serviceprincipalnames"):
            findings.append(("high", "Roastable SPN", f"{name} has an SPN and is kerberoastable."))
        if props.get("dontreqpreauth"):
            findings.append(("high", "AS-REP roastable account", f"{name} does not require Kerberos preauth."))
        roles = props.get("roles") or []
        if isinstance(roles, str):
            roles = [roles]
        if any("Global Administrator" in str(r) for r in roles) and not props.get("pimEligible"):
            findings.append(("critical", "Entra GA without PIM", f"{name} is Global Administrator without PIM eligibility."))
        if props.get("unconstraineddelegation"):
            findings.append(("high", "Unconstrained delegation", f"{name} has unconstrained Kerberos delegation."))
        if props.get("highvalue") and not findings:
            findings.append(("medium", "High-value identity", f"{name} is marked high-value."))
        for sev, title, desc in findings:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{title}-{name}"),
                    name=title,
                    description=desc,
                    severity=sev,
                    category="identity-gap",
                    assets=[name],
                    labels=LABELS,
                    collected_at=now,
                    extra={"kind": kind},
                )
            )
    for edge in _edges(payload):
        kind = str(edge.get("kind") or edge.get("type") or edge.get("label") or "")
        mapped = _EDGE_FINDINGS.get(kind.upper().replace(" ", ""))
        if not mapped:
            continue
        sev, title, desc = mapped
        start = str(edge.get("start") or edge.get("source") or "")
        end = str(edge.get("end") or edge.get("target") or "")
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"{kind}-{start}-{end}"),
                name=title,
                description=f"{desc} {start} -> {end}".strip(),
                severity=sev,
                category="identity-gap",
                assets=[x for x in (start, end) if x],
                labels=LABELS + ["bloodhound", "edge"],
                collected_at=now,
                extra={"edge": kind, "start": start, "end": end},
            )
        )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".xml", ".csv"), parse_file)


if __name__ == "__main__":
    main()
