#!/usr/bin/env python3
"""Parse BloodHound CE / SharpHound / PingCastle-like JSON into identity findings.

Parse-only. Does not invoke a directory collector or a remote shell.
"""

from __future__ import annotations

import csv
from io import StringIO
from pathlib import Path
from typing import Any

import xml.etree.ElementTree as ET

from shared.cis_cat import is_cis_cat, iter_cis_failures
from shared.enum4linux import parse_enum4linux
from shared.io_util import iso_now, read_json, read_text, run_collector
from shared.schema import make_record, make_ref

SOURCE = "identity-ad"
LABELS = ["identity", "ad"]

_META_KIND = {
    "users": "User",
    "computers": "Computer",
    "groups": "Group",
    "domains": "Domain",
    "ous": "OU",
}

_EDGE_FINDINGS = {
    "HASESSION": ("high", "BloodHound HasSession", "Session edge can enable credential theft."),
    "ADMINTO": ("high", "BloodHound AdminTo", "Principal has local admin on the target."),
    "GENERICALL": ("critical", "BloodHound GenericAll", "Full control over the object."),
    "GENERICWRITE": ("high", "BloodHound GenericWrite", "Write access can plant a backdoor."),
    "DCSYNC": ("critical", "BloodHound DCSync", "Principal can replicate directory secrets."),
    "ALLOWEDTODELEGATE": ("high", "BloodHound constrained delegation", "Constrained delegation path."),
    "ADDMEMBER": ("medium", "BloodHound AddMember", "Can add members to a privileged group."),
}


def _looks_like_edge(obj: dict[str, Any]) -> bool:
    if isinstance(obj.get("properties") or obj.get("Properties"), dict):
        return False
    if obj.get("ObjectIdentifier") or obj.get("objectid") or obj.get("objectId"):
        return False
    kind = str(
        obj.get("kind")
        or obj.get("type")
        or obj.get("label")
        or obj.get("EdgeType")
        or obj.get("edgeType")
        or obj.get("relationship")
        or ""
    )
    has_ends = any(
        obj.get(k)
        for k in ("start", "end", "source", "target", "Source", "Target", "startNode", "endNode")
    )
    return has_ends and bool(kind)


def _meta_kind(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        return ""
    return _META_KIND.get(str(meta.get("type") or "").lower(), "")


def _nodes(payload: Any) -> list[dict[str, Any]]:
    raw: list[dict[str, Any]] = []
    if isinstance(payload, list):
        raw = [n for n in payload if isinstance(n, dict)]
    elif isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, dict) and isinstance(data.get("nodes"), list):
            raw = [n for n in data["nodes"] if isinstance(n, dict)]
        elif isinstance(data, list):
            raw = [n for n in data if isinstance(n, dict)]
        elif isinstance(payload.get("nodes"), list):
            raw = [n for n in payload["nodes"] if isinstance(n, dict)]
        elif isinstance(payload.get("PrivilegedAccounts"), list):
            raw = [n for n in payload["PrivilegedAccounts"] if isinstance(n, dict)]
    return [n for n in raw if not _looks_like_edge(n)]


def _aces_as_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """SharpHound ACE rows → mapped edges only. Empty Aces invent nothing."""
    out: list[dict[str, Any]] = []
    for node in nodes:
        aces = node.get("Aces") or node.get("aces") or []
        if not isinstance(aces, list):
            continue
        props = _props(node)
        end = str(
            props.get("name")
            or node.get("ObjectIdentifier")
            or node.get("objectid")
            or node.get("objectId")
            or ""
        )
        for ace in aces:
            if not isinstance(ace, dict):
                continue
            right = str(ace.get("RightName") or ace.get("rightName") or ace.get("kind") or "")
            start = str(
                ace.get("PrincipalName")
                or ace.get("PrincipalSID")
                or ace.get("principal")
                or ""
            )
            if right and start:
                out.append({"kind": right, "start": start, "end": end})
    return out


def _edges(payload: Any) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    if isinstance(payload, list):
        collected.extend(e for e in payload if isinstance(e, dict) and _looks_like_edge(e))
        return collected
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("edges"), list):
        collected.extend(e for e in data["edges"] if isinstance(e, dict))
    if isinstance(payload.get("edges"), list):
        collected.extend(e for e in payload["edges"] if isinstance(e, dict))
    if isinstance(payload.get("relationships"), list):
        collected.extend(e for e in payload["relationships"] if isinstance(e, dict))
    if isinstance(data, list):
        collected.extend(e for e in data if isinstance(e, dict) and _looks_like_edge(e))
    collected.extend(_aces_as_edges(_nodes(payload)))
    return collected


def _fold_props(raw: dict[str, Any]) -> dict[str, Any]:
    out = dict(raw)
    lower = {str(k).lower().replace("_", ""): v for k, v in raw.items()}
    aliases = {
        "name": ("name", "displayname"),
        "hasspn": ("hasspn",),
        "dontreqpreauth": ("dontreqpreauth",),
        "unconstraineddelegation": ("unconstraineddelegation",),
        "highvalue": ("highvalue",),
        "serviceprincipalnames": ("serviceprincipalnames",),
        "pimeligible": ("pimeligible",),
        "roles": ("roles",),
        "description": ("description",),
    }
    for canon, keys in aliases.items():
        if canon in out and out[canon] not in (None, ""):
            continue
        for key in keys:
            if key in lower and lower[key] not in (None, ""):
                out[canon] = lower[key]
                break
    return out


def _props(node: dict[str, Any]) -> dict[str, Any]:
    for key in ("properties", "Properties"):
        if isinstance(node.get(key), dict):
            return _fold_props(node[key])
    return _fold_props(node)


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


def _emit_cis_cat(rows: list[dict[str, str]], now: str) -> list[dict]:
    records: list[dict] = []
    seen_hosts: set[str] = set()
    for row in rows:
        host = row.get("host") or "cis-host"
        hid = row.get("id") or "cis"
        title = row.get("title") or hid
        if host not in seen_hosts:
            seen_hosts.add(host)
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"CIS-assessed host {host}",
                    category="host",
                    assets=[host],
                    labels=LABELS + ["cis-cat"],
                    collected_at=now,
                    extra={"asset_type": "PR"},
                )
            )
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"cis-{hid}-{host}"),
                name=f"CIS-CAT {hid}: {title}",
                description=title,
                severity="high",
                category="host-posture",
                assets=[host],
                labels=LABELS + ["cis-cat"],
                collected_at=now,
                extra={"id": hid, "name": title, "check_id": hid},
            )
        )
    return records


def _emit_enum4linux(hosts: list[dict[str, Any]], now: str) -> list[dict]:
    records: list[dict] = []
    for host in hosts:
        name = str(host.get("name") or "enum-host")
        addr = str(host.get("addr") or "")
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=f"Host {name} ({addr})".strip(),
                category="host",
                assets=[name],
                labels=LABELS + ["enum4linux"],
                collected_at=now,
                extra={"asset_type": "PR", "ip": addr},
            )
        )
        if host.get("null_session"):
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"null-session-{name}"),
                    name=f"SMB null session allowed on {name}",
                    description=f"{name} enum4linux-ng export shows an anonymous/null SMB session.",
                    severity="high",
                    category="identity-gap",
                    assets=[name],
                    labels=LABELS + ["enum4linux", "smb"],
                    collected_at=now,
                    extra={"service": "smb", "port": "445", "access": "null-session"},
                )
            )
        for group in host.get("groups") or []:
            label = str(group)
            low = label.lower()
            if "domain admins" in low:
                title = "Domain Admins group listed"
                desc = f"{name} export lists {label}."
            elif "backup operators" in low:
                title = "Backup Operators privileged group"
                desc = f"{name} export lists {label}."
            else:
                continue
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{title}-{name}"),
                    name=title,
                    description=desc,
                    severity="high",
                    category="identity-gap",
                    assets=[name],
                    labels=LABELS + ["enum4linux"],
                    collected_at=now,
                    extra={"group": label},
                )
            )
        for share in host.get("shares") or []:
            if not isinstance(share, dict):
                continue
            share_name = str(share.get("name") or "").strip()
            access = str(share.get("access") or "")
            if not share_name or "WRITE" not in access.upper():
                continue
            if share_name.upper() in {"IPC$", "PRINT$"}:
                continue
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{name}-share-{share_name}"),
                    name=f"Writable SMB share {share_name} on {name}",
                    description=f"{name} enum4linux-ng export shows {share_name} as {access}.",
                    severity="high",
                    category="exposure",
                    assets=[name],
                    labels=LABELS + ["enum4linux", "smb"],
                    collected_at=now,
                    extra={"port": "445", "service": "smb", "share": share_name, "access": access},
                )
            )
    return records


def parse_file(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    payload: Any = {}
    meta_kind = ""
    if path.suffix.lower() == ".csv" or ("," in text[:200] and "Severity" in text[:400]):
        return parse_hardeningkitty_csv(text, iso_now())
    enum = parse_enum4linux(path, text)
    if enum is not None:
        return _emit_enum4linux(enum, iso_now())
    json_payload: Any = None
    if not (path.suffix.lower() == ".xml" or text.lstrip().startswith("<")):
        try:
            json_payload = read_json(path)
        except Exception:
            json_payload = None
    if is_cis_cat(json_payload, name=path.name, text=text):
        return _emit_cis_cat(iter_cis_failures(json_payload, text=text), iso_now())
    if path.suffix.lower() == ".xml" or text.startswith("<"):
        nodes = _pingcastle_xml_nodes(path)
    else:
        payload = json_payload
        if payload is None:
            return []
        nodes = _nodes(payload)
        meta_kind = _meta_kind(payload)
    now = iso_now()
    records: list[dict] = []
    for node in nodes:
        props = _props(node)
        objectid = (
            node.get("objectid")
            or node.get("ObjectIdentifier")
            or node.get("objectId")
            or props.get("objectid")
        )
        name = str(props.get("name") or node.get("label") or objectid or "identity")
        kind = str(node.get("kind") or node.get("type") or meta_kind or "User")
        # Empty Members / empty Aces invent nothing — we do not walk group membership.
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
                extra={"asset_type": "SP", "kind": kind, "objectid": objectid},
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
        pim = props.get("pimEligible") if "pimEligible" in props else props.get("pimeligible")
        if any("Global Administrator" in str(r) for r in roles) and not pim:
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
        kind = str(
            edge.get("kind")
            or edge.get("type")
            or edge.get("label")
            or edge.get("EdgeType")
            or edge.get("edgeType")
            or edge.get("relationship")
            or ""
        )
        mapped = _EDGE_FINDINGS.get(kind.upper().replace(" ", ""))
        if not mapped:
            continue
        sev, title, desc = mapped
        start = str(
            edge.get("start")
            or edge.get("source")
            or edge.get("Source")
            or edge.get("startNode")
            or ""
        )
        end = str(
            edge.get("end")
            or edge.get("target")
            or edge.get("Target")
            or edge.get("endNode")
            or ""
        )
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
    run_collector(SOURCE, (".json", ".xml", ".csv", ".txt"), parse_file)


if __name__ == "__main__":
    main()
