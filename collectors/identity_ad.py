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

from shared.asset_ids import stamp_ids
from shared.cis_cat import is_cis_cat, iter_cis_failures
from shared.enum4linux import parse_enum4linux
from shared.hardening_dedup import dedupe_hardening
from shared.hardening_map import extra_control_fields, hk_control
from shared.hardeningkitty_csv import hk_row_failed, resolve_hk_host
from shared.io_util import iso_now, read_json, read_text, run_collector
from shared.lab_stamp import SKIP_INPUT_NAMES, path_is_lab, stamp_lab_labels
from shared.schema import canon_severity, make_record, make_ref

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
    "HASSESSION": ("high", "BloodHound HasSession", "Session edge can enable credential theft."),
    "HASESSION": ("high", "BloodHound HasSession", "Session edge can enable credential theft."),
    "ADMINTO": ("high", "BloodHound AdminTo", "Principal has local admin on the target."),
    "GENERICALL": ("critical", "BloodHound GenericAll", "Full control over the object."),
    "GENERICWRITE": ("high", "BloodHound GenericWrite", "Write access can plant a backdoor."),
    "DCSYNC": ("critical", "BloodHound DCSync", "Principal can replicate directory secrets."),
    "ALLOWEDTODELEGATE": ("high", "BloodHound constrained delegation", "Constrained delegation path."),
    "ADDMEMBER": ("medium", "BloodHound AddMember", "Can add members to a privileged group."),
    "WRITEDACL": ("high", "BloodHound WriteDacl", "WriteDacl can plant a backdoor ACE."),
    "WRITEOWNER": ("high", "BloodHound WriteOwner", "WriteOwner can take the object."),
    "OWNS": ("high", "BloodHound Owns", "Owner can rewrite the DACL."),
    "ADDKEYCREDENTIALLINK": ("high", "BloodHound AddKeyCredentialLink", "Shadow-credentials / key-cred write."),
}

# Built-in admin / DC principals. Default ACLs from these are not exposures.
_DEFAULT_ADMIN_RIDS = frozenset({"500", "498", "512", "516", "518", "519", "544", "548"})
_WELL_KNOWN_ADMIN = (
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-9",
)


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


def _sid_rid(sid: str) -> str:
    parts = str(sid or "").strip().split("-")
    return parts[-1] if parts else ""


def _is_default_admin_principal(sid: str) -> bool:
    text = str(sid or "").strip()
    if not text:
        return False
    upper = text.upper()
    if any(token in upper for token in _WELL_KNOWN_ADMIN):
        return True
    return _sid_rid(text) in _DEFAULT_ADMIN_RIDS


def _aces_as_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """SharpHound ACE rows → mapped edges only. Empty Aces invent nothing."""
    out: list[dict[str, Any]] = []
    dcsync_rights: dict[tuple[str, str], set[str]] = {}
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
            if ace.get("IsInherited") is True:
                continue
            right = str(ace.get("RightName") or ace.get("rightName") or ace.get("kind") or "")
            sid = str(ace.get("PrincipalSID") or ace.get("principalSid") or "")
            start = str(
                ace.get("PrincipalName")
                or sid
                or ace.get("principal")
                or ""
            )
            if not right or not start:
                continue
            if _is_default_admin_principal(sid or start):
                continue
            folded = right.upper().replace(" ", "")
            if folded in {"GETCHANGES", "GETCHANGESALL"}:
                dcsync_rights.setdefault((start, end), set()).add(folded)
                continue
            out.append({"kind": right, "start": start, "end": end})
    for (start, end), rights in dcsync_rights.items():
        if "GETCHANGES" in rights and "GETCHANGESALL" in rights:
            out.append({"kind": "DCSync", "start": start, "end": end})
    return out


def _truthy_priv_flag(value: Any) -> bool:
    return value in (True, 1, "1", "true", "True")


def _privileged_from_nodes(nodes: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for node in nodes:
        props = _props(node)
        oid = str(
            node.get("ObjectIdentifier")
            or node.get("objectid")
            or node.get("objectId")
            or ""
        )
        name = str(props.get("name") or oid)
        if _truthy_priv_flag(props.get("admincount")) or _truthy_priv_flag(props.get("highvalue")):
            if name:
                out.add(name)
            if oid:
                out.add(oid)
        if oid and _is_default_admin_principal(oid):
            if name:
                out.add(name)
            out.add(oid)
    return out


def _session_and_admin_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """LocalGroups ADMINISTRATORS → AdminTo; Sessions → one HasSession per privileged principal."""
    names: dict[str, str] = {}
    for node in nodes:
        props = _props(node)
        oid = str(
            node.get("ObjectIdentifier")
            or node.get("objectid")
            or node.get("objectId")
            or ""
        )
        name = str(props.get("name") or oid)
        if oid:
            names[oid] = name
    privileged = _privileged_from_nodes(nodes)
    out: list[dict[str, Any]] = []
    sessions: dict[str, list[str]] = {}
    for node in nodes:
        props = _props(node)
        computer = str(
            props.get("name")
            or node.get("ObjectIdentifier")
            or node.get("objectid")
            or ""
        )
        groups = node.get("LocalGroups") or node.get("local_groups") or []
        if isinstance(groups, list):
            for group in groups:
                if not isinstance(group, dict):
                    continue
                oid = str(group.get("ObjectIdentifier") or group.get("Name") or "")
                gname = str(group.get("Name") or "")
                if not (oid.upper().endswith("-544") or "ADMINISTRATOR" in gname.upper()):
                    continue
                results = group.get("Results") if isinstance(group.get("Results"), list) else []
                for member in results:
                    if not isinstance(member, dict):
                        continue
                    msid = str(member.get("ObjectIdentifier") or member.get("UserSID") or "")
                    if not msid or _is_default_admin_principal(msid):
                        continue
                    start = names.get(msid, msid)
                    privileged.add(start)
                    if msid:
                        privileged.add(msid)
                    out.append({"kind": "AdminTo", "start": start, "end": computer})
        for key in ("Sessions", "PrivilegedSessions"):
            bag = node.get(key) or node.get(key.lower()) or {}
            results = bag.get("Results") if isinstance(bag, dict) else bag
            if not isinstance(results, list):
                continue
            for row in results:
                if not isinstance(row, dict):
                    continue
                user = str(row.get("UserSID") or row.get("user") or "")
                if not user:
                    continue
                start = names.get(user, user)
                end = names.get(str(row.get("ComputerSID") or ""), computer) or computer
                if not (
                    start in privileged
                    or user in privileged
                    or _is_default_admin_principal(user)
                    or _is_default_admin_principal(start)
                ):
                    continue
                hosts = sessions.setdefault(start, [])
                if end and end not in hosts:
                    hosts.append(end)
    for start, hosts in sessions.items():
        out.append(
            {
                "kind": "HasSession",
                "start": start,
                "end": hosts[0] if hosts else start,
                "session_count": len(hosts),
                "hosts": hosts,
            }
        )
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
    collected.extend(_session_and_admin_edges(_nodes(payload)))
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
        "admincount": ("admincount",),
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


def _xml_local(tag: str) -> str:
    return (tag or "").split("}")[-1]


def _child_text(el: ET.Element, *names: str) -> str:
    want = {name.lower() for name in names}
    for child in list(el):
        if _xml_local(child.tag).lower() in want:
            return (child.text or "").strip()
    return ""


# PingCastle privileged-group membership RiskIds (8). 0 members → no finding.
_GROUP_MEMBERSHIP_RULES: dict[str, tuple[str, ...]] = {
    "p-backupoperators": ("backup operators",),
    "p-accountoperators": ("account operators",),
    "p-printoperators": ("print operators",),
    "p-serveroperators": ("server operators",),
    "p-schemaadmins": ("schema admins",),
    "p-enterpriseadmins": ("enterprise admins",),
    "p-domainadmins": ("domain admins",),
    "p-administrators": ("administrators",),
}


def _norm_risk(risk_id: str) -> str:
    return str(risk_id or "").strip().lower().replace("_", "").replace(" ", "")


def _group_rule_names(risk_id: str) -> tuple[str, ...]:
    return _GROUP_MEMBERSHIP_RULES.get(_norm_risk(risk_id), ())


def _member_count(el: ET.Element) -> int | None:
    """NumberOfMember / Members if the file states a count. None = not stated."""
    stated = False
    n = 0
    for name in ("NumberOfMember", "NumberOfMemberEnabled", "NumberOfMembers"):
        raw = _child_text(el, name)
        if raw != "":
            stated = True
            try:
                n = max(n, int(float(raw)))
            except (TypeError, ValueError):
                pass
    for child in list(el):
        tag = _xml_local(child.tag).lower()
        if tag == "members":
            stated = True
            kids = [c for c in list(child) if _xml_local(c.tag).split("}")[-1]]
            n = max(n, len(kids))
    return n if stated else None


def _points_severity(raw: str) -> str:
    try:
        points = int(float(str(raw or "0").strip() or "0"))
    except (TypeError, ValueError):
        points = 0
    if points <= 0:
        return "info"
    if points >= 50:
        return "critical"
    if points >= 30:
        return "high"
    if points >= 10:
        return "medium"
    return "low"


def _parse_pingcastle_xml(path: Path) -> dict[str, Any]:
    """Read PingCastle HealthcheckData: RiskRules + case-insensitive groups/accounts."""
    raw = read_text(path)
    root = ET.fromstring(raw)
    parent = {child: node for node in root.iter() for child in list(node)}
    domain = _child_text(root, "DomainFQDN", "ForestFQDN", "NetBIOSName")
    nodes: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    if domain:
        nodes.append(
            {
                "kind": "Domain",
                "label": domain,
                "properties": {
                    "name": domain,
                    "description": f"PingCastle domain {domain}",
                },
            }
        )
    for el in root.iter():
        tag = _xml_local(el.tag).lower()
        if tag == "healthcheckriskrule":
            risk_id = _child_text(el, "RiskId") or "pingcastle"
            rationale = _child_text(el, "Rationale") or risk_id
            points = _child_text(el, "Points") or "0"
            rules.append(
                {
                    "risk_id": risk_id,
                    "rationale": rationale,
                    "points": points,
                    "severity": _points_severity(points),
                    "category": _child_text(el, "Category") or "",
                    "model": _child_text(el, "Model") or "",
                    "domain": domain or "unknown",
                }
            )
            continue
        if tag in {"healthcheckgroupdata", "group", "privilegedgroup"}:
            name = (
                _child_text(el, "GroupName", "Name")
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
                            "description": _child_text(el, "Description") or f"PingCastle group {name}",
                            "member_count": _member_count(el),
                        },
                    }
                )
            continue
        if tag in {"account", "privilegedaccount", "user", "healthcheckaccountdetaildata"}:
            name = (
                _child_text(el, "Name", "SamAccountName", "SAMAccountName")
                or el.attrib.get("name")
                or ""
            )
            if not name:
                continue
            ancestor_tags = set()
            cur: ET.Element | None = el
            for _ in range(6):
                cur = parent.get(cur) if cur is not None else None
                if cur is None:
                    break
                ancestor_tags.add(_xml_local(cur.tag).lower())
            preauth_parent = "listnopreauth" in ancestor_tags
            dont = _child_text(el, "DontReqPreAuth").lower() in {"true", "1"} or preauth_parent
            props = {
                "name": name,
                "hasspn": _child_text(el, "HasSPN").lower() in {"true", "1"},
                "dontreqpreauth": dont,
                "description": _child_text(el, "Description") or "",
            }
            spn = _child_text(el, "SPN", "ServicePrincipalName")
            if spn:
                props["serviceprincipalnames"] = [spn]
                props["hasspn"] = True
            nodes.append({"kind": "User", "label": name, "properties": props})
    return {"nodes": nodes, "rules": rules, "domain": domain}


def _pingcastle_xml_nodes(path: Path) -> list[dict[str, Any]]:
    return list(_parse_pingcastle_xml(path).get("nodes") or [])


def parse_hardeningkitty_csv(text: str, now: str, path: Path | None = None) -> list[dict]:
    """Parse HardeningKitty Audit CSV. Failed rows only. Actual values redacted.

    Official HK report (HardeningKitty.psm1 @ da0976073caa): Result is the
    measured value; TestResult is Passed/Failed. TestResult is
    authoritative — TestResult=Passed never becomes a finding.
    Legacy/demo CSVs that put Passed|Failed in Result still parse.
    Host comes from filename / sidecar / env / optional column — never
    the invented default windows-host. Never CIS Benchmark / CIS-CAT.
    """
    records: list[dict] = []
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return stamp_lab_labels(records, lab=path_is_lab(path))
    sample = "\n".join(lines[:40])
    dialect = csv.excel
    if "," in sample or ";" in sample or "\t" in sample:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
    reader = csv.DictReader(StringIO("\n".join(lines)), dialect=dialect)
    seen_hosts: set[str] = set()
    for row in reader:
        if not row:
            continue
        lower = {str(k).strip().lower().replace(" ", ""): (v or "").strip() for k, v in row.items() if k}
        host, host_source, unresolved = resolve_hk_host(path, lower)
        outcome, failed = hk_row_failed(lower)
        if not failed:
            continue
        hid = lower.get("id") or lower.get("number") or lower.get("name") or "hk"
        name = lower.get("name") or lower.get("title") or hid
        category = lower.get("category") or ""
        sev = (
            lower.get("severityfinding")
            or lower.get("severity")
            or ("medium" if outcome in {"warning", "warn"} else "high")
        )
        if str(sev).lower() == "passed":
            sev = "high"
        recommended = (
            lower.get("recommended")
            or lower.get("recommendedvalue")
            or lower.get("expected")
            or ""
        )
        control = hk_control(hid, name, category)
        extra = extra_control_fields(control, include_cis_internal=True)
        extra.update(
            {
                "id": hid,
                "check_id": hid,
                "result": outcome or "failed",
                "name": name,
                "category": category,
                "recommended": recommended,
                "severity": sev,
                "tool": "hardeningkitty",
                "baseline": "msft_security_baseline",
                "host_source": host_source,
                "host_unresolved": unresolved,
            }
        )
        extra = stamp_ids(extra, fqdn=host, hostname=host)
        labels = LABELS + ["hardeningkitty"]
        if unresolved:
            labels = labels + ["host-unresolved"]
        if host not in seen_hosts:
            seen_hosts.add(host)
            asset_extra = stamp_ids(
                {"asset_type": "PR", "tool": "hardeningkitty", "host_source": host_source},
                fqdn=host,
                hostname=host,
            )
            if unresolved:
                asset_extra["host_unresolved"] = True
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"Windows host {host}",
                    category="host",
                    assets=[host],
                    labels=LABELS + ["windows", "hardeningkitty"] + (["host-unresolved"] if unresolved else []),
                    collected_at=now,
                    extra=asset_extra,
                )
            )
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"hk-{hid}-{host}"),
                name=f"HardeningKitty {name}",
                description=(
                    f"{name} result={outcome or 'failed'} "
                    f"recommended={recommended or '[n/a]'} actual=[REDACTED]"
                ),
                severity=sev,
                category="identity-gap",
                assets=[host],
                labels=labels,
                collected_at=now,
                extra=extra,
            )
        )
    return stamp_lab_labels(records, lab=path_is_lab(path))


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
                severity=str(row.get("severity") or "high"),
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
                extra=stamp_ids(
                    {"asset_type": "PR", "ip": addr},
                    ip=addr,
                    fqdn=str(host.get("fqdn") or ""),
                    netbios=str(host.get("netbios") or ""),
                    domain=str(host.get("domain") or ""),
                    hostname=name,
                ),
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
                    severity=canon_severity("high"),
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
                    severity=canon_severity("high"),
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
                    severity=canon_severity("high"),
                    category="exposure",
                    assets=[name],
                    labels=LABELS + ["enum4linux", "smb"],
                    collected_at=now,
                    extra={"port": "445", "service": "smb", "share": share_name, "access": access},
                )
            )
    return records


def parse_file(path: Path) -> list[dict]:
    if path.name in SKIP_INPUT_NAMES:
        return []
    if path.suffix.lower() == ".host" or path.name.endswith(".csv.host"):
        return []
    text = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    payload: Any = {}
    meta_kind = ""
    if path.suffix.lower() == ".csv" or ("," in text[:200] and "Severity" in text[:400]):
        return parse_hardeningkitty_csv(text, iso_now(), path=path)
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
    pc_rules: list[dict[str, Any]] = []
    if path.suffix.lower() == ".xml" or text.startswith("<"):
        parsed_pc = _parse_pingcastle_xml(path)
        nodes = list(parsed_pc.get("nodes") or [])
        pc_rules = list(parsed_pc.get("rules") or [])
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
        empty_group = str(kind).lower() == "group" and props.get("member_count") == 0
        is_computer = (
            kind.lower() == "computer"
            or str(props.get("samaccountname") or "").endswith("$")
            or bool(props.get("operatingsystem"))
        )
        is_dc = "OU=DOMAIN CONTROLLERS" in str(props.get("distinguishedname") or "").upper()
        enabled = props.get("enabled")
        if empty_group:
            # Stated 0 members: no group-membership finding (demo files omit the count).
            pass
        else:
            if "BACKUP OPERATORS" in uname or (props.get("highvalue") and "BACKUP" in uname):
                findings.append(("high", "Backup Operators privileged group", "Members can dump SAM / seize privileged files."))
            spns = props.get("serviceprincipalnames") or []
            has_spn = bool(props.get("hasspn") or (isinstance(spns, list) and spns) or (isinstance(spns, str) and spns))
            if has_spn and not is_computer and enabled is not False:
                findings.append(("high", "Roastable SPN", f"{name} has an SPN and is kerberoastable."))
            if props.get("dontreqpreauth"):
                findings.append(("high", "AS-REP roastable account", f"{name} does not require Kerberos preauth."))
            roles = props.get("roles") or []
            if isinstance(roles, str):
                roles = [roles]
            pim = props.get("pimEligible") if "pimEligible" in props else props.get("pimeligible")
            if any("Global Administrator" in str(r) for r in roles) and not pim:
                findings.append(("critical", "Entra GA without PIM", f"{name} is Global Administrator without PIM eligibility."))
            if props.get("unconstraineddelegation") and not is_dc:
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
                    severity=canon_severity(sev),
                    category="identity-gap",
                    assets=[name],
                    labels=LABELS,
                    collected_at=now,
                    extra={"kind": kind},
                )
            )
    group_counts: dict[str, int | None] = {}
    for node in nodes:
        props = _props(node)
        kind = str(node.get("kind") or node.get("type") or "")
        if kind.lower() != "group":
            continue
        gname = str(props.get("name") or node.get("label") or "").strip().lower()
        if gname:
            group_counts[gname] = props.get("member_count")
    for rule in pc_rules:
        risk_id = str(rule.get("risk_id") or "pingcastle")
        domain = str(rule.get("domain") or "ad-domain")
        aliases = _group_rule_names(risk_id)
        if aliases:
            matched = [group_counts.get(alias) for alias in aliases if alias in group_counts]
            if matched and all(count == 0 for count in matched):
                continue
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"pc-{risk_id}-{domain}"),
                name=f"PingCastle {risk_id}",
                description=str(rule.get("rationale") or risk_id),
                severity=canon_severity(rule.get("severity") or "medium"),
                category="identity-gap",
                assets=[domain],
                labels=LABELS + ["pingcastle", "risk-rule"],
                collected_at=now,
                extra={
                    "risk_id": risk_id,
                    "points": rule.get("points") or "0",
                    "category": rule.get("category") or "",
                    "model": rule.get("model") or "",
                },
            )
        )
    raw_edges = _edges(payload)
    session_acc: dict[str, dict[str, Any]] = {}
    other_edges: list[dict[str, Any]] = []
    for edge in raw_edges:
        kind = str(
            edge.get("kind")
            or edge.get("type")
            or edge.get("label")
            or edge.get("EdgeType")
            or edge.get("edgeType")
            or edge.get("relationship")
            or ""
        )
        folded = kind.upper().replace(" ", "")
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
        if folded in {"HASSESSION", "HASESSION"}:
            acc = session_acc.setdefault(start, {"hosts": [], "count": 0})
            raw_count = edge.get("session_count")
            extra_hosts = edge.get("hosts") if isinstance(edge.get("hosts"), list) else []
            if raw_count:
                try:
                    acc["count"] = max(int(raw_count), int(acc["count"]))
                except (TypeError, ValueError):
                    acc["count"] = max(len(extra_hosts) or 1, int(acc["count"]))
                for host in extra_hosts or ([end] if end else []):
                    host_s = str(host)
                    if host_s and host_s not in acc["hosts"]:
                        acc["hosts"].append(host_s)
            else:
                acc["count"] = int(acc["count"]) + 1
                if end and end not in acc["hosts"]:
                    acc["hosts"].append(end)
            continue
        other_edges.append(edge)
    for start, acc in session_acc.items():
        hosts = [str(h) for h in acc["hosts"] if h]
        count = int(acc["count"] or len(hosts) or 1)
        other_edges.append(
            {
                "kind": "HasSession",
                "start": start,
                "end": hosts[0] if hosts else start,
                "session_count": count,
                "hosts": hosts,
            }
        )
    for edge in other_edges:
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
        hosts = edge.get("hosts") if isinstance(edge.get("hosts"), list) else []
        session_count = edge.get("session_count")
        extra = {"edge": kind, "start": start, "end": end}
        assets = [x for x in (start, end) if x]
        ref_tail = f"{kind}-{start}-{end}"
        detail = f"{desc} {start} -> {end}".strip()
        if kind.upper().replace(" ", "") in {"HASSESSION", "HASESSION"}:
            try:
                count = int(session_count or len(hosts) or 1)
            except (TypeError, ValueError):
                count = len(hosts) or 1
            extra["session_count"] = count
            if hosts:
                extra["hosts"] = [str(h) for h in hosts]
            assets = [start] + [str(h) for h in hosts if h and h != start]
            if not assets:
                assets = [x for x in (start, end) if x]
            ref_tail = f"{kind}-{start}"
            host_bit = ", ".join(str(h) for h in hosts) if hosts else end
            detail = f"{desc} {start} has {count} session(s)" + (f" on {host_bit}" if host_bit else "")
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, ref_tail),
                name=title,
                description=detail,
                severity=sev,
                category="identity-gap",
                assets=assets,
                labels=LABELS + ["bloodhound", "edge"],
                collected_at=now,
                extra=extra,
            )
        )
    return records


def main() -> None:
    run_collector(
        SOURCE,
        (".json", ".xml", ".csv", ".txt"),
        parse_file,
        finalize=dedupe_hardening,
    )


if __name__ == "__main__":
    main()
