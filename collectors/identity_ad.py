from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from shared.io_util import discover_input_files, emit, load_structured
from shared.schema import asset, control_extra, evidence, finding

SOURCE = "identity_ad"
PREFIX = "ID-"


def _finding_control(fid: str, title: str, description: str) -> dict[str, Any]:
    blob = f"{fid} {title} {description}".lower()
    if "backup" in blob:
        return control_extra(
            "CTL-BACKUP-RESTORE",
            "Restrict Backup Operators and test restore",
            description="Remove standing Backup Operators membership and test AD/system restore.",
            csf_function="recover",
            priority="2",
            category="process",
        )
    return control_extra(
        "CTL-TIER0-ID",
        "Tier-0 identity hardening / PIM",
        csf_function="protect",
        priority="1",
        category="process",
    )


def parse_doc(doc: Any) -> list:
    if not isinstance(doc, dict):
        return []
    records: list = []
    domain = str(doc.get("domain") or "corp.local")
    records.append(
        asset(
            PREFIX,
            "DOMAIN",
            domain,
            description=f"AD/Entra domain {domain}",
            asset_type="PR",
            source=SOURCE,
            labels=["identity", "ad"],
        )
    )
    for node in doc.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        props = node.get("properties") or {}
        name = str(props.get("name") or props.get("displayname") or "identity")
        kind = str(node.get("kind") or "Object")
        atype = "PR" if kind.lower() in {"domain", "user"} else "SP"
        records.append(
            asset(
                PREFIX,
                name,
                name,
                description=f"{kind} {name}",
                asset_type=atype,
                source=SOURCE,
                labels=["identity", kind.lower()],
                extra={"kind": kind, "hasspn": props.get("hasspn")},
            )
        )
        finding_blob = " ".join(
            str(item.get("id") or item.get("title") or "")
            for item in (doc.get("findings") or [])
            if isinstance(item, dict)
        ).upper()
        if props.get("hasspn") and "KERBEROAST" not in finding_blob and "SPN" not in finding_blob:
            records.append(
                finding(
                    PREFIX,
                    f"SPN-{name}",
                    f"Roastable SPN: {name}",
                    description=f"{name} has an SPN and is Kerberoastable.",
                    severity="high",
                    source=SOURCE,
                    related_assets=[name, domain],
                    labels=["identity", "kerberoast"],
                    extra=control_extra(
                        "CTL-GMSA",
                        "Use gMSA / long random SPN passwords",
                        csf_function="protect",
                        priority="1",
                    ),
                )
            )
    for item in doc.get("findings") or []:
        if not isinstance(item, dict):
            continue
        principal = str(item.get("principal") or "unknown")
        fid = str(item.get("id") or item.get("title"))
        records.append(
            finding(
                PREFIX,
                fid,
                str(item.get("title") or fid),
                description=str(item.get("description") or item.get("title") or fid),
                severity=str(item.get("severity") or "high"),
                source=SOURCE,
                related_assets=[principal, domain],
                labels=["identity", fid],
                extra=_finding_control(fid, str(item.get("title") or ""), str(item.get("description") or "")),
            )
        )
        if "user" in principal.lower() or "@" in principal:
            records.append(
                asset(
                    PREFIX,
                    principal,
                    principal,
                    description=f"Identity {principal}",
                    asset_type="PR",
                    source=SOURCE,
                    labels=["identity", "principal"],
                )
            )
    return records


def _is_scuba(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if doc.get("ProductName") or doc.get("MetaData"):
        return True
    for key in ("Results", "Failed", "Failures"):
        blob = doc.get(key)
        if not isinstance(blob, list) or not blob or not isinstance(blob[0], dict):
            continue
        sample = blob[0]
        if any(
            k in sample
            for k in (
                "Outcome",
                "Requirement",
                "PolicyName",
                "CheckID",
                "ControlId",
                "Controls",
                "RelativePath",
            )
        ):
            return True
    return False


_SCUBA_MS_ID = re.compile(r"(MS\.[A-Za-z]+\.\d+(?:\.\d+)*v\d+)", re.I)


def _scuba_text(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip().strip("\"'")


def _scuba_id_from_relative_path(raw: Any) -> str:
    """Requirement id from ScubaGear RelativePath (`baselines/teams.md#ms.teams.2.1v1`)."""
    text = _scuba_text(raw).replace("\\", "/")
    if not text:
        return ""
    fragment = text.rsplit("#", 1)[-1].strip() if "#" in text else ""
    candidate = fragment or text.rsplit("/", 1)[-1]
    candidate = candidate.split("?", 1)[0].strip()
    if candidate.lower().endswith((".md", ".html", ".json", ".csv")):
        candidate = candidate.rsplit(".", 1)[0]
    match = _SCUBA_MS_ID.search(candidate) or _SCUBA_MS_ID.search(text)
    if match:
        return match.group(1)
    if fragment and any(ch.isdigit() for ch in fragment) and "." in fragment:
        return fragment
    return ""


def _scuba_requirement_id(item: dict[str, Any]) -> tuple[str, bool]:
    """CheckID/ControlId first; RelativePath fragment when those are empty. Second value is True when RelativePath was used."""
    for key in (
        "CheckID",
        "CheckId",
        "ControlId",
        "ControlID",
        "PolicyId",
        "PolicyID",
        "RequirementId",
        "RequirementID",
    ):
        val = _scuba_text(item.get(key))
        if val:
            return val, False
    policy = _scuba_text(item.get("PolicyName"))
    if policy:
        match = _SCUBA_MS_ID.search(policy)
        if match:
            return match.group(1), False
        if len(policy) < 48 and any(ch.isdigit() for ch in policy) and " " not in policy:
            return policy, False
    rel = _scuba_id_from_relative_path(
        item.get("RelativePath") or item.get("relativePath") or item.get("relative_path")
    )
    if rel:
        return rel, True
    req = _scuba_text(item.get("Requirement"))
    if req:
        return req, False
    return "scuba", False


def _scuba_items(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect ScubaGear Results and Failed arrays (Failed items are implicit fails)."""
    items: list[dict[str, Any]] = []
    for key, implicit_fail in (("Results", False), ("Failed", True), ("Failures", True)):
        blob = doc.get(key)
        if not isinstance(blob, list):
            continue
        for item in blob:
            if not isinstance(item, dict):
                continue
            controls = item.get("Controls")
            if isinstance(controls, list):
                for ctl in controls:
                    if isinstance(ctl, dict):
                        row = dict(ctl)
                        if implicit_fail:
                            row["_scuba_failed_list"] = True
                        items.append(row)
                continue
            row = dict(item)
            if implicit_fail:
                row["_scuba_failed_list"] = True
            items.append(row)
    return items


def parse_scuba(doc: dict[str, Any]) -> list:
    records: list = []
    product = str(doc.get("ProductName") or "AAD")
    tenant = str((doc.get("MetaData") or {}).get("TenantId") or "contoso.onmicrosoft.com")
    records.append(
        asset(
            PREFIX,
            f"SCUBA-{product}",
            f"{product} tenant {tenant}",
            description=f"ScubaGear {product} report tenant {tenant}",
            asset_type="PR",
            source=SOURCE,
            labels=["identity", "scubagear", product.lower()],
        )
    )
    seen: set[str] = set()
    for item in _scuba_items(doc):
        from_failed = bool(item.pop("_scuba_failed_list", False))
        outcome = str(item.get("Outcome") or item.get("Result") or item.get("Status") or "").lower()
        if from_failed and outcome not in {"pass", "passed", "ok", "success"}:
            outcome = outcome or "fail"
        if outcome in {"pass", "passed", "ok", "success"}:
            continue
        if outcome not in {"fail", "failed", "warning", "warn"}:
            continue
        rid, from_rel = _scuba_requirement_id(item)
        if rid in seen:
            continue
        seen.add(rid)
        title = str(item.get("Requirement") or item.get("PolicyName") or rid)
        labels = ["identity", "scubagear"]
        if from_failed:
            labels.append("failed-list")
        if from_rel:
            labels.append("relativepath")
        records.append(
            finding(
                PREFIX,
                f"SCUBA-{rid}",
                title,
                description=str(item.get("Details") or title),
                severity="critical" if "pim" in title.lower() or "global admin" in title.lower() else "high",
                source=SOURCE,
                related_assets=[tenant, f"{product} tenant {tenant}"],
                labels=labels,
                extra=control_extra(
                    "CTL-TIER0-ID",
                    "Tier-0 identity hardening / PIM",
                    csf_function="protect",
                    priority="1",
                    category="process",
                ),
            )
        )
    return records


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_text(parent: ET.Element, name: str) -> str:
    for child in parent:
        if _xml_local(child.tag) == name:
            text = (child.text or "").strip()
            if text:
                return text
    found = parent.find(f".//{{*}}{name}")
    if found is not None:
        text = (found.text or "").strip()
        if text:
            return text
    return ""


def _xml_attr(el: ET.Element, *names: str) -> str:
    attrib = el.attrib or {}
    lower = {str(k).lower().rsplit("}", 1)[-1]: (v or "").strip() for k, v in attrib.items()}
    for name in names:
        val = lower.get(name.lower(), "")
        if val:
            return val
    return ""


def _pingcastle_domain(root: ET.Element) -> str:
    """DomainFQDN text, else DomainFQDN attr when Host/DomainFQDN text is empty."""
    host = _xml_text(root, "Host")
    domain = _xml_text(root, "DomainFQDN")
    if domain:
        return domain
    domain = _xml_attr(root, "DomainFQDN", "domainFQDN", "domain")
    if domain:
        return domain
    if host:
        return host
    forest = _xml_text(root, "ForestFQDN") or _xml_attr(root, "ForestFQDN", "forestFQDN")
    if forest:
        return forest
    netbios = _xml_text(root, "NetBIOSName") or _xml_attr(root, "NetBIOSName")
    if netbios:
        return netbios
    return "unknown-domain"


def _points_to_severity(points: int) -> str:
    if points >= 30:
        return "critical"
    if points >= 15:
        return "high"
    if points >= 10:
        return "medium"
    if points >= 1:
        return "low"
    return "info"


def _looks_like_pingcastle_xml(text: str) -> bool:
    lowered = text.lstrip("\ufeff")
    return (
        "<HealthcheckData" in lowered
        or "<HealthcheckRiskRule" in lowered
        or "<HealthcheckRisk" in lowered
        or "<RiskRules" in lowered
    )


def _pingcastle_rule_finding(rule: dict[str, Any], domain: str, key_prefix: str) -> Any | None:
    if not isinstance(rule, dict):
        return None
    risk_id = ""
    for key in ("RiskId", "riskId", "risk_id", "Id", "id"):
        val = rule.get(key)
        if val is not None and str(val).strip():
            risk_id = str(val).strip()
            break
    risk_id = risk_id or "PC-RULE"
    rationale = ""
    for key in ("Rationale", "rationale", "Description", "description"):
        val = rule.get(key)
        if val is not None and str(val).strip():
            rationale = str(val).strip()
            break
    rationale = rationale or risk_id
    category = str(rule.get("Category") or rule.get("category") or "Anomalies")
    model = str(rule.get("Model") or rule.get("model") or "")
    try:
        points = int(float(str(rule.get("Points") if rule.get("Points") is not None else rule.get("points") or "0")))
    except ValueError:
        points = 0
    if points <= 0:
        return None
    title = f"PingCastle {risk_id}: {rationale.splitlines()[0][:80]}"
    return finding(
        PREFIX,
        f"{key_prefix}-{risk_id}",
        title,
        description=f"{rationale} (category={category} model={model} points={points})",
        severity=_points_to_severity(points),
        source=SOURCE,
        related_assets=[domain],
        labels=["identity", "pingcastle", category.lower(), key_prefix.lower()],
        extra=control_extra(
            "CTL-TIER0-ID",
            "Tier-0 identity hardening / PIM",
            csf_function="protect",
            priority="1",
            category="process",
            description=f"Remediate PingCastle {risk_id}",
        ),
    )


def _healthcheck_risk_items(doc: Any) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        return []
    inner = doc.get("HealthcheckData") if isinstance(doc.get("HealthcheckData"), dict) else doc
    if not isinstance(inner, dict):
        return []
    items: list[dict[str, Any]] = []
    for key in (
        "HealthcheckRisk",
        "HealthcheckRisks",
        "HealthcheckRiskRule",
        "HealthcheckRiskRules",
        "RiskRules",
    ):
        val = inner.get(key)
        if isinstance(val, list):
            items.extend(x for x in val if isinstance(x, dict))
        elif isinstance(val, dict):
            items.append(val)
    nodes = inner.get("nodes")
    if isinstance(nodes, list):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            kind = str(node.get("type") or node.get("kind") or node.get("$type") or "").lower()
            if "healthcheckrisk" in kind.replace("_", ""):
                items.append(node)
    return items


def _is_pingcastle_json(doc: Any) -> bool:
    return bool(_healthcheck_risk_items(doc))


def parse_pingcastle_json(doc: Any) -> list:
    if not isinstance(doc, dict):
        return []
    inner = doc.get("HealthcheckData") if isinstance(doc.get("HealthcheckData"), dict) else doc
    if not isinstance(inner, dict):
        inner = doc
    domain = str(
        inner.get("DomainFQDN")
        or inner.get("domainFQDN")
        or inner.get("Domain")
        or inner.get("domain")
        or "corp.local"
    )
    netbios = str(inner.get("NetBIOSName") or inner.get("netBIOSName") or "")
    maturity = str(inner.get("MaturityLevel") if inner.get("MaturityLevel") is not None else inner.get("maturityLevel") or "")
    records: list = [
        asset(
            PREFIX,
            f"PCJSON-{domain}",
            domain,
            description=f"PingCastle JSON domain {domain} netbios={netbios or 'n/a'} maturity={maturity or 'n/a'}",
            asset_type="PR",
            source=SOURCE,
            labels=["identity", "pingcastle", "ad", "healthcheckrisk"],
            extra={"format": "pingcastle-json", "netbios": netbios, "maturity": maturity},
        )
    ]
    for rule in _healthcheck_risk_items(doc):
        rec = _pingcastle_rule_finding(rule, domain, "PCHCR")
        if rec is not None:
            records.append(rec)
    return records


def parse_pingcastle_xml(path: Path) -> list:
    records: list = []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return records
    root = tree.getroot()
    domain = _pingcastle_domain(root)
    netbios = _xml_text(root, "NetBIOSName")
    maturity = _xml_text(root, "MaturityLevel")
    records.append(
        asset(
            PREFIX,
            f"PC-{domain}",
            domain,
            description=f"PingCastle domain {domain} netbios={netbios or 'n/a'} maturity={maturity or 'n/a'}",
            asset_type="PR",
            source=SOURCE,
            labels=["identity", "pingcastle", "ad"],
            extra={"format": "pingcastle-xml", "netbios": netbios, "maturity": maturity},
        )
    )
    for rule in root.iter():
        if _xml_local(rule.tag) not in {"HealthcheckRiskRule", "HealthcheckRisk"}:
            continue
        rec = _pingcastle_rule_finding(
            {
                "RiskId": _xml_text(rule, "RiskId"),
                "Rationale": _xml_text(rule, "Rationale") or _xml_text(rule, "Description"),
                "Category": _xml_text(rule, "Category") or "Anomalies",
                "Model": _xml_text(rule, "Model"),
                "Points": _xml_text(rule, "Points") or "0",
            },
            domain,
            "PCXML",
        )
        if rec is not None:
            records.append(rec)
    return records


PRIV_EDGE_KINDS = {
    "GENERICALL",
    "GENERICWRITE",
    "WRITEDACL",
    "WRITEOWNER",
    "OWNS",
    "ALLEXTENDEDRIGHTS",
    "FORCECHANGEPASSWORD",
    "ADDMEMBER",
    "ADDSELF",
    "ADMINTO",
    "DCSYNC",
    "GETCHANGES",
    "GETCHANGESALL",
    "GETCHANGESINFILTEREDSET",
    "ALLOWEDTODELEGATE",
    "ALLOWEDTOACT",
    "ADDALLOWEDTOACT",
    "AZGLOBALADMIN",
    "AZPRIVILEGEDROLEADMIN",
    "AZRESETPASSWORD",
    "HASSESSION",
}

PRIV_GROUPS = (
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS@",
    "BACKUP OPERATORS",
    "ACCOUNT OPERATORS",
    "SCHEMA ADMINS",
    "DNS ADMINS",
    "GROUP POLICY CREATOR",
)


def _bh_graph(doc: dict[str, Any]) -> tuple[Any, Any]:
    """BloodHound CE: data.nodes/edges, data as node list, or top-level nodes/edges."""
    data = doc.get("data")
    nodes = None
    edges = None
    if isinstance(data, dict):
        nodes = data.get("nodes")
        edges = data.get("edges")
    elif isinstance(data, list):
        nodes = data
        edges = doc.get("edges")
    if nodes is None:
        nodes = doc.get("nodes")
    if edges is None:
        edges = doc.get("edges")
    return nodes, edges


def _bh_sample(nodes: Any) -> dict[str, Any] | None:
    if isinstance(nodes, dict):
        for val in nodes.values():
            if isinstance(val, dict):
                return val
        return None
    if isinstance(nodes, list):
        for val in nodes:
            if isinstance(val, dict):
                return val
    return None


def _is_bloodhound_ce(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    findings = doc.get("findings")
    if isinstance(findings, list) and findings and isinstance(findings[0], dict):
        if findings[0].get("title") or findings[0].get("principal"):
            return False
    nodes, _edges = _bh_graph(doc)
    if not isinstance(nodes, (dict, list)) or not nodes:
        return False
    sample = _bh_sample(nodes)
    if not isinstance(sample, dict):
        return False
    return bool(sample.get("objectId") or sample.get("objectid"))


def _bh_kind(node: dict[str, Any]) -> str:
    kinds = node.get("kinds")
    if isinstance(kinds, list) and kinds:
        return str(kinds[0])
    return str(node.get("kind") or node.get("label") or "Object")


def _bh_name(node: dict[str, Any]) -> str:
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    return str(
        props.get("name")
        or props.get("displayname")
        or node.get("label")
        or node.get("objectId")
        or "identity"
    )


def _bh_index(data: dict[str, Any] | None, nodes_raw: Any = None) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    raw = nodes_raw
    if raw is None and isinstance(data, dict):
        raw = data.get("nodes")
    items: list[dict[str, Any]] = []
    index: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        iterable = raw.items()
    elif isinstance(raw, list):
        iterable = ((str(i), n) for i, n in enumerate(raw))
    else:
        return items, index
    for key, node in iterable:
        if not isinstance(node, dict):
            continue
        blob = dict(node)
        blob["_id"] = str(key)
        items.append(blob)
        index[str(key)] = blob
        oid = str(blob.get("objectId") or blob.get("objectid") or "")
        if oid:
            index[oid] = blob
        name = _bh_name(blob)
        index[name] = blob
    return items, index


def parse_bloodhound_ce(doc: Any) -> list:
    if not isinstance(doc, dict):
        return []
    nodes_raw, edges_raw = _bh_graph(doc)
    data = doc.get("data") if isinstance(doc.get("data"), dict) else doc
    nodes, index = _bh_index(data if isinstance(data, dict) else {}, nodes_raw)
    records: list = []
    domain = "corp.local"
    for node in nodes:
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        if props.get("domain"):
            domain = str(props["domain"])
            break
    records.append(
        asset(
            PREFIX,
            domain,
            domain,
            description=f"AD/Entra domain {domain}",
            asset_type="PR",
            source=SOURCE,
            labels=["identity", "ad", "bloodhound-ce"],
        )
    )
    for node in nodes:
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        name = _bh_name(node)
        kind = _bh_kind(node)
        atype = "PR" if kind.lower() in {"domain", "user"} else "SP"
        records.append(
            asset(
                PREFIX,
                name,
                name,
                description=f"{kind} {name}",
                asset_type=atype,
                source=SOURCE,
                labels=["identity", "bloodhound-ce", kind.lower()],
                extra={"kind": kind, "objectid": node.get("objectId"), "hasspn": props.get("hasspn")},
            )
        )
        if props.get("hasspn"):
            records.append(
                finding(
                    PREFIX,
                    f"BHCE-SPN-{name}",
                    f"Roastable SPN: {name}",
                    description=f"{name} has an SPN (BloodHound CE properties.hasspn).",
                    severity="high",
                    source=SOURCE,
                    related_assets=[name, domain],
                    labels=["identity", "bloodhound-ce", "kerberoast"],
                    extra=control_extra(
                        "CTL-GMSA",
                        "Use gMSA / long random SPN passwords",
                        csf_function="protect",
                        priority="1",
                    ),
                )
            )
        if props.get("dontreqpreauth"):
            records.append(
                finding(
                    PREFIX,
                    f"BHCE-ASREP-{name}",
                    f"AS-REP roastable (preauth disabled): {name}",
                    description=f"{name} has dontreqpreauth set.",
                    severity="high",
                    source=SOURCE,
                    related_assets=[name, domain],
                    labels=["identity", "bloodhound-ce", "asrep"],
                    extra=control_extra(
                        "CTL-PREAUTH",
                        "Require Kerberos pre-authentication",
                        csf_function="protect",
                        priority="1",
                    ),
                )
            )
        if props.get("unconstraineddelegation"):
            records.append(
                finding(
                    PREFIX,
                    f"BHCE-UNCONSTR-{name}",
                    f"Unconstrained delegation: {name}",
                    description=f"{name} allows unconstrained Kerberos delegation.",
                    severity="high",
                    source=SOURCE,
                    related_assets=[name, domain],
                    labels=["identity", "bloodhound-ce", "delegation"],
                    extra=control_extra(
                        "CTL-TIER0-ID",
                        "Tier-0 identity hardening / PIM",
                        csf_function="protect",
                        priority="1",
                        category="process",
                    ),
                )
            )
        if props.get("passwordnotreqd"):
            records.append(
                finding(
                    PREFIX,
                    f"BHCE-NOPWD-{name}",
                    f"Password not required: {name}",
                    description=f"{name} has PASSWD_NOTREQD.",
                    severity="high",
                    source=SOURCE,
                    related_assets=[name, domain],
                    labels=["identity", "bloodhound-ce"],
                    extra=control_extra(
                        "CTL-TIER0-ID",
                        "Tier-0 identity hardening / PIM",
                        csf_function="protect",
                        priority="1",
                        category="process",
                    ),
                )
            )
    edge_iter: list[Any]
    if isinstance(edges_raw, dict):
        edge_iter = list(edges_raw.values())
    elif isinstance(edges_raw, list):
        edge_iter = edges_raw
    elif isinstance(data, dict):
        edge_iter = list(data.get("edges") or [])
    else:
        edge_iter = []
    for edge in edge_iter:
        if not isinstance(edge, dict):
            continue
        kind = str(edge.get("kind") or edge.get("label") or edge.get("type") or "").upper()
        src = index.get(str(edge.get("source") or ""))
        dst = index.get(str(edge.get("target") or ""))
        src_name = _bh_name(src) if src else str(edge.get("source") or "unknown")
        dst_name = _bh_name(dst) if dst else str(edge.get("target") or "unknown")
        privileged_group = any(tok in dst_name.upper() for tok in PRIV_GROUPS)
        if kind == "MEMBEROF" and not privileged_group:
            continue
        if kind not in PRIV_EDGE_KINDS and not (kind == "MEMBEROF" and privileged_group):
            continue
        sev = "critical" if kind in {"GENERICALL", "DCSYNC", "AZGLOBALADMIN"} or privileged_group else "high"
        if kind == "HASSESSION" and "DC" not in dst_name.upper() and not (dst or {}).get("isTierZero"):
            sev = "medium"
        records.append(
            finding(
                PREFIX,
                f"BHCE-{kind}-{src_name}-{dst_name}",
                f"BloodHound {kind}: {src_name} -> {dst_name}",
                description=f"Edge {kind} from {src_name} to {dst_name} (BloodHound CE data.edges).",
                severity=sev,
                source=SOURCE,
                related_assets=[src_name, dst_name, domain],
                labels=["identity", "bloodhound-ce", kind.lower()],
                extra=control_extra(
                    "CTL-TIER0-ID",
                    "Tier-0 identity hardening / PIM",
                    csf_function="protect",
                    priority="1",
                    category="process",
                ),
            )
        )
    return records


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        suffix = path.suffix.lower()
        if suffix == ".xml" or _looks_like_pingcastle_xml(text):
            records.extend(parse_pingcastle_xml(path))
            continue
        for doc in load_structured(path):
            if _is_pingcastle_json(doc):
                records.extend(parse_pingcastle_json(doc))
            elif _is_scuba(doc):
                records.extend(parse_scuba(doc))
            elif _is_bloodhound_ce(doc):
                records.extend(parse_bloodhound_ce(doc))
            else:
                records.extend(parse_doc(doc))
    return records


def main() -> None:
    files = discover_input_files("identity")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "AD",
            "BloodHound/PingCastle/ScubaGear demo parse",
            description="Parsed BloodHound CE data.nodes/data.edges, PingCastle XML HealthcheckRiskRule, PingCastle JSON HealthcheckRisk (when XML is absent), and ScubaGear: Backup Operators, roastable SPN, Entra GA without PIM.",
            source=SOURCE,
        )
    )
    emit("identity", records, files)


if __name__ == "__main__":
    main()
