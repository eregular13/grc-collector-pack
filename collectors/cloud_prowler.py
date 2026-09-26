#!/usr/bin/env python3
"""Parse Prowler JSON into cloud assets + misconfiguration findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.asset_ids import stamp_ids
from shared.io_util import iso_now, read_json, read_text, run_collector
from shared.schema import canon_severity, make_record, make_ref

SOURCE = "cloud-prowler"
LABELS = ["cloud", "prowler"]


def _asff_severity(item: dict[str, Any]) -> str:
    sev = item.get("Severity")
    if isinstance(sev, dict):
        label = sev.get("Label") or sev.get("Normalized") or ""
        return str(label) or "medium"
    if sev:
        return str(sev)
    return "medium"


def _asff_to_prowler(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize AWS Security Finding Format (Prowler ASFF export) to Prowler keys."""
    resources = item.get("Resources") if isinstance(item.get("Resources"), list) else []
    res0 = resources[0] if resources and isinstance(resources[0], dict) else {}
    compliance = item.get("Compliance") if isinstance(item.get("Compliance"), dict) else {}
    pf = item.get("ProductFields") if isinstance(item.get("ProductFields"), dict) else {}
    status = str(compliance.get("Status") or item.get("Status") or "")
    if status.upper() in {"FAILED", "FAIL"}:
        status = "FAIL"
    elif status.upper() in {"PASSED", "PASS"}:
        status = "PASS"
    rtype = str(res0.get("Type") or "")
    service = str(pf.get("ProwlerServiceName") or "")
    if not service:
        service = rtype.replace("Aws", "").split("::")[0] or "cloud"
        if "S3" in rtype:
            service = "s3"
        elif "Iam" in rtype or "IAM" in rtype:
            service = "iam"
    check_id = (
        pf.get("ProwlerCheckID")
        or pf.get("ControlId")
        or item.get("GeneratorId")
        or item.get("Id")
        or "asff"
    )
    return {
        "CheckID": check_id,
        "CheckTitle": item.get("Title") or item.get("GeneratorId") or "asff",
        "Status": status,
        "Severity": _asff_severity(item),
        "ResourceId": res0.get("Id") or item.get("Id") or "resource",
        "ResourceArn": res0.get("Id") or "",
        "Description": item.get("Description") or item.get("Title") or "",
        "ServiceName": service,
    }


def _looks_asff_row(row: dict[str, Any]) -> bool:
    return ("GeneratorId" in row or "Resources" in row) and "CheckID" not in row


def _looks_prowler_row(row: dict[str, Any]) -> bool:
    return "CheckID" in row or "CheckTitle" in row or (
        "Status" in row and ("ResourceId" in row or "ResourceArn" in row)
    )


_C7N_KEYS = (
    "c7n:MatchedFilters",
    "c7n:MatchedFiltersCount",
    "c7n:alert-user",
    "c7n:annotation",
)

# Real Custodian output has no severity field. Security policies default
# Medium via canon_severity (severity_source=default). Name keywords do
# not invent High.
_C7N_SECURITY = (
    "security",
    "encrypt",
    "unencrypt",
    "public",
    "exposed",
    "insecure",
    "privilege",
    "iam",
    "firewall",
    "nacl",
    "secret",
    "password",
    "wildcard",
    "cis",
    "hipaa",
    "pci",
    "ssh",
    "rdp",
    "0.0.0.0",
    "world-open",
    "anonymous",
    "sec-con",
    "security-context",
    "security_context",
    "hostnetwork",
    "hostpid",
    "hostipc",
    "capability",
    "run-as",
    "runas",
    "privileged",
    "admin",
    "open-ssh",
    "open-rdp",
    "missing-sec",
)
_C7N_NOT_WEAKNESS = (
    "cost",
    "unused",
    "idle",
    "underutilized",
    "under-utilized",
    "underutil",
    "oversized",
    "rightsiz",
    "offhours",
    "off-hours",
    "billing",
    "budget",
    "utilization",
    "cpu-under",
    "stop-under",
)
# Operator map: exact policy names that are security findings.
_C7N_SECURITY_NAMES = frozenset(
    {
        "s3-encryption-missing",
        "security-context-pods",
    }
)


def _looks_c7n_keys(row: Any) -> bool:
    """Custodian-specific keys only. Arn/Name/Id alone is Steampipe-shaped too."""
    if not isinstance(row, dict) or _looks_prowler_row(row) or _looks_asff_row(row):
        return False
    return any(k in row for k in _C7N_KEYS)


def _custodian_resources_path(path: Path | None) -> bool:
    """resources.json plus sibling metadata.json (policy name / resource type)."""
    if path is None or path.name.lower() != "resources.json":
        return False
    return (path.parent / "metadata.json").is_file()


def _custodian_meta(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    meta = path.parent / "metadata.json"
    if not meta.is_file():
        return {}
    try:
        doc = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    inner = doc.get("policy") if isinstance(doc.get("policy"), dict) else doc
    return inner if isinstance(inner, dict) else {}


def _custodian_is_security(pname: str, pol: dict[str, Any]) -> bool:
    """Only security policies become findings. Cost/ops → NOT_A_WEAKNESS."""
    if pname.lower() in _C7N_SECURITY_NAMES:
        return True
    blob = f"{pname} {pol.get('description') or ''} {pol.get('resource') or ''}".lower()
    security = any(token in blob for token in _C7N_SECURITY)
    cost = any(token in blob for token in _C7N_NOT_WEAKNESS)
    if security and not cost:
        return True
    if security and cost:
        return True
    return False


def _custodian_resource_id(res: dict[str, Any], resource: str) -> str:
    """Identity is the cloud resource, keyed per resource type — not the policy name."""
    rtype = str(resource or "").lower()
    meta = res.get("metadata") if isinstance(res.get("metadata"), dict) else {}
    if rtype.startswith("k8s.") or rtype in {"k8s", "pod"}:
        ns = str(meta.get("namespace") or res.get("namespace") or "")
        name = str(meta.get("name") or "")
        if ns and name:
            return f"{ns}/{name}"
        if name:
            return name
    if rtype.startswith("azure."):
        name = str(res.get("name") or res.get("Name") or meta.get("name") or "")
        if name:
            return name
        rid = res.get("id") or res.get("Id")
        if rid:
            return str(rid)
    return str(
        res.get("Arn")
        or res.get("arn")
        or res.get("Name")
        or res.get("InstanceId")
        or res.get("Id")
        or res.get("id")
        or meta.get("name")
        or ""
    )


def _custodian_severity(pname: str, pol: dict[str, Any], path: Path | None) -> tuple[str, str]:
    """Severity from policy metadata only. Else medium + default (no High invent)."""
    for key in ("severity", "Severity"):
        if pol.get(key):
            return canon_severity(pol[key]), "policy"
    inner = _custodian_meta(path)
    if inner.get("severity") or inner.get("Severity"):
        return canon_severity(inner.get("severity") or inner.get("Severity")), "metadata"
    return canon_severity("medium"), "default"


def _custodian_policy_name(path: Path | None) -> str:
    if path is None:
        return "c7n-policy"
    meta = _custodian_meta(path)
    if meta.get("name"):
        return str(meta["name"])
    if path.name.lower() == "resources.json":
        parent = path.parent.name.strip()
        if parent:
            return parent
    return path.stem or "c7n-policy"


def _iter_findings(payload: Any, path: Path | None = None) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows = [x for x in payload if isinstance(x, dict)]
        if not rows:
            return []
        if _custodian_resources_path(path) or _looks_c7n_keys(rows[0]):
            return _custodian_from_resources(rows, path)
        if _looks_asff_row(rows[0]):
            return [_asff_to_prowler(x) for x in rows]
        if _looks_prowler_row(rows[0]):
            return rows
        # Bare Steampipe/query lists ({arn,name,id}) are inventory, not Custodian.
        return []
    if not isinstance(payload, dict):
        return []
    asff = payload.get("Findings")
    if isinstance(asff, list) and asff and isinstance(asff[0], dict) and "CheckID" not in asff[0]:
        return [_asff_to_prowler(x) for x in asff if isinstance(x, dict)]
    for key in ("findings", "Checks", "checks", "data"):
        val = payload.get(key)
        if isinstance(val, list):
            return [x for x in val if isinstance(x, dict)]
    if "CheckID" in payload or "CheckTitle" in payload:
        return [payload]
    if "GeneratorId" in payload or "Resources" in payload:
        return [_asff_to_prowler(payload)]
    custodian = _custodian_findings(payload)
    if custodian:
        return custodian
    powerpipe = _powerpipe_findings(payload)
    if powerpipe:
        return powerpipe
    steampipe = _steampipe_findings(payload)
    if steampipe:
        return steampipe
    scout = _scoutsuite_findings(payload)
    if scout:
        return scout
    return []


def _scoutsuite_findings(payload: Any) -> list[dict[str, Any]]:
    services = payload.get("services") if isinstance(payload, dict) else None
    if not isinstance(services, dict):
        return []
    out: list[dict[str, Any]] = []
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        findings = svc.get("findings")
        if not isinstance(findings, dict):
            continue
        for fid, item in findings.items():
            if not isinstance(item, dict):
                continue
            flagged = item.get("flagged_items")
            try:
                nflag = int(flagged)
            except (TypeError, ValueError):
                nflag = 1 if item.get("items") else 0
            if nflag <= 0:
                continue
            items = item.get("items") if isinstance(item.get("items"), list) else [fid]
            level = str(item.get("level") or "warning").lower()
            # ScoutSuite only has danger/warning — danger is high, not a critical tier.
            sev = {"danger": "high", "warning": "medium", "info": "low"}.get(level, "high")
            for rid in items:
                out.append(
                    {
                        "CheckID": str(fid),
                        "CheckTitle": f"ScoutSuite {svc_name}: {item.get('description') or fid}",
                        "Status": "FAIL",
                        "Severity": sev,
                        "ResourceId": str(rid),
                        "ResourceArn": str(rid),
                        "Description": f"{svc_name} {item.get('description') or fid}",
                        "ServiceName": str(svc_name),
                    }
                )
    return out


def _custodian_findings(payload: Any) -> list[dict[str, Any]]:
    policies: list[dict[str, Any]] = []
    if isinstance(payload, dict) and isinstance(payload.get("policies"), list):
        policies = [p for p in payload["policies"] if isinstance(p, dict)]
    elif isinstance(payload, dict) and payload.get("name") and "resources" in payload:
        policies = [payload]
    out: list[dict[str, Any]] = []
    for pol in policies:
        pname = str(pol.get("name") or "c7n-policy")
        resource = str(pol.get("resource") or "cloud")
        service = resource.split(".")[-1] if resource else "cloud"
        rows = pol.get("resources") if isinstance(pol.get("resources"), list) else []
        security = _custodian_is_security(pname, pol)
        path = pol.get("_path")
        path_obj = path if isinstance(path, Path) else None
        for res in rows:
            if not isinstance(res, dict):
                continue
            rid = _custodian_resource_id(res, resource) or pname
            arn = str(res.get("Arn") or res.get("arn") or res.get("id") or res.get("Id") or rid)
            sev, sev_source = _custodian_severity(pname, pol, path_obj)
            item = {
                "CheckID": pname,
                "CheckTitle": f"Cloud Custodian {pname}",
                "Status": "FAIL" if security else "EXCLUDED",
                "Severity": sev,
                "ResourceId": rid,
                "ResourceArn": arn,
                "Description": str(pol.get("description") or f"Policy {pname} matched {rid}"),
                "ServiceName": service,
                "SeveritySource": sev_source,
                "ResourceType": resource,
            }
            if not security:
                item["ExcludeReason"] = "NOT_A_WEAKNESS"
            out.append(item)
    return out


def _custodian_from_resources(rows: list[dict[str, Any]], path: Path | None) -> list[dict[str, Any]]:
    meta = _custodian_meta(path)
    pname = _custodian_policy_name(path)
    resource = str(meta.get("resource") or "cloud")
    findings = _custodian_findings(
        {
            "name": pname,
            "resource": resource,
            "description": meta.get("description") or "",
            "resources": rows,
            "_path": path,
        }
    )
    sev, sev_source = _custodian_severity(pname, meta, path)
    for item in findings:
        item["Severity"] = sev
        item["SeveritySource"] = sev_source
        item["ResourceType"] = resource
    return findings


def _powerpipe_findings(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    if not (payload.get("controls") or payload.get("groups") or payload.get("group_id")):
        return []
    out: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child)
            return
        if not isinstance(node, dict):
            return
        controls = node.get("controls")
        if isinstance(controls, list):
            for ctrl in controls:
                if not isinstance(ctrl, dict):
                    continue
                cid = str(ctrl.get("control_id") or ctrl.get("control") or "powerpipe")
                title = str(ctrl.get("title") or cid)
                sev = ctrl.get("severity") or "medium"
                service = str(ctrl.get("service") or "cloud")
                results = ctrl.get("results") if isinstance(ctrl.get("results"), list) else []
                for res in results:
                    if not isinstance(res, dict):
                        continue
                    status = str(res.get("status") or "").strip().lower()
                    if status not in {"alarm", "error"}:
                        continue
                    rid = str(res.get("resource") or res.get("reason") or cid)
                    out.append(
                        {
                            "CheckID": cid,
                            "CheckTitle": title,
                            "Status": "FAIL",
                            "Severity": sev,
                            "ResourceId": rid,
                            "ResourceArn": str(res.get("arn") or rid),
                            "Description": str(res.get("reason") or title),
                            "ServiceName": service,
                        }
                    )
        groups = node.get("groups")
        if isinstance(groups, list):
            walk(groups)

    walk(payload)
    return out


def _steampipe_findings(payload: Any) -> list[dict[str, Any]]:
    rows = []
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        rows = [r for r in payload["rows"] if isinstance(r, dict)]
    out: list[dict[str, Any]] = []
    for row in rows:
        raw_status = row.get("status")
        if raw_status is None or str(raw_status).strip() == "":
            # steampipe query --output json inventory rows are not controls.
            continue
        status = str(raw_status).lower()
        mapped = "FAIL" if status in {"alarm", "fail", "failed", "error"} else "PASS"
        rid = str(row.get("resource") or row.get("arn") or row.get("title") or "steampipe")
        out.append(
            {
                "CheckID": str(row.get("control") or row.get("title") or "steampipe"),
                "CheckTitle": str(row.get("title") or row.get("control") or "Steampipe control"),
                "Status": mapped,
                "Severity": row.get("severity") or "medium",
                "ResourceId": rid,
                "ResourceArn": str(row.get("arn") or rid),
                "Description": str(row.get("reason") or row.get("title") or rid),
                "ServiceName": str(row.get("service") or "cloud"),
            }
        )
    return out


def _load_cloud_payload(path: Path) -> Any:
    """JSON, or ScoutSuite ``scoutsuite_results =`` JS assignment."""
    try:
        return read_json(path)
    except Exception:
        text = read_text(path).lstrip("\ufeff").lstrip()
    for prefix in ("scoutsuite_results =", "scoutsuite_results="):
        if text.startswith(prefix):
            text = text[len(prefix) :].lstrip()
            break
    text = text.rstrip().rstrip(";")
    return json.loads(text)


def parse_file(path: Path) -> list[dict[str, Any]]:
    payload = _load_cloud_payload(path)
    now = iso_now()
    records: list[dict[str, Any]] = []
    seen_assets: set[str] = set()
    for item in _iter_findings(payload, path=path):
        check = str(item.get("CheckID") or item.get("CheckId") or item.get("check_id") or "check")
        title = str(item.get("CheckTitle") or item.get("title") or check)
        status = str(item.get("Status") or item.get("status") or "").upper()
        sev = item.get("Severity") or item.get("severity") or "medium"
        rid = str(item.get("ResourceId") or item.get("ResourceName") or item.get("resource") or check)
        arn = str(item.get("ResourceArn") or item.get("arn") or rid)
        desc = str(item.get("Description") or item.get("StatusExtended") or title)
        service = str(item.get("ServiceName") or item.get("service") or "cloud")
        asset_type = "SP" if service.lower() in {"iam", "identity", "aad"} else "PR"
        asset_key = rid.lower()
        if asset_key not in seen_assets:
            seen_assets.add(asset_key)
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{rid}"),
                    name=rid,
                    description=f"{service} resource {arn}",
                    severity="info",
                    category="cloud-resource",
                    assets=[rid],
                    labels=LABELS + [service],
                    collected_at=now,
                    extra=stamp_ids(
                        {"asset_type": asset_type, "arn": arn, "service": service},
                        arn=arn,
                    ),
                )
            )
        if item.get("ExcludeReason") or status == "EXCLUDED":
            records.append(
                {
                    "kind": "excluded",
                    "source": SOURCE,
                    "ref_id": make_ref(SOURCE, f"excl-{check}-{rid}"),
                    "name": title,
                    "description": desc,
                    "severity": canon_severity(sev),
                    "category": "excluded",
                    "assets": [rid],
                    "labels": LABELS + [service, "not-a-weakness"],
                    "collected_at": now,
                    "extra": {
                        "exclude_reason": str(item.get("ExcludeReason") or "NOT_A_WEAKNESS"),
                        "check_id": check,
                        "arn": arn,
                        "status": status or "EXCLUDED",
                        "service": service,
                        "resource": rid,
                        "resource_type": item.get("ResourceType") or service,
                    },
                }
            )
            continue
        if status in {"", "FAIL", "FAILED", "MANUAL"}:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{check}-{rid}"),
                    name=title,
                    description=desc,
                    severity=canon_severity(sev),
                    category="cloud-misconfiguration",
                    assets=[rid],
                    labels=LABELS + [service],
                    collected_at=now,
                    extra={
                        "check_id": check,
                        "arn": arn,
                        "status": status or "FAIL",
                        "service": service,
                        **(
                            {"severity_source": item.get("SeveritySource")}
                            if item.get("SeveritySource")
                            else {}
                        ),
                    },
                )
            )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".js"), parse_file)


if __name__ == "__main__":
    main()
