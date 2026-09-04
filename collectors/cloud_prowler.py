#!/usr/bin/env python3
"""Parse Prowler JSON into cloud assets + misconfiguration findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, run_collector
from shared.schema import make_record, make_ref

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


def _iter_findings(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows = [x for x in payload if isinstance(x, dict)]
        if rows and ("GeneratorId" in rows[0] or "Resources" in rows[0]) and "CheckID" not in rows[0]:
            return [_asff_to_prowler(x) for x in rows]
        return rows
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
            sev = {"danger": "critical", "warning": "medium", "info": "low"}.get(level, "high")
            for rid in items[:8]:
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
        for res in rows:
            if not isinstance(res, dict):
                continue
            rid = str(res.get("Name") or res.get("Id") or res.get("id") or pname)
            arn = str(res.get("Arn") or res.get("arn") or rid)
            out.append(
                {
                    "CheckID": pname,
                    "CheckTitle": f"Cloud Custodian {pname}",
                    "Status": "FAIL",
                    "Severity": pol.get("severity") or "high",
                    "ResourceId": rid,
                    "ResourceArn": arn,
                    "Description": str(pol.get("description") or f"Policy {pname} matched {rid}"),
                    "ServiceName": service,
                }
            )
    return out


def _steampipe_findings(payload: Any) -> list[dict[str, Any]]:
    rows = []
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        rows = [r for r in payload["rows"] if isinstance(r, dict)]
    out: list[dict[str, Any]] = []
    for row in rows:
        status = str(row.get("status") or row.get("alarm") or "alarm").lower()
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


def parse_file(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path)
    now = iso_now()
    records: list[dict[str, Any]] = []
    seen_assets: set[str] = set()
    for item in _iter_findings(payload):
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
                    extra={"asset_type": asset_type, "arn": arn, "service": service},
                )
            )
        if status in {"", "FAIL", "FAILED", "MANUAL"}:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{check}-{rid}"),
                    name=title,
                    description=desc,
                    severity=sev,
                    category="cloud-misconfiguration",
                    assets=[rid],
                    labels=LABELS + [service],
                    collected_at=now,
                    extra={
                        "check_id": check,
                        "arn": arn,
                        "status": status or "FAIL",
                        "service": service,
                    },
                )
            )
    return records


def main() -> None:
    run_collector(SOURCE, (".json",), parse_file)


if __name__ == "__main__":
    main()
