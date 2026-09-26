#!/usr/bin/env python3
"""Parse Prowler JSON into cloud assets + misconfiguration findings."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, read_text, run_collector
from shared.schema import make_record, make_ref

SOURCE = "cloud-prowler"
LABELS = ["cloud", "prowler"]
_FAIL_STATUSES = {"", "FAIL", "FAILED"}
_MUTED_TRUTHY = frozenset({"true", "yes", "1", "muted"})


def _is_muted(item: dict[str, Any]) -> bool:
    for key in ("Muted", "muted", "MUTED"):
        val = item.get(key)
        if val is True or str(val).strip().lower() in _MUTED_TRUTHY:
            return True
    unmapped = item.get("unmapped") if isinstance(item.get("unmapped"), dict) else {}
    val = unmapped.get("muted")
    if val is True or str(val).strip().lower() in _MUTED_TRUTHY:
        return True
    return str(item.get("Status") or item.get("status_code") or "").upper() == "MUTED"


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
        "AccountId": str(item.get("AwsAccountId") or ""),
        "Muted": _is_muted(item),
    }


def _is_ocsf(item: dict[str, Any]) -> bool:
    """Prowler v4/v5 default JSON is OCSF Detection Finding (class_uid 2004)."""
    if "CheckID" in item or "CheckTitle" in item or "GeneratorId" in item:
        return False
    if item.get("status_code") and (
        item.get("finding_info") or item.get("metadata") or item.get("class_uid")
    ):
        return True
    return str(item.get("class_name") or "") == "Detection Finding"


def _ocsf_resource(item: dict[str, Any]) -> dict[str, Any]:
    resources = item.get("resources") if isinstance(item.get("resources"), list) else []
    return resources[0] if resources and isinstance(resources[0], dict) else {}


def _ocsf_to_prowler(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize Prowler OCSF v4/v5 JSON to the v3 Check_* keys the emitter uses."""
    meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    info = item.get("finding_info") if isinstance(item.get("finding_info"), dict) else {}
    res0 = _ocsf_resource(item)
    data = res0.get("data") if isinstance(res0.get("data"), dict) else {}
    res_meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    cloud = item.get("cloud") if isinstance(item.get("cloud"), dict) else {}
    account = cloud.get("account") if isinstance(cloud.get("account"), dict) else {}
    group = res0.get("group") if isinstance(res0.get("group"), dict) else {}
    types = info.get("types") if isinstance(info.get("types"), list) else []
    status = str(item.get("status_code") or "").upper()
    check_id = str(meta.get("event_code") or info.get("uid") or "check")
    title = str(info.get("title") or item.get("message") or check_id)
    rid = str(
        res0.get("uid")
        or res0.get("name")
        or res_meta.get("name")
        or account.get("uid")
        or check_id
    )
    arn = str(res_meta.get("arn") or rid)
    service = str(group.get("name") or (types[0] if types else "") or "cloud")
    account_uid = str(account.get("uid") or item.get("account_uid") or "").strip()
    return {
        "CheckID": check_id,
        "CheckTitle": title,
        "Status": status,
        "Severity": item.get("severity") or "medium",
        "ResourceId": rid,
        "ResourceArn": arn,
        "Description": item.get("status_detail") or item.get("message") or title,
        "ServiceName": service,
        "AccountId": account_uid,
        "Muted": _is_muted(item),
    }


def _normalize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    if _is_ocsf(rows[0]):
        return [_ocsf_to_prowler(x) for x in rows]
    if ("GeneratorId" in rows[0] or "Resources" in rows[0]) and "CheckID" not in rows[0]:
        return [_asff_to_prowler(x) for x in rows]
    return rows


def _iter_findings(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return _normalize_rows([x for x in payload if isinstance(x, dict)])
    if not isinstance(payload, dict):
        return []
    asff = payload.get("Findings")
    if isinstance(asff, list) and asff and isinstance(asff[0], dict) and "CheckID" not in asff[0]:
        return _normalize_rows([x for x in asff if isinstance(x, dict)])
    for key in ("findings", "Checks", "checks", "data"):
        val = payload.get(key)
        if isinstance(val, list) and val and isinstance(val[0], dict):
            return _normalize_rows([x for x in val if isinstance(x, dict)])
    if "CheckID" in payload or "CheckTitle" in payload:
        return [payload]
    if _is_ocsf(payload):
        return [_ocsf_to_prowler(payload)]
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


def _looks_prowler_csv(text: str) -> bool:
    head = text.lstrip("\ufeff").splitlines()[0] if text.strip() else ""
    up = head.upper()
    return ";" in head and "CHECK_ID" in up and "STATUS" in up and "RESOURCE_UID" in up


def _read_prowler_csv(path: Path) -> list[dict[str, Any]]:
    """Prowler v4/v5 default CSV is semicolon-delimited (CHECK_ID;STATUS;RESOURCE_UID)."""
    text = read_text(path)
    if not _looks_prowler_csv(text):
        return []
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")), delimiter=";")
    out: list[dict[str, Any]] = []
    for row in reader:
        if not isinstance(row, dict):
            continue
        keys = {str(k).strip().upper(): (v if v is not None else "") for k, v in row.items() if k}
        check = str(keys.get("CHECK_ID") or keys.get("CHECKID") or "").strip()
        if not check:
            continue
        status = str(keys.get("STATUS") or "").strip().upper()
        rid = str(keys.get("RESOURCE_UID") or keys.get("RESOURCE_NAME") or check).strip()
        muted = str(keys.get("MUTED") or "").strip()
        out.append(
            {
                "CheckID": check,
                "CheckTitle": str(keys.get("CHECK_TITLE") or check).strip(),
                "Status": status,
                "Severity": str(keys.get("SEVERITY") or "medium").strip(),
                "ResourceId": rid,
                "ResourceArn": rid,
                "Description": str(
                    keys.get("STATUS_EXTENDED") or keys.get("DESCRIPTION") or check
                ).strip(),
                "ServiceName": str(keys.get("SERVICE_NAME") or "cloud").strip(),
                "AccountId": str(keys.get("ACCOUNT_UID") or keys.get("ACCOUNT_ID") or "").strip(),
                "Muted": muted.lower() in _MUTED_TRUTHY,
            }
        )
    return out


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
    if path.suffix.lower() == ".csv":
        payload = _read_prowler_csv(path)
    else:
        payload = read_json(path)
    now = iso_now()
    records: list[dict[str, Any]] = []
    seen_assets: set[str] = set()
    for item in _iter_findings(payload):
        if _is_muted(item):
            continue
        check = str(item.get("CheckID") or item.get("CheckId") or item.get("check_id") or "check")
        title = str(item.get("CheckTitle") or item.get("title") or check)
        status = str(item.get("Status") or item.get("status_code") or item.get("status") or "").upper()
        if status == "NEW":
            status = str(item.get("status_code") or "").upper()
        sev = item.get("Severity") or item.get("severity") or "medium"
        rid = item.get("ResourceId") or item.get("ResourceName") or item.get("resource")
        if not rid:
            res0 = _ocsf_resource(item)
            rid = res0.get("uid") or res0.get("name")
        rid = str(rid or check)
        arn = str(item.get("ResourceArn") or item.get("arn") or rid)
        desc = str(item.get("Description") or item.get("StatusExtended") or title)
        service = str(item.get("ServiceName") or item.get("service") or "cloud")
        account = str(
            item.get("AccountId")
            or item.get("account_uid")
            or item.get("ACCOUNT_UID")
            or item.get("AwsAccountId")
            or ""
        ).strip()
        asset_type = "SP" if service.lower() in {"iam", "identity", "aad"} else "PR"
        asset_key = rid.lower()
        if asset_key not in seen_assets:
            seen_assets.add(asset_key)
            extra_asset = {"asset_type": asset_type, "arn": arn, "service": service}
            if account:
                extra_asset["account_id"] = account
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
                    extra=extra_asset,
                )
            )
        if status in _FAIL_STATUSES:
            ident = f"{check}-{account}-{rid}" if account else f"{check}-{rid}"
            extra = {
                "check_id": check,
                "arn": arn,
                "status": status or "FAIL",
                "service": service,
            }
            if account:
                extra["account_id"] = account
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, ident),
                    name=title,
                    description=desc,
                    severity=sev,
                    category="cloud-misconfiguration",
                    assets=[rid],
                    labels=LABELS + [service],
                    collected_at=now,
                    extra=extra,
                )
            )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".csv"), parse_file)


if __name__ == "__main__":
    main()
