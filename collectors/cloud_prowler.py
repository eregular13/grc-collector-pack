from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from shared.io_util import discover_input_files, emit, load_structured
from shared.schema import asset, control_extra, evidence, finding, normalize_finding_status

SOURCE = "cloud_prowler"
PREFIX = "CLD-"
CONTROL_BY_CHECK = {
    "s3_bucket_public_access": (
        "CTL-S3-BPA",
        "S3 Block Public Access",
        "protect",
        "1",
    ),
    "iam_user_administrator_access": (
        "CTL-IAM-LEAST-PRIV",
        "IAM least privilege",
        "protect",
        "1",
    ),
    "iam_role_crossaccount_wildcards": (
        "CTL-IAM-TRUST",
        "Restrict IAM trust policies",
        "protect",
        "2",
    ),
    "ec2_securitygroup_allow_ingress_from_internet_to_any_port": (
        "CTL-SG-INGRESS",
        "Restrict security group ingress",
        "protect",
        "1",
    ),
    "rds_instance_storage_encrypted": (
        "CTL-RDS-ENC",
        "Encrypt RDS storage",
        "protect",
        "2",
    ),
    "iam_root_access_keys": (
        "CTL-ROOT-NO-KEYS",
        "Disable root access keys",
        "protect",
        "1",
    ),
    "cloudtrail_multi_region_enabled": (
        "CTL-CLOUDTRAIL",
        "Enable multi-region CloudTrail",
        "detect",
        "2",
    ),
}


def _flatten_v4(item: dict[str, Any]) -> dict[str, Any] | None:
    meta = item.get("Metadata") or item.get("metadata")
    status_obj = item.get("Status") if isinstance(item.get("Status"), dict) else None
    if status_obj is None and isinstance(item.get("status"), dict):
        status_obj = item["status"]
    resource = item.get("Resource") if isinstance(item.get("Resource"), dict) else {}
    if not isinstance(meta, dict) and status_obj is None and not resource:
        return None
    merged = dict(item)
    if isinstance(meta, dict):
        merged.setdefault(
            "CheckID",
            meta.get("CheckID") or meta.get("check_id") or meta.get("EventID"),
        )
        merged.setdefault(
            "CheckTitle",
            meta.get("CheckTitle") or meta.get("check_title") or meta.get("Title"),
        )
        merged.setdefault("Severity", meta.get("Severity") or meta.get("severity"))
        merged.setdefault("Provider", meta.get("Provider"))
    if isinstance(status_obj, dict):
        merged["Status"] = (
            status_obj.get("Status")
            or status_obj.get("status")
            or status_obj.get("Code")
            or ""
        )
        merged.setdefault(
            "StatusExtended",
            status_obj.get("StatusExtended") or status_obj.get("Message") or "",
        )
    if not str(merged.get("Status") or "").strip():
        alt = item.get("CheckStatus") or item.get("check_status") or item.get("CHECK_STATUS")
        if isinstance(alt, dict):
            alt = alt.get("Status") or alt.get("status") or alt.get("Code")
        if alt is not None and str(alt).strip():
            merged["Status"] = alt
    if resource:
        merged.setdefault(
            "ResourceId",
            resource.get("Uid") or resource.get("Id") or resource.get("Arn"),
        )
        merged.setdefault(
            "ResourceName",
            resource.get("Name") or resource.get("Uid") or resource.get("Id"),
        )
        merged.setdefault("ResourceType", resource.get("Type"))
        merged.setdefault("ResourceArn", resource.get("Arn"))
    return merged


def _item_fields(item: dict[str, Any]) -> dict[str, Any]:
    v4 = _flatten_v4(item)
    if v4 is not None:
        return v4
    if (
        "CheckID" in item
        or isinstance(item.get("Status"), str)
        or item.get("CheckStatus") is not None
        or item.get("check_status") is not None
    ):
        return item
    inner = item.get("Finding") or item.get("finding") or {}
    if isinstance(inner, dict) and inner:
        return inner
    if "GeneratorId" in item or "Compliance" in item or "Resources" in item:
        sev = item.get("Severity")
        if isinstance(sev, dict):
            sev = sev.get("Label") or sev.get("Normalized")
        resources = item.get("Resources") or []
        res = resources[0] if resources and isinstance(resources[0], dict) else {}
        compliance = item.get("Compliance") or {}
        status = str(compliance.get("Status") or item.get("RecordState") or "")
        if status.upper() in {"FAILED", "FAIL"}:
            status = "FAIL"
        gen = str(item.get("GeneratorId") or item.get("Id") or "")
        check = gen.split("/")[-1] if "/" in gen else gen.replace("prowler-", "", 1)
        return {
            "CheckID": check,
            "CheckTitle": item.get("Title") or check,
            "Status": status,
            "Severity": sev or "medium",
            "ResourceId": res.get("Id") or item.get("Id"),
            "ResourceName": res.get("Id") or res.get("Type") or "asff-resource",
            "ResourceType": res.get("Type") or "",
            "ResourceArn": res.get("Id") or "",
            "StatusExtended": item.get("Description") or item.get("Title") or check,
        }
    return item


def _finding_lifecycle(row: dict[str, Any], prowler_status: str) -> str:
    """Map Prowler Status / WorkflowStatus / RecordState onto findings.csv status."""
    for key in (
        "FindingStatus",
        "finding_status",
        "WorkflowStatus",
        "workflow_status",
        "RecordState",
        "record_state",
    ):
        val = row.get(key)
        if isinstance(val, dict):
            val = val.get("Status") or val.get("status")
        if val is not None and str(val).strip():
            return normalize_finding_status(val)
    return normalize_finding_status(prowler_status)


def _prowler_status(row: dict[str, Any]) -> tuple[str, str]:
    """Prowler Status, else CheckStatus when Status is empty/whitespace."""
    for key in (
        "Status",
        "status",
        "CheckStatus",
        "check_status",
        "CHECK_STATUS",
        "StatusCode",
        "status_code",
    ):
        if key not in row:
            continue
        val = row.get(key)
        if isinstance(val, dict):
            val = val.get("Status") or val.get("status") or val.get("Code") or val.get("code")
        text = str(val if val is not None else "").strip()
        if text:
            return text.upper(), key
    return "", ""


def parse_prowler_item(item: Any) -> list:
    if not isinstance(item, dict):
        return []
    row = _item_fields(item)
    check = str(row.get("CheckID") or row.get("check_id") or row.get("Uid") or "")
    if not check:
        return []
    resource = str(
        row.get("ResourceName")
        or row.get("ResourceId")
        or row.get("resource_name")
        or "unknown-resource"
    )
    rtype = str(row.get("ResourceType") or row.get("resource_type") or "")
    status, status_key = _prowler_status(row)
    title = str(row.get("CheckTitle") or row.get("Title") or check)
    desc = str(row.get("StatusExtended") or row.get("description") or title)
    sev = str(row.get("Severity") or row.get("severity") or "medium")
    asset_type = "PR" if "Account" in rtype else "SP"
    records = [
        asset(
            PREFIX,
            resource,
            resource,
            description=f"{rtype or 'cloud resource'} {resource}",
            asset_type=asset_type,
            source=SOURCE,
            labels=["cloud", "aws"],
            extra={"resource_type": rtype, "arn": row.get("ResourceArn")},
        )
    ]
    if status in {"FAIL", "FAILED", "MANUAL"}:
        ctl = CONTROL_BY_CHECK.get(check)
        extra = {}
        if ctl:
            extra = control_extra(ctl[0], ctl[1], csf_function=ctl[2], priority=ctl[3])
        extra["check_id"] = check
        extra["cve"] = None
        labels = ["cloud", "prowler", check]
        if status_key.lower().replace("-", "_") in {"checkstatus", "check_status"}:
            labels.append("checkstatus")
        records.append(
            finding(
                PREFIX,
                check,
                title,
                description=desc,
                severity=sev if status != "FAIL" or sev else "high",
                source=SOURCE,
                related_assets=[resource],
                status=_finding_lifecycle(row, status),
                labels=labels,
                extra=extra,
            )
        )
    return records


def _csv_pick(row: dict[str, str], *names: str) -> str:
    lower = {str(k).strip().lower(): (v if v is not None else "") for k, v in row.items()}
    for name in names:
        val = lower.get(name.strip().lower(), "")
        if str(val).strip():
            return str(val).strip()
    return ""


def csv_row_to_item(row: dict[str, Any]) -> dict[str, Any]:
    """Map Prowler CSV headers (v3 CHECK_ID / v4 RESOURCE_UID) onto parse_prowler_item fields."""
    raw = {str(k): ("" if v is None else str(v)) for k, v in row.items()}
    resource = _csv_pick(raw, "RESOURCE_NAME", "RESOURCE_ID", "RESOURCE_UID", "ResourceName")
    return {
        "CheckID": _csv_pick(raw, "CHECK_ID", "CheckID", "check_id"),
        "CheckTitle": _csv_pick(raw, "CHECK_TITLE", "CheckTitle", "TITLE"),
        "Status": _csv_pick(raw, "STATUS", "Status", "CHECK_STATUS", "CheckStatus"),
        "StatusExtended": _csv_pick(raw, "STATUS_EXTENDED", "StatusExtended", "DESCRIPTION"),
        "ResourceId": _csv_pick(raw, "RESOURCE_ID", "RESOURCE_UID", "ResourceId"),
        "ResourceName": resource,
        "ResourceType": _csv_pick(raw, "RESOURCE_TYPE", "ResourceType"),
        "ResourceArn": _csv_pick(raw, "RESOURCE_ARN", "RESOURCE_UID", "ResourceArn"),
        "Severity": _csv_pick(raw, "SEVERITY", "Severity"),
        "FindingStatus": _csv_pick(raw, "FINDING_STATUS", "FindingStatus"),
        "WorkflowStatus": _csv_pick(raw, "WORKFLOW_STATUS", "WorkflowStatus"),
    }


def parse_prowler_csv(path: Path) -> list:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return []
    text = text.lstrip("\ufeff")
    if not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text))
    headers = [str(h or "").strip().lower().replace(" ", "_") for h in (reader.fieldnames or [])]
    if "check_id" not in headers and "checkid" not in headers:
        return []
    records: list = []
    for row in reader:
        if not isinstance(row, dict):
            continue
        item = csv_row_to_item(row)
        if not item.get("CheckID"):
            continue
        if str(item.get("Status") or "").upper() in {"PASS", "PASSED", "OK"}:
            continue
        records.extend(parse_prowler_item(item))
    return records


def parse_files(files: list[Path]) -> list:
    records: list = []
    for path in files:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            records.extend(parse_prowler_csv(path))
            continue
        for item in load_structured(path):
            if isinstance(item, dict) and isinstance(
                item.get("Findings") or item.get("findings"), list
            ):
                for finding_item in item.get("Findings") or item.get("findings") or []:
                    records.extend(parse_prowler_item(finding_item))
            else:
                records.extend(parse_prowler_item(item))
    return records


def main() -> None:
    files = discover_input_files("cloud")
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "PROWLER",
            "Prowler demo parse",
            description="Parsed Prowler JSON and CSV (CHECK_ID/STATUS/SEVERITY; empty Status uses CheckStatus). Live AWS API was not called.",
            source=SOURCE,
        )
    )
    emit("cloud", records, files)


if __name__ == "__main__":
    main()
