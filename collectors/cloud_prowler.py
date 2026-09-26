#!/usr/bin/env python3
"""Parse Prowler JSON into cloud assets + misconfiguration findings."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shared.asset_ids import stamp_ids
from shared.io_util import iso_now, read_json, run_collector
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
    if custodian is not None:
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


# Keyword-gate when no operator policy→control map is present (Metis §13.4.3).
# Hyphens/underscores/camelCase normalize to the same tokens.
_C7N_SECURITY_KEYWORDS = (
    "encrypt",
    "public",
    "security_context",
    "privileged",
    "mfa",
    "logging",
    "tls",
    "iam",
    "kms",
)
_C7N_COST_OPS_KEYWORDS = (
    "underutilized",
    "idle",
    "cpu",
    "stop",
    "tag",
)
_NOT_A_WEAKNESS = "NOT_A_WEAKNESS"
_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _c7n_norm(text: str) -> str:
    return _TOKEN_RE.sub("", str(text or "").lower())


def _c7n_flatten(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(_c7n_flatten(v) for v in value.values()) + " " + " ".join(
            str(k) for k in value
        )
    if isinstance(value, list):
        return " ".join(_c7n_flatten(v) for v in value)
    return str(value)


def _c7n_operator_control(policy_name: str) -> str | None:
    """Optional operator policy→control map. None = no map (keyword-gate)."""
    del policy_name
    return None


def _c7n_gate(policy: dict[str, Any]) -> str:
    """security → finding; cost/ops or no match → NOT_A_WEAKNESS."""
    pname = str(policy.get("name") or "")
    if _c7n_operator_control(pname):
        return "security"
    blob = " ".join(
        (
            pname,
            str(policy.get("description") or ""),
            _c7n_flatten(policy.get("filters")),
        )
    )
    norm = _c7n_norm(blob)
    if any(_c7n_norm(kw) in norm for kw in _C7N_SECURITY_KEYWORDS):
        return "security"
    return _NOT_A_WEAKNESS


def _c7n_policy_from_metadata(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    policy = payload.get("policy")
    if isinstance(policy, dict) and (policy.get("name") or policy.get("resource")):
        return policy
    if payload.get("name") and (payload.get("resource") or "resources" in payload):
        return payload
    return None


def _c7n_resource_type(policy: dict[str, Any]) -> str:
    resource = str(policy.get("resource") or policy.get("resource_type") or "").strip()
    return resource


def _c7n_severity(policy: dict[str, Any]) -> str:
    raw = policy.get("severity")
    if raw is None or str(raw).strip() == "":
        return "medium"
    return canon_severity(raw)


def _c7n_asset_key(res: dict[str, Any], pname: str) -> tuple[str, str]:
    """k8s namespace/name; Azure full ARM id; AWS Arn/*Id. Never dir/leaf collapse."""
    meta = res.get("metadata") if isinstance(res.get("metadata"), dict) else {}
    mname = str(meta.get("name") or "").strip()
    if mname:
        ns = str(meta.get("namespace") or "").strip()
        rid = f"{ns}/{mname}" if ns else mname
        return rid, rid
    arm = str(res.get("id") or "")
    if arm.startswith("/subscriptions/"):
        return arm, arm
    arn = str(res.get("Arn") or res.get("arn") or "").strip()
    if arn:
        return arn, arn
    for key, val in res.items():
        if (
            isinstance(key, str)
            and key.endswith("Id")
            and key not in {"id", "Id"}
            and val
        ):
            rid = str(val)
            return rid, rid
    rid = str(res.get("Name") or res.get("Id") or res.get("id") or pname)
    return rid, str(res.get("Arn") or res.get("arn") or rid)


def _custodian_policy_findings(
    policy: dict[str, Any], resources: list[Any]
) -> list[dict[str, Any]]:
    pname = str(policy.get("name") or "").strip() or "c7n-policy"
    resource = _c7n_resource_type(policy)
    gate = _c7n_gate(policy)
    sev = _c7n_severity(policy)
    desc = str(policy.get("description") or f"Policy {pname}")
    out: list[dict[str, Any]] = []
    for res in resources:
        if not isinstance(res, dict):
            continue
        rid, arn = _c7n_asset_key(res, pname)
        item: dict[str, Any] = {
            "CheckID": pname,
            "CheckTitle": f"Cloud Custodian {pname}",
            "Status": "FAIL",
            "Severity": sev,
            "ResourceId": rid,
            "ResourceArn": arn,
            "Description": f"{desc} matched {rid}" if desc else f"Policy {pname} matched {rid}",
            "ServiceName": resource,
            "policy_name": pname,
            "policy_resource": resource,
            "custodian_gate": gate,
        }
        if gate == _NOT_A_WEAKNESS:
            item["exclude_reason"] = _NOT_A_WEAKNESS
        out.append(item)
    return out


def _custodian_findings(payload: Any) -> list[dict[str, Any]] | None:
    if not isinstance(payload, dict):
        return None
    policies: list[dict[str, Any]] = []
    if isinstance(payload.get("policies"), list):
        policies = [p for p in payload["policies"] if isinstance(p, dict)]
    elif payload.get("name") and "resources" in payload:
        policies = [payload]
    else:
        return None
    out: list[dict[str, Any]] = []
    for pol in policies:
        rows = pol.get("resources") if isinstance(pol.get("resources"), list) else []
        out.extend(_custodian_policy_findings(pol, rows))
    return out


def _custodian_items(path: Path, payload: Any) -> list[dict[str, Any]] | None:
    """Real c7n drop is metadata.json + sibling resources.json. Demo is policies[]."""
    if path.name == "metadata.json":
        policy = _c7n_policy_from_metadata(payload)
        if policy is None:
            return None
        resources: list[Any] = []
        sibling = path.parent / "resources.json"
        if sibling.is_file():
            loaded = read_json(sibling)
            if isinstance(loaded, list):
                resources = loaded
        elif isinstance(payload, dict) and isinstance(payload.get("resources"), list):
            resources = payload["resources"]
        return _custodian_policy_findings(policy, resources)
    sibling_meta = path.parent / "metadata.json"
    if path.name == "resources.json" or (
        isinstance(payload, list) and sibling_meta.is_file()
    ):
        if not sibling_meta.is_file():
            return None
        policy = _c7n_policy_from_metadata(read_json(sibling_meta))
        if policy is None:
            return None
        rows = payload if isinstance(payload, list) else []
        return _custodian_policy_findings(policy, rows)
    return _custodian_findings(payload)


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
    items = _custodian_items(path, payload)
    if items is None:
        items = _iter_findings(payload)
    for item in items:
        check = str(item.get("CheckID") or item.get("CheckId") or item.get("check_id") or "check")
        title = str(item.get("CheckTitle") or item.get("title") or check)
        status = str(item.get("Status") or item.get("status") or "").upper()
        sev = item.get("Severity") or item.get("severity") or "medium"
        rid = str(item.get("ResourceId") or item.get("ResourceName") or item.get("resource") or check)
        arn = str(item.get("ResourceArn") or item.get("arn") or rid)
        desc = str(item.get("Description") or item.get("StatusExtended") or title)
        service = str(item.get("ServiceName") or item.get("service") or "")
        if not service:
            service = "cloud"
        asset_type = "SP" if service.lower() in {"iam", "identity", "aad"} or ".iam" in service.lower() else "PR"
        extra: dict[str, Any] = {
            "check_id": check,
            "arn": arn,
            "status": status or "FAIL",
            "service": service,
        }
        for key in ("policy_name", "policy_resource", "custodian_gate", "exclude_reason"):
            if item.get(key):
                extra[key] = item[key]
        excluded = extra.get("exclude_reason") == _NOT_A_WEAKNESS
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
        if status in {"", "FAIL", "FAILED", "MANUAL"}:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{check}-{rid}"),
                    name=title,
                    description=desc,
                    severity=sev,
                    category="not-a-weakness" if excluded else "cloud-misconfiguration",
                    assets=[rid],
                    labels=LABELS + [service, "custodian"] if extra.get("policy_name") else LABELS + [service],
                    collected_at=now,
                    extra=extra,
                )
            )
    return records


def main() -> None:
    run_collector(SOURCE, (".json",), parse_file)


if __name__ == "__main__":
    main()
