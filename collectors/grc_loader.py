from __future__ import annotations

import csv
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.io_util import (
    ensure_out_tree,
    exclusive_file_lock,
    get_out,
    read_jsonl,
    refuse_live_scan,
    write_json,
    write_text,
)
from shared.schema import (
    ASSET_TYPES,
    FINDING_CSV_SEVERITIES,
    asset_type_for_name,
    normalize_finding_status,
    normalize_severity,
    ocsf_severity_id,
    severity_to_riskready,
    severity_to_vuln,
)

CISO_ASSET_HEADER = [
    "ref_id",
    "name",
    "description",
    "domain",
    "type",
    "reference_link",
    "observation",
    "filtering_labels",
    "parent_assets",
]
CISO_CONTROL_HEADER = [
    "ref_id",
    "name",
    "description",
    "domain",
    "status",
    "category",
    "priority",
    "csf_function",
]
CISO_EVIDENCE_HEADER = ["name", "description"]
CISO_FINDING_HEADER = [
    "ref_id",
    "name",
    "description",
    "severity",
    "status",
    "filtering_labels",
]
CISO_VULN_HEADER = [
    "ref_id",
    "name",
    "description",
    "status",
    "severity",
    "assets",
    "applied_controls",
]
CISO_RISK_HEADER = [
    "ref_id",
    "assets",
    "threats",
    "name",
    "description",
    "existing_controls",
    "current_impact",
    "current_proba",
    "current_risk",
    "additional_controls",
    "residual_impact",
    "residual_proba",
    "residual_risk",
    "treatment",
]


REQUIRED_CANONICAL = (
    "cloud",
    "nmap",
    "vuln",
    "wazuh",
    "identity",
    "easm",
    "k8s",
    "code",
    "saas",
)


def load_canonical(*, require_all: bool = True) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cdir = get_out() / "canonical"
    missing = [name for name in REQUIRED_CANONICAL if not (cdir / f"{name}.jsonl").exists()]
    if require_all and missing:
        raise SystemExit(
            "loader race/missing canonical: "
            + ",".join(missing)
            + " — run the nine collectors first"
        )
    if not cdir.exists():
        return rows
    for path in sorted(cdir.glob("*.jsonl")):
        rows.extend(read_jsonl(path))
    return rows


def _labels(row: dict[str, Any]) -> str:
    """Comma-joined labels. Never spaces-only or empty tokens (I-034)."""
    parts: list[str] = []
    for item in row.get("labels") or []:
        token = str(item).strip()
        if token:
            parts.append(token)
    return ",".join(parts)


def dedupe_assets(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()
    for row in rows:
        name = str(row.get("name") or row.get("ref_id") or "").strip()
        atype = asset_type_for_name(name, str(row.get("asset_type") or "SP"))
        key = (name.lower(), atype)
        if key not in seen:
            seen[key] = dict(row)
            seen[key]["asset_type"] = atype
            continue
        existing = seen[key]
        for label in row.get("labels") or []:
            if label not in existing.setdefault("labels", []):
                existing["labels"].append(label)
        for rel in row.get("related_assets") or []:
            if rel not in existing.setdefault("related_assets", []):
                existing["related_assets"].append(rel)
    return list(seen.values())


def dedupe_by_ref(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for row in rows:
        ref = str(row.get("ref_id") or "").strip()
        if not ref:
            continue
        if ref not in seen:
            seen[ref] = dict(row)
    return list(seen.values())


def _write_csv(path: Path, header: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in header})
    tmp.replace(path)


def _write_semicolon_csv(path: Path, header: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=header,
            extrasaction="ignore",
            delimiter=";",
        )
        writer.writeheader()
        for row in rows:
            cleaned = {k: str(row.get(k, "")).replace(";", ",") for k in header}
            writer.writerow(cleaned)
    tmp.replace(path)


def collect_controls(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    found: OrderedDict[str, dict[str, str]] = OrderedDict()
    for row in findings:
        extra = row.get("extra") or {}
        ctl = extra.get("control") if isinstance(extra, dict) else None
        if not isinstance(ctl, dict):
            continue
        ref = str(ctl.get("ref_id") or "").strip()
        if not ref or ref in found:
            continue
        found[ref] = {
            "ref_id": ref,
            "name": str(ctl.get("name") or ref),
            "description": str(ctl.get("description") or ctl.get("name") or ref),
            "domain": str(ctl.get("domain") or "default"),
            "status": str(ctl.get("status") or "to_do"),
            "category": str(ctl.get("category") or "technical"),
            "priority": str(ctl.get("priority") or "2"),
            "csf_function": str(ctl.get("csf_function") or "protect"),
        }
    if "CTL-REVIEW" not in found:
        found["CTL-REVIEW"] = {
            "ref_id": "CTL-REVIEW",
            "name": "GRC finding review",
            "description": "Periodic review of imported collector findings.",
            "domain": "default",
            "status": "to_do",
            "category": "process",
            "priority": "3",
            "csf_function": "govern",
        }
    funcs = {row.get("csf_function") for row in found.values()}
    if "respond" not in funcs:
        found["CTL-IR-RESPOND"] = {
            "ref_id": "CTL-IR-RESPOND",
            "name": "Incident response playbook",
            "description": "Contain and eradicate high/critical collector findings.",
            "domain": "default",
            "status": "to_do",
            "category": "process",
            "priority": "2",
            "csf_function": "respond",
        }
    if "recover" not in funcs:
        found["CTL-BACKUP-RESTORE"] = {
            "ref_id": "CTL-BACKUP-RESTORE",
            "name": "Restrict Backup Operators and test restore",
            "description": "Remove standing Backup Operators membership and test AD/system restore.",
            "domain": "default",
            "status": "to_do",
            "category": "process",
            "priority": "2",
            "csf_function": "recover",
        }
    return list(found.values())


def _control_refs_for(finding_row: dict[str, Any]) -> str:
    extra = finding_row.get("extra") or {}
    ctl = extra.get("control") if isinstance(extra, dict) else None
    if isinstance(ctl, dict) and ctl.get("ref_id"):
        return str(ctl["ref_id"])
    return "CTL-REVIEW"


def _is_cve(row: dict[str, Any]) -> bool:
    extra = row.get("extra") or {}
    cve = extra.get("cve") if isinstance(extra, dict) else None
    blob = " ".join(
        [
            str(row.get("ref_id") or ""),
            str(row.get("name") or ""),
            str(cve or ""),
        ]
    ).upper()
    return "CVE-" in blob or bool(cve)


def _risk_numbers(sev: str) -> tuple[str, str, str, str, str, str]:
    mapping = {
        "critical": ("4", "4", "4", "3", "2", "3"),
        "high": ("3", "3", "3", "2", "2", "2"),
        "medium": ("2", "2", "2", "2", "1", "1"),
        "low": ("1", "2", "1", "1", "1", "1"),
    }
    return mapping.get(sev, mapping["medium"])


def run_loader() -> dict[str, int]:
    refuse_live_scan()
    out = ensure_out_tree()
    with exclusive_file_lock(out / ".loader.lock"):
        return _run_loader_unlocked()


def _run_loader_unlocked() -> dict[str, int]:
    rows = load_canonical(require_all=True)
    assets = dedupe_assets([r for r in rows if r.get("kind") == "asset"])
    findings = dedupe_by_ref([r for r in rows if r.get("kind") == "finding"])
    evidence_rows = dedupe_by_ref([r for r in rows if r.get("kind") == "evidence"])
    incidents_in = dedupe_by_ref([r for r in rows if r.get("kind") == "incident"])
    controls = collect_controls(findings)

    asset_csv = []
    for row in assets:
        atype = asset_type_for_name(row.get("name") or "", str(row.get("asset_type") or "SP"))
        asset_csv.append(
            {
                "ref_id": row.get("ref_id") or "",
                "name": row.get("name") or "",
                "description": row.get("description") or "",
                "domain": row.get("domain") or "default",
                "type": atype,
                "reference_link": row.get("reference_link") or "",
                "observation": row.get("observation") or "",
                "filtering_labels": _labels(row),
                "parent_assets": ",".join(row.get("parent_assets") or []),
            }
        )

    finding_csv = []
    for row in findings:
        sev = normalize_severity(row.get("severity"))
        if sev not in FINDING_CSV_SEVERITIES:
            if sev == "info":
                continue
            sev = "low"
        finding_csv.append(
            {
                "ref_id": row.get("ref_id") or "",
                "name": row.get("name") or "",
                "description": row.get("description") or "",
                "severity": sev,
                "status": normalize_finding_status(row.get("status")),
                "filtering_labels": _labels(row),
            }
        )

    vuln_csv = []
    for row in findings:
        if not _is_cve(row) and row.get("source") != "vuln_scan":
            continue
        vuln_csv.append(
            {
                "ref_id": row.get("ref_id") or "",
                "name": row.get("name") or "",
                "description": row.get("description") or "",
                "status": "Exploitable",
                "severity": severity_to_vuln(row.get("severity")),
                "assets": ",".join(row.get("related_assets") or []),
                "applied_controls": _control_refs_for(row),
            }
        )

    evidence_csv = []
    seen_ev: set[str] = set()
    for row in evidence_rows:
        name = str(row.get("name") or row.get("ref_id") or "evidence")
        if name in seen_ev:
            continue
        seen_ev.add(name)
        evidence_csv.append(
            {
                "name": name,
                "description": str(row.get("description") or name),
            }
        )

    canon_by_ref = {str(r.get("ref_id") or ""): r for r in findings}
    hc_pairs: list[tuple[dict[str, str], dict[str, Any]]] = []
    seen_hc: set[str] = set()
    for csv_row in finding_csv:
        if csv_row.get("severity") not in {"high", "critical"}:
            continue
        ref = str(csv_row.get("ref_id") or "")
        if not ref or ref in seen_hc:
            continue
        seen_hc.add(ref)
        hc_pairs.append((csv_row, canon_by_ref.get(ref) or {}))

    risk_csv = []
    for csv_row, src in hc_pairs:
        sev = str(csv_row.get("severity") or "high")
        ci, cp, cr, ri, rp, rr = _risk_numbers(sev)
        risk_csv.append(
            {
                "ref_id": f"RSK-{csv_row.get('ref_id')}",
                "assets": ",".join(src.get("related_assets") or []),
                "threats": "exploit,misconfiguration",
                "name": csv_row.get("name") or "",
                "description": csv_row.get("description") or "",
                "existing_controls": _control_refs_for(src),
                "current_impact": ci,
                "current_proba": cp,
                "current_risk": cr,
                "additional_controls": "CTL-REVIEW",
                "residual_impact": ri,
                "residual_proba": rp,
                "residual_risk": rr,
                "treatment": "mitigate",
            }
        )

    out = get_out()
    ciso = out / "ciso-assistant"
    _write_csv(ciso / "assets.csv", CISO_ASSET_HEADER, asset_csv)
    _write_csv(ciso / "applied_controls.csv", CISO_CONTROL_HEADER, controls)
    _write_csv(ciso / "evidences.csv", CISO_EVIDENCE_HEADER, evidence_csv)
    _write_csv(ciso / "findings.csv", CISO_FINDING_HEADER, finding_csv)
    _write_csv(ciso / "vulnerabilities.csv", CISO_VULN_HEADER, vuln_csv)
    _write_semicolon_csv(ciso / "risk_scenarios.csv", CISO_RISK_HEADER, risk_csv)

    rr_assets = [
        {
            "ref_id": r.get("ref_id"),
            "name": r.get("name"),
            "description": r.get("description"),
            "asset_type": asset_type_for_name(r.get("name") or "", str(r.get("asset_type") or "SP")),
            "domain": r.get("domain") or "default",
            "labels": r.get("labels") or [],
            "source": r.get("source"),
        }
        for r in assets
    ]
    rr_incidents = []
    seen_inc: set[str] = set()
    for row in incidents_in:
        key = str(row.get("ref_id"))
        if key in seen_inc:
            continue
        seen_inc.add(key)
        rr_incidents.append(
            {
                "ref_id": row.get("ref_id"),
                "title": row.get("name"),
                "description": row.get("description"),
                "severity": normalize_severity(row.get("severity")),
                "status": row.get("status") or "open",
                "related_assets": row.get("related_assets") or [],
                "source": row.get("source"),
            }
        )
    for row in findings:
        sev = normalize_severity(row.get("severity"))
        if sev not in {"high", "critical"}:
            continue
        key = f"INC-{row.get('ref_id')}"
        if key in seen_inc:
            continue
        seen_inc.add(key)
        rr_incidents.append(
            {
                "ref_id": key,
                "title": row.get("name"),
                "description": row.get("description"),
                "severity": sev,
                "status": "open",
                "related_assets": row.get("related_assets") or [],
                "source": row.get("source"),
            }
        )
    rr_evidence = [
        {
            "name": r.get("name"),
            "description": r.get("description"),
            "source": r.get("source"),
            "ref_id": r.get("ref_id"),
        }
        for r in evidence_rows
    ]
    rr_risks = []
    for csv_row, src in hc_pairs:
        sev = str(csv_row.get("severity") or "high")
        likelihood, impact = severity_to_riskready(sev)
        rr_risks.append(
            {
                "ref_id": f"RSK-{csv_row.get('ref_id')}",
                "name": csv_row.get("name"),
                "description": csv_row.get("description"),
                "severity": sev,
                "likelihood": likelihood,
                "impact": impact,
                "assets": src.get("related_assets") or [],
                "treatment": "mitigate",
                "note": "Review-only. Not uploaded by push_riskready.sh.",
            }
        )

    rr = out / "riskready"
    write_json(rr / "assets.json", rr_assets)
    write_json(rr / "incidents.json", rr_incidents)
    write_json(rr / "evidence.json", rr_evidence)
    write_json(rr / "risks_proposed.json", rr_risks)

    ocsf_items = []
    ocsf_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for row in finding_csv:
        sev = row["severity"]
        ocsf_items.append(
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "category_uid": 2,
                "category_name": "Findings",
                "activity_id": 1,
                "activity_name": "Create",
                "time": ocsf_time,
                "severity_id": ocsf_severity_id(sev),
                "severity": sev.capitalize(),
                "finding_info": {
                    "uid": row["ref_id"],
                    "title": row["name"],
                    "desc": row["description"],
                },
                "compliance": {"status": "Non-Compliant"},
                "metadata": {
                    "product": {
                        "name": "grc-collector-pack",
                        "vendor_name": "GRC Collector",
                    }
                },
                "unmapped": {"ref_id": row["ref_id"]},
            }
        )
    write_json(
        out / "ocsf" / "compliance_findings.json",
        {
            "class_uid": 2003,
            "class_name": "Compliance Finding",
            "items": ocsf_items,
        },
    )

    canon_files = sorted((out / "canonical").glob("*.jsonl"))
    summary = {
        "assets": len(asset_csv),
        "findings": len(finding_csv),
        "evidence": len(evidence_csv),
        "incidents": len(rr_incidents),
        "vulnerabilities": len(vuln_csv),
        "risks_proposed": len(rr_risks),
        "applied_controls": len(controls),
        "canonical_rows": len(rows),
        "sensors_canonical": len(canon_files),
    }
    write_json(out / "summary.json", summary)
    write_text(
        out / "evidence" / "loader.md",
        "# Loader evidence\n\n"
        + "\n".join(f"- {k}: {v}" for k, v in summary.items())
        + "\n",
    )
    print(f"loader: {summary}")
    return summary


def main() -> None:
    run_loader()


if __name__ == "__main__":
    main()
