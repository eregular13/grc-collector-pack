"""Append-only POA&M ID ledger. Offline, persistent, never auto-closes.

Fingerprint::

    fp_v1 = sha256("v1|" + source_family + "|" + weakness_key + "|" + asset_key)

``asset_key`` is ASSET ID + PORT (see ``shared.asset_key.asset_key``), not the
lower-cased name. IDs are ``EGP-`` + first 10 hex of fp_v1, upper-cased.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from copy import deepcopy
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from shared.asset_key import (
    asset_host,
    asset_key,
    display_asset,
    legacy_name_asset_key,
    normalize_weakness_name,
)
from shared.finding_types import extra_dict
from shared.io_util import in_dir, out_dir
from shared.kev import (
    collect_cves,
    effective_due,
    fedramp_risk_for_col_r,
    join_kev,
    kev_overdue_on_detection,
    template_due_date,
    KevCatalog,
)
from shared.poam_fields import _to_date
from shared.scan_time import NOT_RECORDED, artifact_detection, merge_detection
from shared.schema import PREFIX, ciso_finding_severity

LEDGER_IN_REL = Path("poam") / "poam-ledger.json"
LEDGER_OUT_REL = Path("poam") / "poam-ledger.json"
OVERRIDES_REL = Path("poam") / "overrides.csv"

TRACKED_FIELDS = (
    "asset_key",
    "current_scanner_rating",
    "kev_cves",
    "kev_due",
    "vendor_dependency",
    "last_vendor_checkin",
    "vendor_product",
    "point_of_contact",
    "remediation_plan",
)

REOPEN_SUFFIX = re.compile(r"-R(\d+)$")
LEDGER_CHAIN_BROKEN = "LEDGER_CHAIN_BROKEN"
LEDGER_LOST = "LEDGER_LOST"


def source_family(rec: dict[str, Any]) -> str:
    src = str(rec.get("source") or "").strip()
    if src in PREFIX:
        return src
    return src or "unknown"


def _tool_tag(rec: dict[str, Any]) -> str:
    extra = extra_dict(rec)
    tool = str(extra.get("tool") or extra.get("scanner") or "").strip().lower()
    if tool:
        return tool
    labels = {str(x).lower() for x in (rec.get("labels") or [])}
    for known in (
        "nessus",
        "trivy",
        "nuclei",
        "nikto",
        "sarif",
        "prowler",
        "greenbone",
        "testssl",
    ):
        if known in labels:
            return known
    return {
        "vuln-scan": "vuln",
        "cloud-prowler": "prowler",
        "inventory-nmap": "nmap",
        "code-secrets": "sast",
        "k8s-kubescape": "k8s",
        "host-wazuh": "wazuh",
        "identity-ad": "ad",
        "easm": "easm",
        "saas-idp": "saas",
    }.get(source_family(rec), source_family(rec))


def weakness_key(rec: dict[str, Any]) -> str:
    """Scanner unique vulnerability reference, then CVE-as-id, then name."""
    extra = extra_dict(rec)
    scanner_id = ""
    for key in ("id", "rule", "check_id"):
        val = str(extra.get(key) or "").strip()
        if val:
            scanner_id = val
            break
    tool = _tool_tag(rec)
    if scanner_id:
        return f"{tool}:{scanner_id}"
    cves = collect_cves(rec)
    extra_cve = str(extra.get("cve") or "").strip()
    if extra_cve and cves:
        return f"cve:{cves[0]}"
    name = normalize_weakness_name(str(rec.get("name") or rec.get("ref_id") or "finding"))
    return f"name:{name}"


def fp_v1(rec: dict[str, Any], *, asset_key_fn=asset_key) -> str:
    payload = "v1|" + source_family(rec) + "|" + weakness_key(rec) + "|" + asset_key_fn(rec)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def assign_poam_id(fp: str, used: dict[str, str]) -> str:
    """EGP- + first 10 hex, upper-cased. Collision with a different fp → 12 hex."""
    short = "EGP-" + fp[:10].upper()
    holder = used.get(short)
    if holder is None or holder == fp:
        return short
    return "EGP-" + fp[:12].upper()


def next_reopen_id(base_id: str, existing: set[str]) -> str:
    core = REOPEN_SUFFIX.sub("", base_id)
    n = 1
    while f"{core}-R{n}" in existing:
        n += 1
    return f"{core}-R{n}"


def detection_time(rec: dict[str, Any], run_date: date | None = None) -> tuple[date | None, str]:
    """Artifact scan timestamp only. Never the pack run date or collected_at."""
    del run_date
    detected, basis, _tz = artifact_detection(rec)
    return detected, basis


def fan_out_instances(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """One instance per asset. Multi-asset records must not collapse."""
    out: list[dict[str, Any]] = []
    for rec in findings:
        assets = [a for a in (rec.get("assets") or []) if str(a).strip()]
        if len(assets) <= 1:
            out.append(rec)
            continue
        for asset in assets:
            clone = dict(rec)
            clone["assets"] = [asset]
            extra = dict(extra_dict(rec))
            clone["extra"] = extra
            out.append(clone)
    return out


def payload_sha256(doc: dict[str, Any]) -> str:
    body = {
        "items": doc.get("items") or {},
        "closed": doc.get("closed") or [],
        "events": doc.get("events") or [],
        "fp_migrations": doc.get("fp_migrations") or [],
    }
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def empty_ledger() -> dict[str, Any]:
    return {
        "version": 1,
        "prev_sha256": "",
        "sha256": "",
        "warnings": [],
        "items": {},
        "closed": [],
        "events": [],
        "fp_migrations": [],
    }


def load_ledger_file(path: Path) -> tuple[dict[str, Any], list[str]]:
    if not path.is_file():
        return empty_ledger(), [LEDGER_LOST]
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return empty_ledger(), [LEDGER_CHAIN_BROKEN]
    if not isinstance(doc, dict):
        return empty_ledger(), [LEDGER_CHAIN_BROKEN]
    warnings: list[str] = []
    stored = str(doc.get("sha256") or "")
    computed = payload_sha256(doc)
    if stored and stored != computed:
        warnings.append(LEDGER_CHAIN_BROKEN)
    doc.setdefault("items", {})
    doc.setdefault("closed", [])
    doc.setdefault("events", [])
    doc.setdefault("fp_migrations", [])
    doc.setdefault("warnings", [])
    return doc, warnings


def load_overrides(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    out: dict[str, dict[str, str]] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            poam_id = str(row.get("poam_id") or "").strip()
            if poam_id:
                out[poam_id] = {k: (v if v is not None else "") for k, v in row.items()}
    return out


def _used_ids(ledger: dict[str, Any]) -> dict[str, str]:
    used: dict[str, str] = {}
    for fp, item in (ledger.get("items") or {}).items():
        pid = str(item.get("poam_id") or "")
        if pid:
            used[pid] = fp
    for item in ledger.get("closed") or []:
        pid = str(item.get("poam_id") or "")
        if pid:
            used[pid] = str(item.get("fp") or "")
    return used


def _existing_id_set(ledger: dict[str, Any]) -> set[str]:
    return set(_used_ids(ledger))


def _event(run_iso: str, fp: str, poam_id: str, kind: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "at": run_iso,
        "fp": fp,
        "poam_id": poam_id,
        "kind": kind,
        "detail": detail or {},
    }


def _iso_date(raw: Any) -> str:
    got = _to_date(raw)
    return got.isoformat() if got else ""


def _new_item(
    rec: dict[str, Any],
    *,
    fp: str,
    poam_id: str,
    run_date: date,
    run_iso: str,
    kev: dict[str, Any],
    catalog_sha: str,
) -> dict[str, Any]:
    detected, basis = detection_time(rec, run_date)
    rating = fedramp_risk_for_col_r(rec.get("severity"))
    scanner = ciso_finding_severity(rec.get("severity"))
    kev_due = kev.get("kev_due")
    if detected is not None:
        tmpl = template_due_date(detected, rec.get("severity"))
        eff = effective_due(tmpl, kev_due)
        template_s = tmpl.isoformat()
        effective_s = (eff or tmpl).isoformat()
        odd = detected.isoformat()
    else:
        tmpl = None
        template_s = ""
        effective_s = kev_due.isoformat() if kev_due else ""
        odd = NOT_RECORDED
        basis = "not_recorded"
    return {
        "poam_id": poam_id,
        "fp": fp,
        "source_family": source_family(rec),
        "weakness_key": weakness_key(rec),
        "asset_key": asset_key(rec),
        "display_asset": display_asset(rec),
        "cves": list(kev.get("cves") or []),
        "kev_cves": list(kev.get("kev_cves") or []),
        "kev_due": kev_due.isoformat() if kev_due else "",
        "kev_catalog_sha256": catalog_sha,
        "kev_tracking": kev.get("tracking") or "",
        "kev_comments": list(kev.get("comments") or []),
        "first_seen": run_iso,
        "last_seen": run_iso,
        "original_detection_date": odd,
        "detection_date_basis": basis,
        "original_risk_rating": rating,
        "current_scanner_rating": scanner,
        "scanner_critical": scanner == "critical",
        "status": "open",
        "status_date": run_date.isoformat(),
        "closed_date": "",
        "closure_evidence": [],
        "vendor_dependency": "",
        "vd_source": "",
        "last_vendor_checkin": "",
        "vendor_product": "",
        "point_of_contact": "",
        "remediation_plan": "",
        "prior_poam_id": "",
        "missed_covered_runs": 0,
        "missed_dates": [],
        "effective_due": effective_s,
        "template_due": template_s,
        "kev_overdue_on_detection": kev_overdue_on_detection(detected, kev_due),
        "name": str(rec.get("name") or rec.get("ref_id") or ""),
        "description": str(rec.get("description") or rec.get("name") or ""),
        "ref_id": str(rec.get("ref_id") or ""),
        "severity": scanner,
    }


def _tracked_snapshot(item: dict[str, Any]) -> dict[str, Any]:
    return {k: item.get(k) for k in TRACKED_FIELDS}


def _apply_override(item: dict[str, Any], override: dict[str, str], run_date: date) -> list[str]:
    changed: list[str] = []
    mapping = {
        "vendor_dependency": "vendor_dependency",
        "last_vendor_checkin": "last_vendor_checkin",
        "vendor_product": "vendor_product",
        "point_of_contact": "point_of_contact",
        "remediation_plan": "remediation_plan",
    }
    for src, dest in mapping.items():
        if src in override and override[src] != "" and override[src] != item.get(dest):
            item[dest] = override[src]
            changed.append(dest)
    return changed


def _migrate_if_needed(rec: dict[str, Any], ledger: dict[str, Any], run_iso: str) -> str:
    new_fp = fp_v1(rec)
    items: dict[str, Any] = ledger["items"]
    if new_fp in items:
        return new_fp
    old_fp = fp_v1(rec, asset_key_fn=legacy_name_asset_key)
    mapped = None
    if old_fp in items:
        mapped = old_fp
    else:
        for row in ledger.get("fp_migrations") or []:
            if row.get("from") == old_fp and row.get("to"):
                mapped = old_fp
                break
    if mapped and mapped in items:
        item = items.pop(mapped)
        kept_id = item.get("poam_id")
        kept_date = item.get("original_detection_date")
        if new_fp in items:
            other = items[new_fp]
            d1 = _to_date(kept_date)
            d2 = _to_date(other.get("original_detection_date"))
            if d1 and (not d2 or d1 < d2):
                other["original_detection_date"] = kept_date
                other["poam_id"] = kept_id
            item = other
        else:
            item["fp"] = new_fp
            item["asset_key"] = asset_key(rec)
            items[new_fp] = item
        ledger["fp_migrations"].append(
            {
                "from": mapped,
                "to": new_fp,
                "poam_id": item.get("poam_id"),
                "original_detection_date": item.get("original_detection_date"),
                "reason": "name_to_asset_id_port",
            }
        )
        ledger["events"].append(
            _event(run_iso, new_fp, str(item.get("poam_id") or ""), "migrated", {"from": mapped})
        )
        return new_fp
    return new_fp


def build_coverage(instances: Iterable[dict[str, Any]]) -> dict[str, set[str]]:
    cov: dict[str, set[str]] = {}
    for rec in instances:
        fam = source_family(rec)
        bucket = cov.setdefault(fam, set())
        bucket.add(asset_key(rec))
        host = asset_host(rec)
        if host:
            bucket.add(host)
    return cov


def is_covered(item: dict[str, Any], coverage: dict[str, set[str]]) -> bool:
    fam = str(item.get("source_family") or "")
    if fam not in coverage:
        return False
    keys = coverage[fam]
    ak = str(item.get("asset_key") or "")
    host = ak.split(":")[0] if ak else ""
    return ak in keys or (host in keys if host else False)


def apply_ledger(
    findings: list[dict[str, Any]],
    *,
    catalog: KevCatalog,
    run_at: datetime | None = None,
    ledger_in: dict[str, Any] | None = None,
    overrides: dict[str, dict[str, str]] | None = None,
    prior_existed: bool = True,
) -> dict[str, Any]:
    """Apply one run to the ledger. Never auto-closes."""
    clock = run_at or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    run_date = clock.date()
    run_iso = clock.strftime("%Y-%m-%dT%H:%M:%SZ")
    ledger = deepcopy(ledger_in) if ledger_in is not None else empty_ledger()
    ledger.setdefault("items", {})
    ledger.setdefault("closed", [])
    ledger.setdefault("events", [])
    ledger.setdefault("fp_migrations", [])
    warnings = list(ledger.get("warnings") or [])
    if not prior_existed:
        warnings.append(LEDGER_LOST)
    overrides = overrides or {}
    instances = fan_out_instances(findings)
    coverage = build_coverage(instances)
    seen: set[str] = set()
    catalog_sha = catalog.sha256 if catalog.kev_evaluated else ""

    for rec in instances:
        fp = _migrate_if_needed(rec, ledger, run_iso)
        seen.add(fp)
        cves = collect_cves(rec)
        kev = join_kev(cves, catalog)
        used = _used_ids(ledger)
        item = ledger["items"].get(fp)
        if item is None:
            poam_id = assign_poam_id(fp, used)
            used[poam_id] = fp
            item = _new_item(
                rec,
                fp=fp,
                poam_id=poam_id,
                run_date=run_date,
                run_iso=run_iso,
                kev=kev,
                catalog_sha=catalog_sha,
            )
            if not prior_existed:
                item["detection_date_basis"] = f"{item['detection_date_basis']}+ledger_lost"
            ledger["items"][fp] = item
            ledger["events"].append(_event(run_iso, fp, poam_id, "created"))
        else:
            status = str(item.get("status") or "open")
            if status == "closed":
                closed_copy = deepcopy(item)
                ledger["closed"].append(closed_copy)
                new_id = next_reopen_id(str(item.get("poam_id") or ""), _existing_id_set(ledger) | {closed_copy.get("poam_id", "")})
                detected, basis = detection_time(rec)
                fresh = _new_item(
                    rec,
                    fp=fp,
                    poam_id=new_id,
                    run_date=run_date,
                    run_iso=run_iso,
                    kev=kev,
                    catalog_sha=catalog_sha,
                )
                fresh["status"] = "reopened"
                fresh["prior_poam_id"] = str(item.get("poam_id") or "")
                fresh["original_detection_date"] = (
                    detected.isoformat() if detected is not None else NOT_RECORDED
                )
                fresh["detection_date_basis"] = basis if detected is not None else "not_recorded"
                fresh["kev_comments"] = list(fresh.get("kev_comments") or []) + [
                    f"Reopened from {item.get('poam_id')}; closed row remains on Closed."
                ]
                ledger["items"][fp] = fresh
                ledger["events"].append(
                    _event(run_iso, fp, new_id, "reopened", {"prior_poam_id": item.get("poam_id")})
                )
                item = fresh
            else:
                before = _tracked_snapshot(item)
                item["last_seen"] = run_iso
                item["missed_covered_runs"] = 0
                item["current_scanner_rating"] = ciso_finding_severity(rec.get("severity"))
                item["scanner_critical"] = item["current_scanner_rating"] == "critical"
                item["cves"] = list(kev.get("cves") or [])
                item["kev_cves"] = list(kev.get("kev_cves") or [])
                item["kev_due"] = kev["kev_due"].isoformat() if kev.get("kev_due") else ""
                item["kev_catalog_sha256"] = catalog_sha
                item["kev_tracking"] = kev.get("tracking") or ""
                item["kev_comments"] = list(kev.get("comments") or [])
                item["asset_key"] = asset_key(rec)
                item["display_asset"] = display_asset(rec)
                item["name"] = str(rec.get("name") or item.get("name") or "")
                item["description"] = str(rec.get("description") or item.get("description") or "")
                incoming, incoming_basis = detection_time(rec)
                item["original_detection_date"] = merge_detection(
                    str(item.get("original_detection_date") or NOT_RECORDED),
                    incoming,
                )
                if incoming is not None and item["original_detection_date"] != NOT_RECORDED:
                    if item.get("detection_date_basis") in {"", "not_recorded", "run", "collected_at"}:
                        item["detection_date_basis"] = incoming_basis
                detected = _to_date(item.get("original_detection_date"))
                if detected is not None:
                    tmpl = template_due_date(detected, rec.get("severity"))
                    item["template_due"] = tmpl.isoformat()
                    item["effective_due"] = (
                        effective_due(tmpl, kev.get("kev_due")) or tmpl
                    ).isoformat()
                else:
                    item["template_due"] = ""
                    item["effective_due"] = (
                        kev.get("kev_due").isoformat() if kev.get("kev_due") else ""
                    )
                item["kev_overdue_on_detection"] = kev_overdue_on_detection(
                    detected, kev.get("kev_due")
                )
                if status == "pending_verification":
                    item["status"] = "open"
                    item["status_date"] = run_date.isoformat()
                    ledger["events"].append(
                        _event(run_iso, fp, str(item.get("poam_id") or ""), "seen_from_pending")
                    )
                after = _tracked_snapshot(item)
                if after != before:
                    item["status_date"] = run_date.isoformat()
                    ledger["events"].append(
                        _event(
                            run_iso,
                            fp,
                            str(item.get("poam_id") or ""),
                            "field_changed",
                            {"before": before, "after": after},
                        )
                    )
                else:
                    ledger["events"].append(
                        _event(run_iso, fp, str(item.get("poam_id") or ""), "reobserved")
                    )

        ov = overrides.get(str(item.get("poam_id") or ""))
        if ov:
            changed = _apply_override(item, ov, run_date)
            if str(ov.get("status") or "").strip().lower() == "closed" and ov.get("evidence_ref"):
                closed_on = _to_date(ov.get("status_date") or ov.get("closed_date")) or run_date
                item["status"] = "closed"
                item["closed_date"] = closed_on.isoformat()
                item["status_date"] = closed_on.isoformat()
                ev = list(item.get("closure_evidence") or [])
                ev.append(ov.get("evidence_ref"))
                item["closure_evidence"] = ev
                ledger["events"].append(
                    _event(run_iso, fp, str(item["poam_id"]), "closed", {"evidence_ref": ov.get("evidence_ref")})
                )
            elif changed:
                item["status_date"] = run_date.isoformat()
                ledger["events"].append(
                    _event(run_iso, fp, str(item["poam_id"]), "field_changed", {"override": changed})
                )

    for fp, item in list(ledger["items"].items()):
        if fp in seen:
            continue
        if str(item.get("status") or "") == "closed":
            continue
        if str(item.get("vendor_dependency") or "").strip().lower() == "yes":
            continue
        if str(item.get("operational_requirement") or "").strip().lower() in {"yes", "or"}:
            continue
        if not is_covered(item, coverage):
            ledger["events"].append(
                _event(run_iso, fp, str(item.get("poam_id") or ""), "not_observed_no_coverage")
            )
            continue
        missed = int(item.get("missed_covered_runs") or 0) + 1
        item["missed_covered_runs"] = missed
        dates = list(item.get("missed_dates") or [])
        dates.append(run_date.isoformat())
        item["missed_dates"] = dates
        if missed >= 2 and str(item.get("status") or "") != "pending_verification":
            item["status"] = "pending_verification"
            item["status_date"] = run_date.isoformat()
            ledger["events"].append(
                _event(run_iso, fp, str(item.get("poam_id") or ""), "pending_verification", {"dates": dates})
            )

    ledger["warnings"] = sorted(set(warnings + list(catalog.warnings)))
    if LEDGER_CHAIN_BROKEN in (ledger_in or {}).get("warnings", []):
        ledger["warnings"] = sorted(set(ledger["warnings"] + [LEDGER_CHAIN_BROKEN]))
    ledger["run_at"] = run_iso
    ledger["prev_sha256"] = str((ledger_in or {}).get("sha256") or "")
    ledger["sha256"] = payload_sha256(ledger)
    return ledger


def pending_comment(item: dict[str, Any]) -> str:
    dates = ", ".join(item.get("missed_dates") or [])
    return (
        f"Not detected in rescans {dates}; "
        "closure requires evidence + 3PAO verification"
    )


def run_ledger(
    findings: list[dict[str, Any]],
    catalog: KevCatalog,
    *,
    run_at: datetime | None = None,
    in_root: Path | None = None,
    out_root: Path | None = None,
) -> dict[str, Any]:
    """Load in/poam/poam-ledger.json, apply, write out/poam/poam-ledger.json."""
    src = (in_root or in_dir()) / LEDGER_IN_REL
    existed = src.is_file()
    prior, warnings = load_ledger_file(src)
    if warnings:
        prior.setdefault("warnings", [])
        prior["warnings"] = sorted(set(list(prior["warnings"]) + warnings))
    overrides = load_overrides((in_root or in_dir()) / OVERRIDES_REL)
    ledger = apply_ledger(
        findings,
        catalog=catalog,
        run_at=run_at,
        ledger_in=prior,
        overrides=overrides,
        prior_existed=existed,
    )
    dest = (out_root or out_dir()) / LEDGER_OUT_REL
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(ledger, indent=2, default=str) + "\n", encoding="utf-8")
    return ledger
