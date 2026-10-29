#!/usr/bin/env python3
"""Parse Nuclei JSONL, Trivy JSON, Grype JSON, Greenbone XML/CSV/JSON, Nikto, Nessus XML, sslscan, or SARIF.

Parse-only. Does not run nuclei, nikto, Nessus, or sslscan, and does not call a Nessus API.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shared.asset_ids import stamp_ids
from shared.greenbone import cvss_band, parse_greenbone
from shared.grype import grype_host_target, grype_ids, grype_scan_time, grype_target, is_grype, iter_grype_matches
from shared.io_util import iso_now, read_json, read_jsonl, read_text, run_collector
from shared.nessus import parse_nessus
from shared.nikto import is_interesting as nikto_interesting
from shared.nikto import nikto_severity
from shared.nikto import parse_nikto, row_cves as nikto_row_cves
from shared.sslscan import parse_sslscan
from shared.sarif import iter_sarif_results, load_sarif
from shared.schema import canon_severity, make_record, make_ref
from shared.testssl import human_title as testssl_human_title
from shared.testssl import is_testssl, iter_testssl_findings
from shared.vendor_dependency import no_fix_from_scanner_tokens

SOURCE = "vuln-scan"
LABELS = ["vuln", "scanner"]


def _is_nuclei_row(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    if row.get("template-id") or row.get("template_id") or row.get("templateID"):
        return True
    return isinstance(row.get("info"), dict) and bool(
        row["info"].get("name") or row["info"].get("severity")
    )


def _nuclei_from_payload(payload: Any) -> list[dict[str, Any]]:
    if _is_nuclei_row(payload):
        return [payload]  # type: ignore[list-item]
    if isinstance(payload, list):
        if is_testssl(payload):
            return []
        return [r for r in payload if _is_nuclei_row(r)]
    if not isinstance(payload, dict):
        return []
    for key in ("results", "matches", "findings", "nuclei"):
        raw = payload.get(key)
        if isinstance(raw, list):
            return [r for r in raw if _is_nuclei_row(r)]
    return []


def _nuclei_rows(path: Path) -> list[dict[str, Any]]:
    text = read_text(path).lstrip("\ufeff").strip()
    if not text:
        return []
    if path.suffix.lower() == ".jsonl" or "nuclei" in path.name.lower() or (
        text[0] == "{" and "\n{" in text
    ):
        rows = [r for r in read_jsonl(path) if _is_nuclei_row(r)]
        if rows:
            return rows
    try:
        payload = read_json(path)
    except Exception:
        return [r for r in read_jsonl(path) if _is_nuclei_row(r)]
    return _nuclei_from_payload(payload)


def _is_trivy_k8s(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("ClusterName") is not None or payload.get("cluster_name") is not None:
        if "Resources" in payload or "resources" in payload:
            return True
    resources = payload.get("Resources") or payload.get("resources")
    if not isinstance(resources, list):
        return False
    for res in resources:
        if not isinstance(res, dict):
            continue
        if isinstance(res.get("Results") or res.get("results"), list):
            return True
        if res.get("Kind") and (res.get("Name") or res.get("Namespace") is not None):
            return True
    return False


def _is_trivy(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("SchemaVersion") is not None or payload.get("ArtifactName") or payload.get("ArtifactType"):
        return True
    # Trivy uses capital Results. Lowercase results is Greenbone / other tools.
    if isinstance(payload.get("Results"), list):
        return True
    return _is_trivy_k8s(payload)


def _trivy_result_blocks(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    blocks: list[dict[str, Any]] = []
    for result in payload.get("Results") or payload.get("results") or []:
        if isinstance(result, dict):
            blocks.append(result)
    for res in payload.get("Resources") or payload.get("resources") or []:
        if not isinstance(res, dict):
            continue
        ns = str(res.get("Namespace") or "")
        kind = str(res.get("Kind") or "")
        rname = str(res.get("Name") or "")
        inner = res.get("Results") or res.get("results") or []
        if not isinstance(inner, list):
            continue
        for result in inner:
            if not isinstance(result, dict):
                continue
            extra = dict(result)
            extra["_k8s"] = {"namespace": ns, "kind": kind, "name": rname}
            blocks.append(extra)
    return blocks


def _trivy_ids(payload: dict[str, Any]) -> dict[str, Any]:
    meta = payload.get("Metadata") if isinstance(payload.get("Metadata"), dict) else {}
    tags = meta.get("RepoTags") if isinstance(meta.get("RepoTags"), list) else []
    digests = meta.get("RepoDigests") if isinstance(meta.get("RepoDigests"), list) else []
    image_ref = str(payload.get("ArtifactName") or (tags[0] if tags else "") or "").strip()
    return {
        "image_digest": [str(x) for x in digests if x],
        "image_id": str(meta.get("ImageID") or "").strip(),
        "artifact_id": str(payload.get("ArtifactID") or "").strip(),
        "image_ref": image_ref,
    }


def _image_scoped_target(payload: dict[str, Any], target: str) -> str:
    """Qualify a container-image Result Target that does not name the image.

    Trivy names language/binary Results generically ("Node.js", "Python",
    "usr/local/bin/gosu"). Used bare as the asset name, those merge findings from
    different images into one asset. OS-package Targets already start with the
    image name ("repo/app:1.0 (debian 12)") and stay unchanged, as do
    filesystem/repository scans.
    """
    if str(payload.get("ArtifactType") or "").strip().lower() != "container_image":
        return target
    artifact = str(payload.get("ArtifactName") or "").strip()
    if not artifact or not target or target.startswith(artifact):
        return target
    return f"{artifact} :: {target}"


def _trivy_title(vuln: dict[str, Any], vid: str, pkg: str, is_cve: bool) -> str:
    """Finding name that always carries PkgName (fixstack rollup groups by it).

    Trivy titles for Go stdlib CVEs name a sub-package ("net/url: ..."), not the
    PkgName ("stdlib"). Without "<id> in <PkgName>", rollup.py reads the
    sub-package as the package and splits one package into many POA&M rows.
    """
    title = str(vuln.get("Title") or vid)
    if pkg and pkg.lower() not in title.lower():
        return f"{vid} in {pkg}" if is_cve else f"{title} ({pkg})"
    return title


def _trivy_distinct_targets(payload: dict[str, Any]) -> list[str]:
    """Unique scan Targets in document order (multi-result Trivy reports)."""
    seen: set[str] = set()
    out: list[str] = []
    for result in _trivy_result_blocks(payload):
        if not isinstance(result, dict):
            continue
        k8s = result.get("_k8s") if isinstance(result.get("_k8s"), dict) else {}
        target = str(
            result.get("Target") or result.get("target") or k8s.get("name") or "image"
        ).strip() or "image"
        if k8s.get("namespace"):
            target = f"{k8s.get('namespace')}/{target}"
        elif not k8s:
            target = _image_scoped_target(payload, target)
        key = target.lower()
        if key not in seen:
            seen.add(key)
            out.append(target)
    return out


def _trivy_ids_for_target(payload: dict[str, Any], target: str) -> dict[str, Any]:
    """Per-Target identity so multi-Target scans keep one asset per Target.

    A container scan with an OS Target plus language/binary Targets shares one
    digest/ImageID. Stamped on every Target, the shared digest merges them into
    one asset and the other Targets' findings point at assets that were never
    written. With more than one Target, image_ref is the Target and the shared
    digest/IDs are dropped. Single-Target scans keep their ids unchanged, so
    their asset keys and POA&M IDs do not move.
    """
    ids = dict(_trivy_ids(payload))
    t = (target or "").strip() or "image"
    if len(_trivy_distinct_targets(payload)) > 1:
        ids["image_ref"] = t
        ids["image_digest"] = []
        ids["image_id"] = ""
        ids["artifact_id"] = ""
    return ids


def _trivy_rows(payload: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not isinstance(payload, dict):
        return rows
    for result in _trivy_result_blocks(payload):
        k8s = result.get("_k8s") if isinstance(result.get("_k8s"), dict) else {}
        target = str(
            result.get("Target")
            or result.get("target")
            or k8s.get("name")
            or "image"
        )
        if k8s.get("namespace"):
            target = f"{k8s.get('namespace')}/{target}"
        elif not k8s:
            target = _image_scoped_target(payload, target)
        ids = _trivy_ids_for_target(payload, target)
        for vuln in result.get("Vulnerabilities") or result.get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                vuln = {**vuln, "_target": target, "_class": "vuln", "_ids": ids}
                rows.append(vuln)
        for secret in result.get("Secrets") or result.get("secrets") or []:
            if not isinstance(secret, dict):
                continue
            rows.append(
                {
                    "VulnerabilityID": str(secret.get("RuleID") or secret.get("Title") or "secret"),
                    "Title": str(secret.get("Title") or secret.get("RuleID") or "secret"),
                    "Description": str(secret.get("Category") or secret.get("Match") or secret.get("Title") or "secret"),
                    "Severity": secret.get("Severity") or "high",
                    "PkgName": "",
                    "_target": target,
                    "_class": "secret",
                    "_ids": ids,
                }
            )
        for mis in result.get("Misconfigurations") or result.get("misconfigurations") or []:
            if not isinstance(mis, dict):
                continue
            if str(mis.get("Status") or mis.get("status") or "").upper() not in {"FAIL", "FAILED"}:
                continue
            rows.append(
                {
                    "VulnerabilityID": str(mis.get("ID") or mis.get("AVDID") or mis.get("Title") or "misconfig"),
                    "Title": str(mis.get("Title") or mis.get("ID") or "misconfiguration"),
                    "Description": str(mis.get("Message") or mis.get("Description") or mis.get("Title") or "misconfig"),
                    "Severity": mis.get("Severity") or "medium",
                    "PkgName": "",
                    "_target": target,
                    "_class": "misconfig",
                    "_ids": ids,
                }
            )
    return rows


def _greenbone_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return [r for r in payload["results"] if isinstance(r, dict) and r.get("nvt")]
    return []


def _testssl_ref(row: dict[str, Any], host: str) -> str:
    vid = str(row.get("cve") or row.get("id") or "testssl")
    ip = str(row.get("ip") or "").split("/")[0].strip()
    if ip and ip not in {host, ""}:
        return f"{vid}-{host}-{ip}"
    return f"{vid}-{host}"


def _emit_testssl_row(row: dict[str, Any], host: str, now: str) -> dict:
    vid = str(row.get("cve") or row.get("id") or "testssl")
    extra_labels = [str(x) for x in (row.get("labels") or []) if x]
    return make_record(
        kind="finding",
        source=SOURCE,
        ref_id=make_ref(SOURCE, _testssl_ref(row, host)),
        name=testssl_human_title(str(row.get("id") or ""), str(row.get("finding") or vid)),
        description=str(row.get("finding") or row.get("cve") or vid),
        severity=canon_severity(row.get("severity") or "high"),
        category="vulnerability",
        assets=[host],
        labels=LABELS + ["testssl"] + extra_labels,
        collected_at=now,
        extra={
            "cve": row.get("cve") or "",
            "id": row.get("id") or "",
            "ip": row.get("ip") or "",
            **({"scan_time": str(row.get("scan_time"))} if row.get("scan_time") else {}),
        },
    )


def _no_fix_extra(*tokens: Any) -> dict[str, Any]:
    """Stamp solution_type/status plus no_fix_available when the scanner says so."""
    extra: dict[str, Any] = {}
    solution_type = str(tokens[0] or "").strip() if tokens else ""
    status = str(tokens[1] or "").strip() if len(tokens) > 1 else ""
    if solution_type:
        extra["solution_type"] = solution_type
    if status:
        extra["status"] = status
    if no_fix_from_scanner_tokens(solution_type, status):
        extra["no_fix_available"] = True
    return extra


def _greenbone_cves(row: dict[str, Any]) -> list[str]:
    raw = row.get("cves")
    if isinstance(raw, (list, tuple)):
        return [str(c).strip() for c in raw if str(c).strip()]
    joined = str(row.get("cve") or "").strip()
    return [part for part in joined.replace(",", " ").split() if part.upper().startswith("CVE")]


def _emit_greenbone_row(row: dict[str, Any], now: str) -> tuple[str, dict]:
    host = str(row.get("host") or "unknown")
    vid = str(row.get("oid") or row.get("name") or "openvas")
    port = str(row.get("port") or "")
    cves = _greenbone_cves(row)
    return host, make_record(
        kind="finding",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"{vid}-{host}-{port}"),
        name=str(row.get("name") or vid),
        description=str(row.get("description") or vid),
        severity=canon_severity(row.get("severity") or "medium"),
        category="vulnerability",
        assets=[host],
        labels=LABELS + ["greenbone"],
        collected_at=now,
        extra={
            "cve": " ".join(cves),
            "cves": cves,
            "id": vid,
            "rule": vid,
            "oid": vid,
            "port": port,
            "cvss": row.get("cvss") or "",
            "threat": row.get("threat") or "",
            **_no_fix_extra(row.get("solution_type")),
            **({"solution": str(row.get("solution"))} if row.get("solution") else {}),
            **({"scan_time": str(row.get("scan_time"))} if row.get("scan_time") else {}),
        },
    )


def _grype_records(payload: dict[str, Any], now: str, add_asset, stem: str = "") -> list[dict]:
    """Grype JSON: one finding per match on the scanned target (Trivy-shaped).

    Asset = the scan target (image/dir), not one per package. CVE rows key on
    ``cve:<id>`` + asset like Trivy CVE rows; non-CVE ids (GHSA without a
    related CVE) key on ``rule``. Structured CVEs: vulnerability.id and
    relatedVulnerabilities[].id only.
    """
    target = grype_host_target(payload, stem)
    ids = grype_ids(payload)
    scan_time = grype_scan_time(payload)
    out: list[dict] = []
    rows = iter_grype_matches(payload)
    if rows:
        add_asset(target, ids)
    for row in rows:
        vid, pkg, cves = row["vid"], row["pkg"], row["cves"]
        is_cve = vid.upper().startswith("CVE-")
        primary = vid.upper() if is_cve else (cves[0] if cves else "")
        extra: dict[str, Any] = {
            "cve": primary,
            "cves": cves,
            "pkg": pkg,
            "installed_version": row["version"],
            "pkg_type": row["pkg_type"],
            "class": "vuln",
            "tool": "grype",
        }
        if not primary:
            extra["rule"] = vid
            extra["check_id"] = vid
        elif not is_cve:
            extra["advisory"] = vid
        if row["fixed"]:
            extra["fixed_version_hint"] = row["fixed"]
        extra = stamp_ids(extra, **ids)
        extra.update(_no_fix_extra("", "will_not_fix" if row["fix_state"] == "wont-fix" else row["fix_state"]))
        if scan_time:
            extra["scan_time"] = scan_time
        shown = primary or vid
        name = f"{shown} in {pkg}" if pkg else shown
        out.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"grype-{vid}-{target}-{pkg}-{row['version']}"),
                name=name,
                description=row["description"] or name,
                severity=row["severity"] or "medium",
                category="vulnerability",
                assets=[target],
                labels=LABELS + ["grype"],
                collected_at=now,
                extra=extra,
            )
        )
    return out


def parse_file(path: Path) -> list[dict]:
    now = iso_now()
    records: list[dict] = []
    seen_assets: set[str] = set()

    def add_asset(name: str, ids: dict[str, Any] | None = None) -> None:
        key = name.lower()
        if key in seen_assets:
            return
        seen_assets.add(key)
        extra = stamp_ids({"asset_type": "PR"}, **(ids or {}))
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=f"Scanned target {name}",
                category="host",
                assets=[name],
                labels=LABELS,
                collected_at=now,
                extra=extra,
            )
        )

    sarif = load_sarif(path)
    if sarif:
        for row in iter_sarif_results(sarif):
            host = str(row.get("uri") or "unknown")
            ids = row.get("ids") if isinstance(row.get("ids"), dict) else {}
            add_asset(host, ids)
            rid = str(row.get("rule_id") or "sarif")
            extra = stamp_ids(
                {"rule": rid, "cve": rid if rid.upper().startswith("CVE") else ""},
                **ids,
            )
            if row.get("scan_time"):
                extra["scan_time"] = row.get("scan_time")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{rid}-{host}"),
                    name=str(row.get("message") or rid),
                    description=str(row.get("message") or rid),
                    severity=row.get("severity") or "medium",
                    category="vulnerability",
                    assets=[host],
                    labels=LABELS + ["sarif", str(row.get("tool") or "sarif").lower()],
                    collected_at=now,
                    extra=extra,
                )
            )
        return records

    try:
        peek = read_json(path)
    except Exception:
        peek = None
    if peek is not None and is_testssl(peek):
        testssl_at = ""
        if isinstance(peek, dict):
            testssl_at = str(peek.get("at") or "")
        for row in iter_testssl_findings(peek):
            host = str(row.get("host") or "unknown")
            if testssl_at and not row.get("scan_time"):
                row = {**row, "scan_time": testssl_at}
            add_asset(host)
            records.append(_emit_testssl_row(row, host, now))
        if records:
            return records

    sslscan = parse_sslscan(path)
    if sslscan is not None:
        for row in sslscan:
            host = str(row.get("host") or "unknown")
            add_asset(host)
            vid = str(row.get("id") or row.get("name") or "sslscan")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"sslscan-{vid}-{host}"),
                    name=str(row.get("name") or row.get("finding") or vid),
                    description=str(row.get("finding") or row.get("name") or vid),
                    severity=row.get("severity") or "high",
                    category="vulnerability",
                    assets=[host],
                    labels=LABELS + ["sslscan"],
                    collected_at=now,
                    extra={
                        "cve": row.get("cve") or "",
                        "id": vid,
                        "port": "443",
                        "service": "https",
                    },
                )
            )
        return records

    nikto = parse_nikto(path)
    if nikto is not None:
        for row in nikto:
            url = str(row.get("url") or "/")
            msg = str(row.get("msg") or "")
            rid = str(row.get("id") or "nikto")
            cves = nikto_row_cves(row)
            # A row that names a CVE is never header noise (ETag inode leak
            # rows carry CVE-2003-1418); dropping it lost the CVE silently.
            if not cves and not nikto_interesting(url, msg, rid):
                continue
            host = str(row.get("host") or "unknown")
            add_asset(host)
            extra = {"url": url, "id": rid}
            if cves:
                extra["cves"] = cves
                extra["cve"] = " ".join(cves)
            if row.get("scan_time"):
                extra["scan_time"] = row.get("scan_time")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"nikto-{rid}-{host}-{url}"),
                    name=f"Nikto: {msg or url}",
                    description=(
                        f"{msg} url={url} (Nikto file-drop; not a live HTTP probe)"
                    ),
                    severity=canon_severity(nikto_severity(url, msg, rid)),
                    category="exposure",
                    assets=[host],
                    labels=LABELS + ["nikto"],
                    collected_at=now,
                    extra=extra,
                )
            )
        return records

    nessus = parse_nessus(path)
    if nessus is not None:
        for row in nessus:
            host = str(row.get("host") or "unknown")
            ids = row.get("ids") if isinstance(row.get("ids"), dict) else {}
            add_asset(host, ids)
            plugin = str(row.get("plugin_id") or "nessus")
            port = str(row.get("port") or "")
            cves = [str(c).strip() for c in (row.get("cves") or []) if str(c).strip()]
            cwes = [str(c).strip() for c in (row.get("cwes") or []) if str(c).strip()]
            extra = stamp_ids(
                {
                    "port": port,
                    "service": row.get("service") or "",
                    "id": plugin,
                    "protocol": row.get("protocol") or "",
                    "id_quality": row.get("id_quality") or "",
                    "tool": "nessus",
                    "plugin_family": row.get("plugin_family") or "",
                    "cves": cves,
                    "cwes": cwes,
                },
                **ids,
            )
            if cwes:
                extra["cwe"] = " ".join(cwes)
            if row.get("scan_time"):
                extra["scan_time"] = row.get("scan_time")
            if cves:
                extra["cve"] = " ".join(cves)
            if row.get("solution"):
                extra["solution"] = str(row.get("solution"))
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"nessus-{plugin}-{host}-{port}"),
                    name=str(row.get("name") or plugin),
                    description=(
                        f"{row.get('description') or row.get('name')} "
                        "(Nessus file-drop; not a live scan)"
                    ),
                    severity=row.get("severity") or "high",
                    category="vulnerability",
                    assets=[host],
                    labels=LABELS + ["nessus"],
                    collected_at=now,
                    extra=extra,
                )
            )
        return records

    greenbone = parse_greenbone(path)
    if greenbone is not None:
        for row in greenbone:
            host, rec = _emit_greenbone_row(row, now)
            add_asset(host)
            records.append(rec)
        return records

    if peek is not None and is_grype(peek):
        return records + _grype_records(peek, now, add_asset, Path(path).stem)

    nuclei = _nuclei_rows(path)
    if nuclei:
        for row in nuclei:
            info = row.get("info") if isinstance(row.get("info"), dict) else {}
            tid = str(
                row.get("template-id")
                or row.get("template_id")
                or row.get("templateID")
                or info.get("name")
                or "nuclei"
            )
            sev = str(info.get("severity") or row.get("severity") or "medium").lower()
            if sev in {"info", "unknown"}:
                continue
            host = str(
                row.get("host")
                or row.get("matched-at")
                or row.get("matched_at")
                or row.get("url")
                or row.get("ip")
                or "unknown"
            )
            add_asset(host)
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{tid}-{host}"),
                    name=str(info.get("name") or tid),
                    description=str(info.get("description") or tid),
                    severity=sev,
                    category="vulnerability",
                    assets=[host],
                    labels=LABELS + ["nuclei"],
                    collected_at=now,
                    extra={
                        "cve": tid if tid.upper().startswith("CVE") else "",
                        "rule": tid,
                        "template_id": tid,
                        **(
                            {"scan_time": str(row.get("timestamp") or row.get("time"))}
                            if (row.get("timestamp") or row.get("time"))
                            else {}
                        ),
                    },
                )
            )
        return records

    try:
        payload = read_json(path)
    except Exception:
        return records

    # prior-unit PQ-1 preferred product insertion: collapse per (image,PkgName) here or keep
    # per-CVE for CISO vulns and roll on POA&M path (see scripts/fixstack/rollup.py).
    # prior-unit: mint assets for image/scan Targets (e.g. example/db:1.0), not one per package.
    if _is_trivy(payload):
        trivy = _trivy_rows(payload)
        if not trivy:
            return records
        trivy_created = ""
        if isinstance(payload, dict):
            trivy_created = str(payload.get("CreatedAt") or payload.get("created_at") or "")
        # First pass: mint one asset per image/scan Target before vulns (CSV FK order).
        image_targets: list[tuple[str, dict[str, Any]]] = []
        seen_targets: set[str] = set()
        for vuln in trivy:
            target = str(vuln.get("_target") or "image").strip() or "image"
            ids = vuln.get("_ids") if isinstance(vuln.get("_ids"), dict) else {}
            key = target.lower()
            if key not in seen_targets:
                seen_targets.add(key)
                image_targets.append((target, ids))
        for target, ids in image_targets:
            add_asset(target, ids)
        for vuln in trivy:
            vid = str(vuln.get("VulnerabilityID") or vuln.get("id") or "CVE-UNKNOWN")
            target = str(vuln.get("_target") or "image")
            ids = vuln.get("_ids") if isinstance(vuln.get("_ids"), dict) else {}
            klass = str(vuln.get("_class") or "vuln")
            is_cve = vid.upper().startswith("CVE")
            pkg = str(vuln.get("PkgName") or "").strip()
            fixed = str(
                vuln.get("FixedVersion")
                or vuln.get("fixed_version")
                or vuln.get("FixedVersion")
                or ""
            ).strip()
            # Optional prior-unit: "Upgrade X to Y" as fixed-version *hint* only
            title = str(vuln.get("Title") or "")
            desc = str(vuln.get("Description") or vuln.get("PkgName") or vid)
            if not fixed:
                m = re.search(r"(?i)upgrade\s+(\S+)\s+to\s+(\S+)", f"{title} {desc}")
                if m:
                    fixed = m.group(2).strip(".,;")
            extra_blob: dict[str, Any] = {
                "cve": vid if is_cve else "",
                "pkg": pkg or vuln.get("PkgName"),
                "class": klass,
            }
            if fixed:
                extra_blob["fixed_version_hint"] = fixed
            # CVE rows stay on cve:CVE-… (master). rule/check_id is only for
            # misconfig/secret IDs (KSV/AVD/DS/RuleID).
            if not is_cve:
                extra_blob["rule"] = vid
                extra_blob["check_id"] = vid
            extra = stamp_ids(extra_blob, **ids)
            extra.update(
                _no_fix_extra(
                    "",
                    vuln.get("Status") or vuln.get("status") or vuln.get("VulnerabilityStatus"),
                )
            )
            if trivy_created:
                extra["scan_time"] = trivy_created
            # Attach finding to image target asset (not one asset per package).
            assets = [target]
            if pkg and pkg.lower() not in {target.lower(), ""}:
                # keep package name in description/extra only — grain stays image+package on rollup
                pass
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{vid}-{target}"),
                    name=_trivy_title(vuln, vid, pkg, is_cve),
                    description=desc,
                    severity=vuln.get("Severity") or "medium",
                    category="vulnerability",
                    assets=assets,
                    labels=LABELS + ["trivy"],
                    collected_at=now,
                    extra=extra,
                )
            )
        return records

    if is_testssl(payload):
        testssl_at = ""
        if isinstance(payload, dict):
            testssl_at = str(payload.get("at") or payload.get("scanTime") or "")
            # scanTime is elapsed seconds in real testssl.sh JSON — only keep clock strings.
            if testssl_at.isdigit():
                testssl_at = str(payload.get("at") or "")
        for row in iter_testssl_findings(payload):
            host = str(row.get("host") or "unknown")
            if testssl_at and not row.get("scan_time"):
                row = {**row, "scan_time": testssl_at}
            add_asset(host)
            records.append(_emit_testssl_row(row, host, now))
        if records:
            return records

    gb_stamp = ""
    if isinstance(payload, dict):
        gb_stamp = str(payload.get("timestamp") or payload.get("scan_start") or "")
    for row in _greenbone_rows(payload):
        nvt = row.get("nvt") if isinstance(row.get("nvt"), dict) else {}
        vid = str(nvt.get("oid") or row.get("name") or "openvas")
        host = str(row.get("host") or "unknown")
        raw_sev = row.get("severity") or nvt.get("cvss_base") or "medium"
        sev = cvss_band(raw_sev) or str(raw_sev)
        solution = nvt.get("solution") if isinstance(nvt.get("solution"), dict) else {}
        solution_type = (
            row.get("solution_type")
            or solution.get("type")
            or nvt.get("solution_type")
            or ""
        )
        add_asset(host)
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"{vid}-{host}"),
                name=str(row.get("name") or vid),
                description=str(row.get("description") or vid),
                severity=sev,
                category="vulnerability",
                assets=[host],
                labels=LABELS + ["greenbone"],
                collected_at=now,
                extra={
                    "id": vid,
                    "rule": vid,
                    "oid": vid,
                    "cve": row.get("cve") or "",
                    "cves": _greenbone_cves(row),
                    **_no_fix_extra(solution_type),
                    **(
                        {
                            "scan_time": str(
                                row.get("timestamp") or row.get("scan_start") or gb_stamp
                            )
                        }
                        if (row.get("timestamp") or row.get("scan_start") or gb_stamp)
                        else {}
                    ),
                },
            )
        )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".jsonl", ".sarif", ".txt", ".xml", ".nessus", ".csv"), parse_file)


if __name__ == "__main__":
    main()
