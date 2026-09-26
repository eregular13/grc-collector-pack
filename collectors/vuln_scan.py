#!/usr/bin/env python3
"""Parse Nuclei JSONL, Trivy JSON, Greenbone XML/CSV/JSON, Nikto, Nessus XML, sslscan, or SARIF.

Parse-only. Does not run nuclei, nikto, Nessus, or sslscan, and does not call a Nessus API.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.asset_ids import stamp_ids
from shared.greenbone import cvss_band, parse_greenbone
from shared.io_util import iso_now, read_json, read_jsonl, read_text, run_collector
from shared.nessus import parse_nessus
from shared.nikto import is_interesting as nikto_interesting
from shared.nikto import nikto_severity
from shared.nikto import parse_nikto
from shared.sslscan import parse_sslscan
from shared.sarif import iter_sarif_results, load_sarif
from shared.schema import make_record, make_ref
from shared.testssl import is_testssl, iter_testssl_findings

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


def _trivy_rows(payload: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not isinstance(payload, dict):
        return rows
    ids = _trivy_ids(payload)
    for result in payload.get("Results") or payload.get("results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or result.get("target") or "image")
        for vuln in result.get("Vulnerabilities") or result.get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                vuln = {**vuln, "_target": target, "_ids": ids}
                rows.append(vuln)
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
        name=str(row.get("id") or row.get("finding") or vid),
        description=str(row.get("finding") or row.get("cve") or vid),
        severity=row.get("severity") or "high",
        category="vulnerability",
        assets=[host],
        labels=LABELS + ["testssl"] + extra_labels,
        collected_at=now,
        extra={"cve": row.get("cve") or "", "id": row.get("id") or "", "ip": row.get("ip") or ""},
    )


def _emit_greenbone_row(row: dict[str, Any], now: str) -> tuple[str, dict]:
    host = str(row.get("host") or "unknown")
    vid = str(row.get("oid") or row.get("name") or "openvas")
    port = str(row.get("port") or "")
    return host, make_record(
        kind="finding",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"{vid}-{host}-{port}"),
        name=str(row.get("name") or vid),
        description=str(row.get("description") or vid),
        severity=row.get("severity") or "medium",
        category="vulnerability",
        assets=[host],
        labels=LABELS + ["greenbone"],
        collected_at=now,
        extra={
            "cve": row.get("cve") or "",
            "id": vid,
            "port": port,
            "cvss": row.get("cvss") or "",
            "threat": row.get("threat") or "",
        },
    )


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
                    ref_id=make_ref(SOURCE, rid),
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
        for row in iter_testssl_findings(peek):
            host = str(row.get("host") or "unknown")
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
            if not nikto_interesting(url, msg, rid):
                continue
            host = str(row.get("host") or "unknown")
            add_asset(host)
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"nikto-{rid}-{host}-{url}"),
                    name=f"Nikto: {msg or url}",
                    description=(
                        f"{msg} url={url} (Nikto file-drop; not a live HTTP probe)"
                    ),
                    severity=nikto_severity(url, msg, rid),
                    category="exposure",
                    assets=[host],
                    labels=LABELS + ["nikto"],
                    collected_at=now,
                    extra={"url": url, "id": rid},
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
            extra = stamp_ids(
                {
                    "port": port,
                    "service": row.get("service") or "",
                    "id": plugin,
                    "protocol": row.get("protocol") or "",
                    "id_quality": row.get("id_quality") or "",
                    "tool": "nessus",
                    "cves": cves,
                },
                **ids,
            )
            if row.get("scan_time"):
                extra["scan_time"] = row.get("scan_time")
            if cves:
                extra["cve"] = " ".join(cves)
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
                    ref_id=make_ref(SOURCE, tid),
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

    trivy = _trivy_rows(payload)
    if trivy:
        trivy_created = ""
        if isinstance(payload, dict):
            trivy_created = str(payload.get("CreatedAt") or payload.get("created_at") or "")
        for vuln in trivy:
            vid = str(vuln.get("VulnerabilityID") or vuln.get("id") or "CVE-UNKNOWN")
            target = str(vuln.get("_target") or "image")
            ids = vuln.get("_ids") if isinstance(vuln.get("_ids"), dict) else {}
            add_asset(target, ids)
            extra = stamp_ids({"cve": vid, "pkg": vuln.get("PkgName")}, **ids)
            if trivy_created:
                extra["scan_time"] = trivy_created
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, vid),
                    name=str(vuln.get("Title") or vid),
                    description=str(vuln.get("Description") or vuln.get("PkgName") or vid),
                    severity=vuln.get("Severity") or "medium",
                    category="vulnerability",
                    assets=[target],
                    labels=LABELS + ["trivy"],
                    collected_at=now,
                    extra=extra,
                )
            )
        return records

    if is_testssl(payload):
        for row in iter_testssl_findings(payload):
            host = str(row.get("host") or "unknown")
            add_asset(host)
            records.append(_emit_testssl_row(row, host, now))
        if records:
            return records

    for row in _greenbone_rows(payload):
        nvt = row.get("nvt") if isinstance(row.get("nvt"), dict) else {}
        vid = str(nvt.get("oid") or row.get("name") or "openvas")
        host = str(row.get("host") or "unknown")
        raw_sev = row.get("severity") or nvt.get("cvss_base") or "medium"
        sev = cvss_band(raw_sev) or str(raw_sev)
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
                extra={"id": vid, "cve": row.get("cve") or ""},
            )
        )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".jsonl", ".sarif", ".txt", ".xml", ".nessus", ".csv"), parse_file)


if __name__ == "__main__":
    main()
