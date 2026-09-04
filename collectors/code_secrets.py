#!/usr/bin/env python3
"""Parse Gitleaks / Semgrep / Trivy FS. Secrets are redacted."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, read_jsonl, run_collector
from shared.sarif import is_sarif, iter_sarif_results
from shared.schema import make_record, make_ref

SOURCE = "code-secrets"
LABELS = ["code", "secrets"]


def _load(path: Path) -> Any:
    try:
        return read_json(path)
    except Exception:
        rows = read_jsonl(path)
        return rows if rows else {}


def _trufflehog(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict) and x.get("DetectorName")]
    if isinstance(payload, dict) and payload.get("DetectorName"):
        return [payload]
    return []


def _gitleaks(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict) and (x.get("RuleID") or x.get("Secret"))]
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        return [x for x in payload["findings"] if isinstance(x, dict)]
    return []


def parse_file(path: Path) -> list[dict]:
    payload = _load(path)
    now = iso_now()
    records: list[dict] = []
    seen_assets: set[str] = set()

    def add_asset(name: str) -> None:
        key = name.lower()
        if key in seen_assets:
            return
        seen_assets.add(key)
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=f"Code asset {name}",
                category="repository",
                assets=[name],
                labels=LABELS,
                collected_at=now,
                extra={"asset_type": "PR"},
            )
        )

    hog = _trufflehog(payload)
    if hog:
        for leak in hog:
            meta = leak.get("SourceMetadata") if isinstance(leak.get("SourceMetadata"), dict) else {}
            data = meta.get("Data") if isinstance(meta.get("Data"), dict) else {}
            fs = data.get("Filesystem") if isinstance(data.get("Filesystem"), dict) else {}
            git = data.get("Git") if isinstance(data.get("Git"), dict) else {}
            fpath = str(fs.get("file") or git.get("file") or leak.get("SourceID") or "repo")
            add_asset(fpath)
            detector = str(leak.get("DetectorName") or "secret")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"trufflehog-{detector}-{fpath}"),
                    name=f"TruffleHog {detector}",
                    description=f"{detector} secret in {fpath} value=[REDACTED] verified={leak.get('Verified', False)}",
                    severity="critical" if leak.get("Verified") else "high",
                    category="secrets",
                    assets=[fpath],
                    labels=LABELS + ["trufflehog"],
                    collected_at=now,
                    extra={"verified": leak.get("Verified")},
                )
            )
        return records

    leaks = _gitleaks(payload)
    if leaks:
        for leak in leaks:
            fpath = str(leak.get("File") or leak.get("file") or "repo")
            add_asset(fpath)
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, str(leak.get("RuleID") or "secret") + "-" + fpath),
                    name=str(leak.get("Description") or leak.get("RuleID") or "Secret"),
                    description=f"Secret rule {leak.get('RuleID')} in {fpath}:{leak.get('StartLine', '?')} value=[REDACTED]",
                    severity="critical",
                    category="secrets",
                    assets=[fpath],
                    labels=LABELS + ["gitleaks"],
                    collected_at=now,
                    extra={"line": leak.get("StartLine")},
                )
            )
        return records

    if isinstance(payload, dict) and is_sarif(payload):
        for row in iter_sarif_results(payload):
            uri = str(row.get("uri") or "repo")
            add_asset(uri)
            rid = str(row.get("rule_id") or "sarif")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, rid),
                    name=str(row.get("message") or rid),
                    description=str(row.get("message") or rid),
                    severity=row.get("severity") or "medium",
                    category="sast",
                    assets=[uri],
                    labels=LABELS + ["sarif", str(row.get("tool") or "sarif").lower()],
                    collected_at=now,
                    extra={"rule": rid},
                )
            )
        if records:
            return records

    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        for hit in payload["results"]:
            if not isinstance(hit, dict):
                continue
            fpath = str(hit.get("path") or "repo")
            extra = hit.get("extra") if isinstance(hit.get("extra"), dict) else {}
            add_asset(fpath)
            sev = extra.get("severity") or hit.get("severity") or "high"
            if str(sev).upper() == "ERROR":
                sev = "high"
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, str(hit.get("check_id") or "sast")),
                    name=str(extra.get("message") or hit.get("check_id") or "SAST finding"),
                    description=str(extra.get("message") or hit.get("check_id")),
                    severity=sev,
                    category="sast",
                    assets=[fpath],
                    labels=LABELS + ["semgrep"],
                    collected_at=now,
                    extra={},
                )
            )
        if records:
            return records

    if isinstance(payload, dict) and (payload.get("Results") or payload.get("results")):
        for result in payload.get("Results") or []:
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target") or "lockfile")
            add_asset(target)
            for vuln in result.get("Vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vid = str(vuln.get("VulnerabilityID") or "CVE")
                records.append(
                    make_record(
                        kind="finding",
                        source=SOURCE,
                        ref_id=make_ref(SOURCE, vid),
                        name=str(vuln.get("Title") or vid),
                        description=str(vuln.get("Description") or vid),
                        severity=vuln.get("Severity") or "medium",
                        category="vulnerability",
                        assets=[target],
                        labels=LABELS + ["trivy", "lockfile"],
                        collected_at=now,
                        extra={"cve": vid, "pkg": vuln.get("PkgName")},
                    )
                )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".jsonl", ".sarif"), parse_file)


if __name__ == "__main__":
    main()
