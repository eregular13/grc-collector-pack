"""CVE-completeness accounting for every scanner source (not only Trivy).

Two layers, both fail closed (the Trivy PQ-1 rollup conservation check exits 2
on a mismatch; this mirrors it):

1. input -> canonical: every CVE a scanner *reports as a finding* in a dropped
   file (structured fields only, never reference URLs) must appear on some
   canonical record (out/canonical/*.jsonl). Catches parser/filter losses.
2. canonical -> export: every structured CVE on a canonical finding must be in
   poam.csv, in excluded.csv (with the CVE id in its ``cves`` column and a
   non-empty reason), or on a poam_members.csv row whose parent is in
   poam.csv. Catches dedupe/fold/rollup losses.

Parse-only. Reads the work dir; writes out/poam/cve_accounting.json.
"""
from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_NOT_VULN_RE = re.compile(r"NOT\s+VULNERABLE", re.I)
_VULN_STATE_RE = re.compile(r"State:\s*(LIKELY\s+)?VULNERABLE", re.I)
_TESTSSL_QUIET = {"OK", "INFO", "DEBUG", ""}
_SKIP_NAMES = {"lab.txt", "sample.txt", "readme.md"}


def _cves(blob: Any) -> set[str]:
    return {m.upper() for m in CVE_RE.findall(str(blob or ""))}


def _tag(el: ET.Element) -> str:
    return el.tag.split("}")[-1].lower()


# ---------------------------------------------------------------- inputs

def _nmap_xml(root: ET.Element) -> set[str]:
    out: set[str] = set()
    for sc in root.iter("script"):
        sid = (sc.attrib.get("id") or "").lower()
        if sid == "vulners":
            for el in sc.iter("elem"):
                if (el.attrib.get("key") or "").lower() == "id":
                    out |= _cves(el.text)
            if not any(True for _ in sc.iter("elem")):
                out |= _cves(sc.attrib.get("output"))
        elif "vuln" in sid:
            text = sc.attrib.get("output") or ""
            if _VULN_STATE_RE.search(text) and not _NOT_VULN_RE.search(text):
                out |= _cves(text)
    return out


def _nikto(path: Path) -> set[str]:
    """Nikto item description/references text (independent of the collector)."""
    out: set[str] = set()
    if path.suffix.lower() == ".xml":
        root = ET.parse(path).getroot()
        for item in root.iter():
            if _tag(item) != "item":
                continue
            for child in item:
                if _tag(child) in {"description", "references"}:
                    out |= _cves(child.text)
        return out
    for payload in _json_rows(path):
        rows = []
        if isinstance(payload, dict):
            rows = payload.get("vulnerabilities") or payload.get("items") or []
        elif isinstance(payload, list):
            for host in payload:
                if isinstance(host, dict):
                    rows.extend(host.get("vulnerabilities") or [])
        for row in rows:
            if isinstance(row, dict):
                out |= _cves(
                    f"{row.get('msg') or row.get('description') or row.get('message') or ''} "
                    f"{row.get('references') or row.get('refs') or ''}"
                )
    return out


def _openscap(root: ET.Element) -> set[str]:
    """XCCDF rule-results with result=fail and a CVE ident."""
    out: set[str] = set()
    for rr in root.iter():
        if _tag(rr) != "rule-result":
            continue
        result = next((c.text for c in rr if _tag(c) == "result"), "") or ""
        if result.strip().lower() not in {"fail", "error"}:
            continue
        for c in rr:
            if _tag(c) == "ident":
                out |= _cves(c.text)
    return out


def _json_rows(path: Path) -> list[Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return [json.loads(text)]
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows


def _json_cves(payload: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(payload, list):
        for row in payload:
            if isinstance(row, dict) and "id" in row and "severity" in row and "finding" in row:
                if str(row.get("severity") or "").upper() not in _TESTSSL_QUIET:
                    out |= _cves(row.get("cve"))  # testssl
            elif isinstance(row, (dict, list)):
                out |= _json_cves(row)
        return out
    if not isinstance(payload, dict):
        return out
    if isinstance(payload.get("Results"), list):  # trivy
        for res in payload["Results"]:
            for v in (res or {}).get("Vulnerabilities") or []:
                out |= _cves(v.get("VulnerabilityID"))
        return out
    if isinstance(payload.get("matches"), list):  # grype
        for m in payload["matches"]:
            out |= _cves(((m or {}).get("vulnerability") or {}).get("id"))
        return out
    if isinstance(payload.get("scanResult"), list):  # testssl --jsonfile-pretty
        for sr in payload["scanResult"]:
            for key, rows in (sr or {}).items():
                if isinstance(rows, list):
                    out |= _json_cves(rows)
        return out
    data = payload.get("data") if isinstance(payload.get("data"), dict) else None
    vuln = (data or {}).get("vulnerability") or payload.get("vulnerability")
    if isinstance(vuln, dict):  # wazuh vulnerability-detector alert / state
        status = str(vuln.get("status") or "").lower()
        if status not in {"solved", "fixed"}:
            out |= _cves(vuln.get("cve") or vuln.get("id"))
        return out
    for key in ("hits", "_source", "alerts", "items", "affected_items"):  # wazuh API/indexer
        inner = payload.get(key)
        if isinstance(inner, dict):
            out |= _json_cves(inner)
        elif isinstance(inner, list):
            for row in inner:
                out |= _json_cves(row)
    return out


def file_cves(path: Path) -> set[str]:
    suffix = path.suffix.lower()
    try:
        if suffix == ".xml":
            head = path.read_text(encoding="utf-8", errors="replace")[:4096].lower()
            if "<nmaprun" in head:
                return _nmap_xml(ET.parse(path).getroot())
            if "niktoscan" in head or "<niktoscan" in head:
                return _nikto(path)
            if "xccdf" in head or "<benchmark" in head or "<testresult" in head or "asset-report-collection" in head:
                return _openscap(ET.parse(path).getroot())
            return set()
        if suffix in {".json", ".jsonl", ".ndjson"}:
            out: set[str] = set()
            for payload in _json_rows(path):
                if isinstance(payload, dict) and ("vulnerabilities" in payload or "items" in payload) and _is_nikto(payload):
                    out |= _nikto(path)
                    continue
                out |= _json_cves(payload)
            return out
    except (ET.ParseError, OSError, ValueError):
        return set()
    return set()


def _is_nikto(payload: dict) -> bool:
    from shared.nikto import is_nikto_payload

    return bool(is_nikto_payload(payload))


def input_cves(in_root: Path) -> dict[str, set[str]]:
    """CVE -> {"sensor/file"} for every file under in/."""
    found: dict[str, set[str]] = defaultdict(set)
    if not in_root.is_dir():
        return found
    for path in sorted(in_root.rglob("*")):
        if not path.is_file() or path.name.lower() in _SKIP_NAMES:
            continue
        rel = path.relative_to(in_root).as_posix()
        for cve in file_cves(path):
            found[cve].add(rel)
    return found


# ---------------------------------------------------------------- outputs

def structured_cves(rec: dict[str, Any]) -> set[str]:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    raw: list[str] = [str(extra.get("cve") or "")]
    cv = extra.get("cves")
    if isinstance(cv, (list, tuple)):
        raw.extend(str(x or "") for x in cv)
    elif cv:
        raw.append(str(cv))
    return {c for blob in raw for c in _cves(blob)}


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def account(work: Path) -> dict[str, Any]:
    out = work / "out"
    records: list[dict[str, Any]] = []
    for jf in sorted((out / "canonical").glob("*.jsonl")):
        for line in jf.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    canonical_any: set[str] = set()
    need: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for rec in records:
        canonical_any |= _cves(json.dumps(rec))
        if rec.get("kind") not in {"finding", "vulnerability", "excluded"}:
            continue
        for cve in structured_cves(rec):
            need[cve].append((str(rec.get("source") or ""), str(rec.get("ref_id") or "")))

    poam_rows = _read_csv(out / "poam" / "poam.csv")
    poam_cves: set[str] = set()
    poam_ids: set[str] = set()
    for row in poam_rows:
        poam_cves |= _cves(" ".join(str(v) for v in row.values()))
        poam_ids.add(str(row.get("poam_id") or ""))
    ex_by_ref: dict[str, set[str]] = defaultdict(set)
    for row in _read_csv(out / "poam" / "excluded.csv"):
        if not str(row.get("excluded_reason") or row.get("reason_code") or "").strip():
            continue
        ex_by_ref[str(row.get("finding_ref_id") or row.get("id") or "")] |= _cves(row.get("cves"))
    migrated: dict[str, str] = {}
    for row in _read_csv(out / "poam" / "poam-id-migration.csv"):
        old_id, new_id = str(row.get("old_id") or ""), str(row.get("new_id") or "")
        if old_id and new_id:
            migrated[old_id] = new_id

    def _live_parent(pid: str) -> bool:
        seen: set[str] = set()
        while pid and pid not in poam_ids and pid not in seen:
            seen.add(pid)
            pid = migrated.get(pid, "")
        return bool(pid) and pid in poam_ids

    member_refs = {
        str(r.get("finding_ref_id") or "")
        for r in _read_csv(out / "poam" / "poam_members.csv")
        if _live_parent(str(r.get("poam_id") or r.get("egp_id") or ""))
    }

    how: dict[str, int] = defaultdict(int)
    unaccounted: dict[str, list[str]] = defaultdict(list)
    for cve, refs in sorted(need.items()):
        if cve in poam_cves:
            how["poam"] += 1
        elif any(cve in ex_by_ref.get(ref, ()) for _, ref in refs):
            how["excluded"] += 1
        elif any(ref in member_refs for _, ref in refs):
            how["rollup_member"] += 1
        else:
            for src, ref in refs:
                unaccounted[src or "unknown"].append(f"{cve}@{ref}")

    inputs = input_cves(work / "in")
    not_parsed: dict[str, list[str]] = defaultdict(list)
    for cve, files in sorted(inputs.items()):
        if cve not in canonical_any:
            for f in sorted(files):
                not_parsed[f].append(cve)

    ok = not unaccounted and not not_parsed
    return {
        "ok": ok,
        "input_cves": len(inputs),
        "canonical_cves": len(need),
        "accounted": dict(how),
        "input_not_parsed": {k: sorted(set(v)) for k, v in not_parsed.items()},
        "canonical_unaccounted": {k: sorted(set(v)) for k, v in unaccounted.items()},
    }


def write_report(work: Path) -> dict[str, Any]:
    report = account(work)
    dest = work / "out" / "poam" / "cve_accounting.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def summary_line(report: dict[str, Any]) -> str:
    acc = report.get("accounted") or {}
    lost_in = sum(len(v) for v in (report.get("input_not_parsed") or {}).values())
    lost_out = sum(len(v) for v in (report.get("canonical_unaccounted") or {}).values())
    state = "ok" if report.get("ok") else "FAIL"
    return (
        f"CVE_ACCOUNTING={state} input={report.get('input_cves', 0)} "
        f"canonical={report.get('canonical_cves', 0)} poam={acc.get('poam', 0)} "
        f"excluded={acc.get('excluded', 0)} member={acc.get('rollup_member', 0)} "
        f"input_not_parsed={lost_in} unaccounted={lost_out}"
    )
