"""CIS Controls v8 IG1 coverage: mapped vs real-scan-backed vs sample-only.

Safeguard ids only; the wording here is ours, not CIS text.

* mapped: the pack's control tables stamp the id on some finding type.
  "refs" ids reach POA&M framework_refs; "internal" ids live only under
  extra.cis_v8_internal and never reach client outputs.
* real: a POA&M row carrying the id came from a LAB or CLIENT estate.
* sample: every POA&M row carrying the id is SAMPLE/DEMO/MIXED.
* A mapped id with no POA&M row is "mapped, no evidence" — never "clean".
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]

IG1: dict[int, tuple[int, ...]] = {
    1: (1, 2), 2: (1, 2, 3), 3: (1, 2, 3, 4, 5, 6), 4: (1, 2, 3, 4, 5, 6, 7),
    5: (1, 2, 3, 4), 6: (1, 2, 3, 4, 5), 7: (1, 2, 3, 4), 8: (1, 2, 3), 9: (1, 2),
    10: (1, 2, 3), 11: (1, 2, 3, 4), 12: (1,), 14: (1, 2, 3, 4, 5, 6, 7, 8), 15: (1,),
    17: (1, 2, 3),
}
SAFEGUARDS: tuple[str, ...] = tuple(f"{c}.{s}" for c in sorted(IG1) for s in IG1[c])

_PROCESS = "process or policy safeguard; no scanner output can show it is met or missed"
# Why a safeguard stays unmapped. Scan-derivable candidates get a specific reason.
UNMAPPED_REASONS: dict[str, str] = {
    "1.2": "nmap/asset ledger record discovered hosts, but the pack has no authorized-asset "
    "baseline to call a host unauthorized",
    "2.1": "grype/vuln collectors emit only vulnerable packages, not a full software inventory",
    "2.2": "no collector derives end-of-support status; the asset ledger eol field is operator-entered",
    "2.3": "needs an authorized-software list; no collector produces one",
    "3.1": _PROCESS, "3.2": _PROCESS,
    "3.4": "no collector reads data-retention settings",
    "3.5": "no collector reads data-disposal evidence",
    "3.6": "no collector reads disk-encryption state on end-user devices",
    "4.2": "nmap sees services such as SNMP, but collectors do not classify a host as network "
    "infrastructure, so a device-config finding cannot be attributed honestly",
    "4.6": "no collector reads how assets and software are administered",
    "5.1": "identity/SaaS collectors ingest account exports but emit findings, not an account "
    "inventory; a finding cannot show the inventory exists",
    "6.1": _PROCESS, "6.2": _PROCESS, "6.3": "no collector reads MFA for externally exposed apps "
    "separately from admin MFA", "6.4": "no collector reads remote-network-access MFA",
    "6.5": "no collector reads admin MFA as a distinct safeguard signal",
    "7.1": _PROCESS, "7.2": _PROCESS,
    "8.1": _PROCESS + " (audit-log collection itself is covered by another safeguard)",
    "8.3": "no collector reads log storage capacity",
    "9.1": "no collector identifies browser or mail-client versions as such",
    "9.2": "dns_email checks SPF/DKIM/DMARC records only; nothing reads DNS filtering",
    "10.2": "no collector reads anti-malware signature update state",
    "10.3": "no collector reads removable-media autorun settings",
    "11.1": _PROCESS, "11.2": "no collector reads backup job state",
    "11.3": "no collector reads backup protection", "11.4": "no collector reads backup isolation",
    "12.1": "vuln collectors see outdated software, but collectors do not classify a host as "
    "network infrastructure",
    **{f"14.{i}": _PROCESS for i in range(1, 9)},
    "15.1": _PROCESS, "17.1": _PROCESS, "17.2": _PROCESS, "17.3": _PROCESS,
}

# Finding types reviewed for an IG1 id and deliberately left without one.
UNMAPPED_FINDINGS: dict[str, str] = {
    "AUTH-9230": "password hashing rounds is credential-storage hardening; the IG1 password "
    "safeguard is about unique, strong passwords, so no IG1 id fits honestly",
}

_REFS_TOKEN = re.compile(r"\bcis_(\d+)_(\d+)\b")
_PREFIX_TOKEN = re.compile(r"CIS_V8_PREFIX\}(\d+)\.(\d+)")
_INTERNAL_TUPLE = re.compile(r"\"cis_v8_internal\":\s*\(([^)]*)\)")
REAL_ESTATES = ("LAB", "CLIENT")


def _ids(pairs: Iterable[tuple[str, str]]) -> set[str]:
    return {f"{int(a)}.{int(b)}" for a, b in pairs}


def mapped_safeguards(root: Path = ROOT) -> dict[str, str]:
    """safeguard -> "refs" (reaches framework_refs) or "internal" (internal-only)."""
    refs: set[str] = set()
    internal: set[str] = set()
    for rel in ("shared/control_map.py", "shared/finding_types.py"):
        p = root / rel
        if p.is_file():
            refs |= _ids(_REFS_TOKEN.findall(p.read_text(encoding="utf-8")))
    for rel in ("shared/hardening_map.py", "shared/framework_class_map.py"):
        p = root / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8")
        internal |= _ids(_PREFIX_TOKEN.findall(text))
        for body in _INTERNAL_TUPLE.findall(text):
            for tok in re.findall(r"\"(\d+)\.(\d+)\"", body):
                internal |= _ids([tok])
    out: dict[str, str] = {}
    for sg in SAFEGUARDS:
        if sg in refs:
            out[sg] = "refs"
        elif sg in internal:
            out[sg] = "internal"
    return out


def _row_ids(refs: str) -> set[str]:
    return _ids(_REFS_TOKEN.findall(str(refs or "")))


def _estate_kind(row: dict[str, Any]) -> str:
    text = str(row.get("estate") or "").strip().upper()
    for kind in ("MIXED", "SAMPLE", "DEMO", "LAB", "CLIENT"):
        if text.startswith(kind):
            return kind
    return "SAMPLE"  # unknown estate never counts as real


def evidence_from_poam(paths: Iterable[Path]) -> dict[str, dict[str, int]]:
    """safeguard -> {"real": n, "sample": n} POA&M rows across poam.csv files."""
    ev: dict[str, dict[str, int]] = {sg: {"real": 0, "sample": 0} for sg in SAFEGUARDS}
    for path in paths:
        with Path(path).open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                bucket = "real" if _estate_kind(row) in REAL_ESTATES else "sample"
                for sg in _row_ids(row.get("framework_refs") or "") & set(SAFEGUARDS):
                    ev[sg][bucket] += 1
    return ev


def coverage(poam_paths: Iterable[Path], root: Path = ROOT) -> list[dict[str, Any]]:
    mapped = mapped_safeguards(root)
    ev = evidence_from_poam(poam_paths)
    rows: list[dict[str, Any]] = []
    for sg in SAFEGUARDS:
        surface = mapped.get(sg, "")
        real, sample = ev[sg]["real"], ev[sg]["sample"]
        if not surface:
            status, note = "UNMAPPED", UNMAPPED_REASONS.get(sg, "no finding type maps here yet")
        elif real:
            status, note = "REAL", ""
        elif sample:
            status, note = "SAMPLE-ONLY", "only bundled sample/demo rows carry this id"
        elif surface == "internal":
            status, note = "MAPPED-INTERNAL", "id is internal-only; it never reaches POA&M framework_refs"
        else:
            status, note = "MAPPED-NO-EVIDENCE", "no POA&M row in these outputs; not evidence of compliance"
        rows.append({"safeguard": sg, "status": status, "surface": surface or "-",
                     "real_rows": real, "sample_rows": sample, "note": note})
    return rows


def summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = {"safeguards": len(rows), "mapped": sum(r["status"] != "UNMAPPED" for r in rows)}
    for key in ("REAL", "SAMPLE-ONLY", "MAPPED-NO-EVIDENCE", "MAPPED-INTERNAL", "UNMAPPED"):
        out[key] = sum(r["status"] == key for r in rows)
    return out


def render_markdown(rows: list[dict[str, Any]], sources: list[str]) -> str:
    s = summary(rows)
    lines = [
        "# CIS Controls v8 IG1 coverage",
        "",
        "Safeguard ids only. REAL = a LAB/CLIENT POA&M row carries the id. SAMPLE-ONLY = only "
        "bundled sample/demo rows do. MAPPED-NO-EVIDENCE / MAPPED-INTERNAL are not evidence "
        "that a safeguard is met.",
        "",
        " ".join(f"{k}={v}" for k, v in s.items()),
        "",
        "Inputs: " + (", ".join(sources) or "none"),
        "",
        "| Safeguard | Status | Surface | Real rows | Sample rows | Note |",
        "|---|---|---|---|---|---|",
    ]
    lines_tail = ["", "## Findings reviewed and left without an IG1 id", ""]
    lines_tail += [f"- {k}: {v}" for k, v in sorted(UNMAPPED_FINDINGS.items())]
    lines += [
        f"| {r['safeguard']} | {r['status']} | {r['surface']} | {r['real_rows']} | "
        f"{r['sample_rows']} | {r['note']} |"
        for r in rows
    ]
    return "\n".join(lines + lines_tail) + "\n"


def write_report(rows: list[dict[str, Any]], out_dir: Path, sources: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "ig1-coverage.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    (out_dir / "ig1-coverage.md").write_text(render_markdown(rows, sources), encoding="utf-8", newline="\n")
