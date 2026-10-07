"""CISO Data-Wizard import mapping (PQ-4/5/7/8 + PQ-9).

Lab-proven rules (jobs 08–18), productized for export + dry-run prep:

1. **PQ-4 / PQ-5** — ``domain`` on assets + applied_controls = import folder
   name (not bare ``Global``) so folder-filtered GET counts match creates.
2. **PQ-7** — AppliedControl / Finding / Vulnerability display
   ``name = "{title} [{ref_id}]"`` so names stay unique across tenants.
3. **PQ-8** — Wizard ``name`` length ≤ 200 after the suffix for
   Vulnerability, Finding, and AppliedControl (CISO Community max_length;
   lab job 43b Findings rejected >200). Truncate **title**, keep
   `` [ref_id]`` tail; overlong ref alone → first 180 of ref + 8-char hash.
   Full untruncated title is preserved in ``description`` when truncated.
4. **PQ-9** — split Vulnerability CSV into chunks (default 500 rows) for
   Data-Wizard loads; single ~5k-row POSTs can WORKER TIMEOUT on SQLite.

Also: vuln ``assets`` must be exact imported asset **names**;
``applied_controls`` FKs ⊆ exported control ref_ids (or display names).

File-only. No HTTP. Never POST ``/api/risks``. Never print tokens.
"""

from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

# CISO Community wizard name max_length (Vulnerability lab job 10;
# Findings confirmed 200 in job 43b import stop).
VULN_NAME_MAX = 200
WIZARD_NAME_MAX = 200
# AppliedControl / Finding share the wizard 200 cap (not Django 255).
DEFAULT_NAME_MAX = WIZARD_NAME_MAX
# PQ-9 lab-proven safe wizard chunk size.
DEFAULT_VULN_CHUNK = 500

_SUFFIX_RE = re.compile(r"\s*\[[^\]]+\]\s*$")


def strip_ref_suffix(title: str) -> str:
    """Remove a trailing `` [ref_id]`` so re-mapping does not double-suffix."""
    return _SUFFIX_RE.sub("", (title or "").strip()).strip()


def unique_display_name(
    title: str,
    ref_id: str,
    *,
    max_len: int = DEFAULT_NAME_MAX,
) -> str:
    """PQ-7/8: ``title [ref_id]`` truncated so full string length ≤ max_len."""
    orig = strip_ref_suffix(title)
    rid = (ref_id or "").strip()
    if not rid:
        return orig[:max_len]
    suffix = f" [{rid}]"
    if len(suffix) > max_len:
        digest = hashlib.sha256(rid.encode("utf-8")).hexdigest()[:8]
        base = rid[:180]
        return f"{base}-{digest}"[:max_len]
    if not orig:
        if len(rid) <= max_len:
            return rid
        return unique_display_name("", rid, max_len=max_len)
    full = f"{orig}{suffix}"
    if len(full) <= max_len:
        return full
    keep = max_len - len(suffix)
    if keep < 1:
        return suffix[-max_len:]
    return f"{orig[:keep]}{suffix}"



def _preserve_full_title_in_description(row: dict[str, str], orig_title: str, mapped_name: str) -> None:
    """If title was truncated for max_len, keep full text in description."""
    full = strip_ref_suffix(orig_title)
    mapped_title = strip_ref_suffix(mapped_name)
    if not full or len(full) <= len(mapped_title):
        return
    desc = row.get("description") or ""
    if full in desc:
        return
    row["description"] = f"{full}\n\n{desc}".strip() if desc else full


def plan_vuln_chunks(
    n_rows: int,
    *,
    chunk_size: int = DEFAULT_VULN_CHUNK,
) -> list[tuple[int, int]]:
    """Return inclusive-exclusive ``(start, end)`` row ranges for PQ-9."""
    if n_rows < 0:
        raise ValueError("n_rows must be >= 0")
    size = int(chunk_size)
    if size < 1:
        raise ValueError("chunk_size must be >= 1")
    if n_rows == 0:
        return []
    return [(i, min(i + size, n_rows)) for i in range(0, n_rows, size)]


def write_vuln_chunks(
    src_csv: Path,
    dest_dir: Path,
    *,
    chunk_size: int = DEFAULT_VULN_CHUNK,
    prefix: str = "vulnerabilities_chunk",
) -> dict[str, Any]:
    """Split a vulnerabilities.csv into chunk CSVs. No HTTP."""
    src = Path(src_csv)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    with src.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise ValueError(f"no header in {src}")
        fields = list(reader.fieldnames)
        rows = list(reader)
    ranges = plan_vuln_chunks(len(rows), chunk_size=chunk_size)
    paths: list[str] = []
    for idx, (start, end) in enumerate(ranges, start=1):
        path = dest / f"{prefix}{idx:02d}.csv"
        with path.open("w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows[start:end])
        paths.append(str(path))
    return {
        "source": str(src),
        "n_rows": len(rows),
        "chunk_size": int(chunk_size),
        "n_chunks": len(ranges),
        "ranges": [{"start": a, "end": b, "n": b - a} for a, b in ranges],
        "paths": paths,
    }


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with Path(path).open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields = list(reader.fieldnames or [])
        rows = [{k: (v if v is not None else "") for k, v in row.items()} for row in reader]
    return fields, rows


def _write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, str]]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def map_ciso_csvs(
    src_dir: Path,
    dest_dir: Path,
    *,
    domain: str,
    vuln_name_max: int = VULN_NAME_MAX,
    other_name_max: int = DEFAULT_NAME_MAX,
    drop_unmatched_asset_vulns: bool = True,
) -> dict[str, Any]:
    """Rewrite a ciso-assistant/ tree for wizard import (PQ-4/5/7/8).

    Copies evidences as-is. risk_scenarios.csv is copied unchanged (POA&M
    path is separate; scenario names are not CISO Vulnerability.max_length).
    """
    src = Path(src_dir)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    folder = (domain or "").strip() or "Global"
    stats: dict[str, Any] = {
        "domain": folder,
        "counts": {},
        "max_name_len": {},
        "dup_names": {},
        "pq4": {},
        "paths": {},
    }

    a_fields, assets = _read_csv(src / "assets.csv")
    for row in assets:
        if "domain" in a_fields:
            row["domain"] = folder
        if "name" in a_fields:
            n = row.get("name") or ""
            if len(n) > other_name_max:
                _preserve_full_title_in_description(row, n, n[:other_name_max])
                row["name"] = n[:other_name_max]
    _write_csv(dest / "assets.csv", a_fields, assets)
    asset_names = {(r.get("name") or "").strip() for r in assets if (r.get("name") or "").strip()}
    asset_ref_ids = {(r.get("ref_id") or "").strip() for r in assets if (r.get("ref_id") or "").strip()}
    ref_to_name = {
        (r.get("ref_id") or "").strip(): (r.get("name") or "").strip()
        for r in assets
        if (r.get("ref_id") or "").strip()
    }
    stats["counts"]["assets"] = len(assets)
    stats["paths"]["assets"] = str(dest / "assets.csv")

    c_fields, controls_in = _read_csv(src / "applied_controls.csv")
    seen_ctl: set[str] = set()
    controls: list[dict[str, str]] = []
    for row in controls_in:
        rid = (row.get("ref_id") or "").strip()
        if not rid or rid in seen_ctl:
            continue
        seen_ctl.add(rid)
        if "domain" in c_fields:
            row["domain"] = folder
        _orig_name = row.get("name") or ""
        row["name"] = unique_display_name(_orig_name, rid, max_len=other_name_max)
        _preserve_full_title_in_description(row, _orig_name, row["name"])
        controls.append(row)
    _write_csv(dest / "applied_controls.csv", c_fields, controls)
    ctl_ref_ids = {(r.get("ref_id") or "").strip() for r in controls}
    ctl_names = {(r.get("name") or "").strip() for r in controls}
    stats["counts"]["applied_controls"] = len(controls)
    stats["paths"]["applied_controls"] = str(dest / "applied_controls.csv")

    if (src / "evidences.csv").is_file():
        e_fields, evidences = _read_csv(src / "evidences.csv")
        if "name" in e_fields:
            for row in evidences:
                n = row.get("name") or ""
                if len(n) > other_name_max:
                    _preserve_full_title_in_description(row, n, n[:other_name_max])
                    row["name"] = n[:other_name_max]
        _write_csv(dest / "evidences.csv", e_fields, evidences)
        stats["counts"]["evidences"] = len(evidences)
        stats["paths"]["evidences"] = str(dest / "evidences.csv")

    f_fields, findings = _read_csv(src / "findings.csv")
    for row in findings:
        rid = (row.get("ref_id") or "").strip()
        _orig_name = row.get("name") or ""
        row["name"] = unique_display_name(_orig_name, rid, max_len=other_name_max)
        _preserve_full_title_in_description(row, _orig_name, row["name"])
    _write_csv(dest / "findings.csv", f_fields, findings)
    stats["counts"]["findings"] = len(findings)
    stats["paths"]["findings"] = str(dest / "findings.csv")

    v_fields, vulns_raw = _read_csv(src / "vulnerabilities.csv")
    unmatched: Counter[str] = Counter()
    kept: list[dict[str, str]] = []
    dropped = 0
    asset_rewrites = 0
    ctl_trimmed = 0
    for row in vulns_raw:
        assets_val = (row.get("assets") or "").strip()
        if assets_val in asset_names:
            row["assets"] = assets_val
        elif assets_val in asset_ref_ids:
            row["assets"] = ref_to_name.get(assets_val, assets_val)
            asset_rewrites += 1
        else:
            parts = [p.strip() for p in assets_val.replace(";", "|").split("|") if p.strip()]
            mapped_parts: list[str] = []
            ok = True
            for part in parts:
                if part in asset_names:
                    mapped_parts.append(part)
                elif part in asset_ref_ids:
                    mapped_parts.append(ref_to_name.get(part, part))
                    asset_rewrites += 1
                else:
                    ok = False
                    break
            if ok and mapped_parts:
                row["assets"] = "|".join(mapped_parts)
            elif drop_unmatched_asset_vulns:
                unmatched[assets_val or "<empty>"] += 1
                dropped += 1
                continue
        ac = (row.get("applied_controls") or "").strip()
        if ac:
            parts = [p.strip() for p in re.split(r"[,;|]", ac) if p.strip()]
            kept_parts = [p for p in parts if p in ctl_ref_ids or p in ctl_names]
            if len(kept_parts) != len(parts):
                ctl_trimmed += 1
            row["applied_controls"] = ",".join(kept_parts)
        rid = (row.get("ref_id") or "").strip()
        _orig_name = row.get("name") or ""
        row["name"] = unique_display_name(_orig_name, rid, max_len=vuln_name_max)
        _preserve_full_title_in_description(row, _orig_name, row["name"])
        kept.append(row)
    _write_csv(dest / "vulnerabilities.csv", v_fields, kept)
    stats["counts"]["vulnerabilities"] = len(kept)
    stats["paths"]["vulnerabilities"] = str(dest / "vulnerabilities.csv")
    stats["pq4"] = {
        "source_vuln_rows": len(vulns_raw),
        "dropped_no_asset_row": dropped,
        "kept_vuln_rows": len(kept),
        "unmatched_asset_values": dict(unmatched.most_common(20)),
        "asset_ref_rewrites": asset_rewrites,
        "ctl_fk_rows_trimmed": ctl_trimmed,
    }

    if (src / "risk_scenarios.csv").is_file():
        # Preserve byte-oriented copy for non-mapped scenario export.
        text = (src / "risk_scenarios.csv").read_text(encoding="utf-8")
        (dest / "risk_scenarios.csv").write_text(text, encoding="utf-8")
        stats["paths"]["risk_scenarios"] = str(dest / "risk_scenarios.csv")

    def _dups(rows: list[dict[str, str]]) -> dict[str, int]:
        c = Counter((r.get("name") or "").strip() for r in rows)
        return {k: v for k, v in c.items() if k and v > 1}

    def _maxlen(rows: list[dict[str, str]]) -> int:
        return max((len((r.get("name") or "")) for r in rows), default=0)

    _ev_for_len = locals().get("evidences") or []
    stats["max_name_len"] = {
        "assets": _maxlen(assets),
        "applied_controls": _maxlen(controls),
        "findings": _maxlen(findings),
        "vulnerabilities": _maxlen(kept),
        "evidences": _maxlen(_ev_for_len),
    }
    stats["dup_names"] = {
        "assets": _dups(assets),
        "applied_controls": _dups(controls),
        "findings": _dups(findings),
        "vulnerabilities": _dups(kept),
    }
    stats["dup_name_counts"] = {k: len(v) for k, v in stats["dup_names"].items()}
    stats["ok"] = (
        stats["dup_name_counts"]["applied_controls"] == 0
        and stats["dup_name_counts"]["findings"] == 0
        and stats["dup_name_counts"]["vulnerabilities"] == 0
        and stats["max_name_len"]["vulnerabilities"] <= vuln_name_max
        and stats["max_name_len"]["findings"] <= other_name_max
        and stats["max_name_len"]["applied_controls"] <= other_name_max
        and stats["max_name_len"]["assets"] <= other_name_max
        and stats["max_name_len"]["evidences"] <= other_name_max
    )
    return stats


def chunk_plan_for_mapped(
    mapped_dir: Path,
    *,
    chunk_size: int = DEFAULT_VULN_CHUNK,
    dest_dir: Path | None = None,
) -> dict[str, Any]:
    """PQ-9 plan (+ optional chunk files) for a mapped ciso-assistant tree."""
    vuln = Path(mapped_dir) / "vulnerabilities.csv"
    dest = Path(dest_dir) if dest_dir is not None else Path(mapped_dir) / "vuln-chunks"
    return write_vuln_chunks(vuln, dest, chunk_size=chunk_size)
