"""Evidence rows are sensor-run attestations, not screenshot dumps."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def _family(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    return str(rec.get("category") or extra.get("service") or extra.get("check_id") or "posture")


def build_evidence_rows(
    sources: list[str],
    findings: list[dict[str, Any]],
    canonical_count: int,
    now: str,
) -> list[list[str]]:
    """One row per producing sensor, loader run, plus high/critical families."""
    rows: list[list[str]] = []
    seen: set[str] = set()

    def add(name: str, desc: str) -> None:
        if name in seen:
            return
        seen.add(name)
        rows.append([name, desc])

    for src in sources:
        add(f"{src} collector run", f"Canonical records ingested from {src} at {now}")

    families: dict[tuple[str, str], list[str]] = defaultdict(list)
    for rec in findings:
        if str(rec.get("severity")) not in {"high", "critical"}:
            continue
        src = str(rec.get("source") or "sensor")
        fam = _family(rec)
        ref = str(rec.get("ref_id") or rec.get("name") or "finding")
        families[(src, fam)].append(ref)

    if not families:
        for src in sources:
            add(
                f"{src} high-critical attestation",
                f"No high/critical findings from {src} in this run (source file out/canonical).",
            )
    else:
        for (src, fam), refs in sorted(families.items()):
            name = f"{src} {fam} high-critical attestation"
            listed = ", ".join(refs[:8])
            more = f" (+{len(refs) - 8} more)" if len(refs) > 8 else ""
            add(
                name,
                f"{len(refs)} high/critical finding(s) from {src} family {fam}; refs {listed}{more}. "
                f"Source file out/canonical (sensor {src}).",
            )

    add("grc-loader run", f"Normalized {canonical_count} canonical records at {now}")
    return rows
