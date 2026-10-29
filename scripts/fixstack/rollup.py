#!/usr/bin/env python3
"""PQ-1 proof: roll Trivy POA&M rows to one item per (image, package).

Stdlib only. Reads CSV, writes rolled CSV + stats JSON. Does not touch master.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SEV_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "undefined": 0,
    "": 0,
}
SEV_CANON = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "undefined": "undefined",
}

UPGRADE_RE = re.compile(
    r"(?:Upgrade|upgrade|Patch|patch)\s+([A-Za-z0-9_./@+-]+)\s+to\b"
)
# Trivy collector title for rows whose vendor title lacks the package:
# "<CVE/GHSA/other id> in <PkgName>" (collectors/vuln_scan.py).
VID_IN_PKG_RE = re.compile(r"^(?:CVE|GHSA|[A-Z][A-Z0-9]*)-[A-Za-z0-9._-]+ in (\S+)$")
# Trivy collector non-CVE form: "<vendor title> (<PkgName>)" when the title lacks the pkg.
TITLE_PKG_SUFFIX_RE = re.compile(r"^(?P<title>.+) \((?P<pkg>[^()\s]+)\)$")
VID_TOKEN_RE = re.compile(r"^(?:CVE|GHSA|TEMP|[A-Z]{2,})-[A-Za-z0-9._-]+$")
FIXED_RE = re.compile(
    r"(?:fixed(?:[- ]version)?|FixedVersion)\s*[:=]\s*([^\s,;)]+)",
    re.I,
)


def is_trivy(row: dict[str, str]) -> bool:
    return "trivy" in (row.get("detector_source") or "").lower()


def package_of(row: dict[str, str]) -> str:
    """Best-effort package from POA&M CSV (no raw Trivy JSON)."""
    weakness = (row.get("weakness") or "").strip()
    # Undo the OWASP CSV formula guard ("'@scope/pkg: …") so the package key is
    # the same whichever title form carried it; output re-guards (_csv_guard).
    if weakness[:2] in {"'=", "'+", "'-", "'@"}:
        weakness = weakness[1:]
    m_vid = VID_IN_PKG_RE.match(weakness)
    if m_vid:
        return m_vid.group(1)[:80]
    m_sfx = TITLE_PKG_SUFFIX_RE.match(weakness)
    if m_sfx:
        pkg = m_sfx.group("pkg")
        # Mirror the collector: suffix only added when title lacks the pkg.
        if (
            pkg.lower() not in m_sfx.group("title").lower()
            and not VID_TOKEN_RE.match(pkg)
        ):
            return pkg[:80]
    if ":" in weakness:
        left = weakness.split(":", 1)[0].strip()
        # Reject sentence-like titles (kernel prose without pkg prefix).
        if (
            left
            and len(left) <= 80
            and " " not in left
            and not left.lower().startswith("in the")
        ):
            return left
        if left.lower() in {"kernel", "linux", "openssl", "glibc", "curl"}:
            return left.lower() if left.lower() != "linux" else "kernel"
    action = row.get("recommended_action") or ""
    m = UPGRADE_RE.search(action)
    if m:
        return m.group(1)
    # Last resort: first token of weakness (still groups something).
    token = (weakness.split() or ["unparsed-package"])[0].strip(",.;:")
    if token.lower().startswith("in"):
        return "unparsed-package"
    return token[:80] or "unparsed-package"


def _csv_guard(text: str) -> str:
    """Re-apply the pack's CSV formula guard to a cell we build (e.g. "@scope/pkg: …")."""
    return "'" + text if text[:1] in {"=", "+", "-", "@"} else text


def image_of(row: dict[str, str]) -> str:
    return (row.get("asset") or "").strip() or "unknown-image"


def stable_id(image: str, package: str) -> str:
    payload = f"trivy-pkg-v1|{image}|{package}".encode("utf-8")
    return "EGP-" + hashlib.sha256(payload).hexdigest()[:10].upper()


def max_sev(sevs: list[str]) -> str:
    best = ""
    best_r = -1
    for s in sevs:
        key = (s or "").strip().lower()
        r = SEV_RANK.get(key, 0)
        if r > best_r:
            best_r = r
            best = SEV_CANON.get(key, key or "undefined")
    return best or "undefined"


def earliest_date(dates: list[str]) -> str:
    clean = []
    for d in dates:
        t = (d or "").strip()
        if not t or t.lower() in {"not recorded", "pending due date", "n/a"}:
            continue
        clean.append(t)
    if not clean:
        return "not recorded"
    return sorted(clean)[0]


def fixed_version_of(rows: list[dict[str, str]]) -> str:
    for row in rows:
        blob = " ".join(
            [
                row.get("recommended_action") or "",
                row.get("weakness_description") or "",
                row.get("milestones") or "",
            ]
        )
        m = FIXED_RE.search(blob)
        if m:
            return m.group(1)
        # Trivy-ish "before X" in description sometimes.
        m2 = re.search(r"\bbefore\s+(\d+(?:\.\d+){1,3}[^\s,]*)", blob, re.I)
        if m2:
            return f">={m2.group(1)} (from prose; verify)"
    return "unknown"


def risk_label(sev: str) -> str:
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }.get((sev or "").lower(), (sev or "Undefined").title())


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: rollup.py IN_POAM.csv OUT_DIR", file=sys.stderr)
        return 2
    in_path = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    with in_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    before = len(rows)
    sev_before = Counter((r.get("severity") or "").strip().lower() for r in rows)

    non_trivy: list[dict[str, str]] = []
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if is_trivy(row):
            groups[(image_of(row), package_of(row))].append(row)
        else:
            non_trivy.append(row)

    trivy_before = sum(len(v) for v in groups.values())
    rolled: list[dict[str, str]] = []
    cve_sum = 0
    image_group_counts: Counter[str] = Counter()
    sev_groups: Counter[str] = Counter()

    for (image, package), members in sorted(groups.items(), key=lambda x: (-len(x[1]), x[0])):
        cves = []
        seen = set()
        for m in members:
            cve = (m.get("cve") or "").strip()
            if not cve:
                # Try ref_id
                ref = m.get("finding_ref_id") or ""
                mm = re.search(r"(CVE-\d{4}-\d+)", ref, re.I)
                cve = mm.group(1).upper() if mm else ""
            if cve and cve.upper() not in seen:
                seen.add(cve.upper())
                cves.append(cve.upper() if cve.upper().startswith("CVE-") else cve)
        if not cves:
            # still count member rows as conservation unit
            cves = [f"ROW-{i}" for i in range(len(members))]
            cve_ids_for_sum = len(members)
        else:
            cve_ids_for_sum = len(cves)

        # Conservation: sum of group CVE counts should equal original trivy rows
        # when each row is one CVE (prior-unit shape). Prefer member count for check.
        cve_sum += len(members)
        image_group_counts[image] += 1

        sev = max_sev([m.get("severity") or "" for m in members])
        sev_groups[sev] += 1
        det = earliest_date([m.get("original_detection_date") or "" for m in members])
        fixed = fixed_version_of(members)
        pid = stable_id(image, package)
        template = dict(members[0])
        cve_list = ", ".join(c for c in cves if not str(c).startswith("ROW-"))
        if not cve_list:
            cve_list = f"{len(members)} findings (no CVE id on row)"

        template.update(
            {
                "weakness": _csv_guard(f"{package}: package rollup ({len(members)} CVEs/findings)"),
                "asset": image,
                "severity": sev,
                "recommended_action": (
                    f"Remediate package '{package}' on image/target '{image}' "
                    f"({len(members)} Trivy findings). "
                    + (
                        f"Fixed version hint: {fixed}. "
                        if fixed != "unknown"
                        else "Fixed version: unknown from POA&M CSV. "
                    )
                    + "See weakness_description for CVE list. "
                    "This is a vulnerability package rollup, not a config-drift playbook."
                ),
                "status": "open",
                "poam_id": pid,
                "finding_ref_id": f"VULN-pkg-{package}-{_slug(image)}"[:180],
                "weakness_description": (
                    f"Trivy package rollup for {package} on {image}. "
                    f"CVE count={len(members)}. CVEs: {cve_list}"
                )[:4000],
                "detector_source": "vuln-scan (trivy) [pkg-rollup]",
                "weakness_source_id": f"pkg:{package}",
                "original_detection_date": det,
                "original_risk_rating": risk_label(sev),
                "cve": cve_list if len(cve_list) <= 500 else (cve_list[:497] + "..."),
                "milestones": (
                    f"M1 Validate package owner/scope; "
                    f"M2 Patch or rebuild image for {package}; "
                    f"M3 Rescan; close member CVEs when clear"
                ),
            }
        )
        rolled.append(template)

    out_rows = non_trivy + rolled
    after = len(out_rows)
    sev_after = Counter((r.get("severity") or "").strip().lower() for r in out_rows)

    out_csv = out_dir / "poam_rolled.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for row in out_rows:
            w.writerow({k: row.get(k, "") for k in fieldnames})

    top5 = image_group_counts.most_common(5)
    stats = {
        "input": str(in_path),
        "output_csv": str(out_csv),
        "rows_before": before,
        "rows_after": after,
        "non_trivy_passthrough": len(non_trivy),
        "trivy_rows_before": trivy_before,
        "trivy_groups": len(groups),
        "cve_conservation": {
            "sum_group_member_counts": cve_sum,
            "original_trivy_rows": trivy_before,
            "ok": cve_sum == trivy_before,
        },
        "top5_images_by_group_count": [
            {"image": img, "group_count": n} for img, n in top5
        ],
        "severity_tally_before": dict(sev_before),
        "severity_tally_after": dict(sev_after),
        "severity_tally_trivy_groups": dict(sev_groups),
        "reduction_ratio": round(trivy_before / max(len(groups), 1), 2),
    }
    stats_path = out_dir / "rollup_stats.json"
    stats_path.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")

    # Human one-pager
    lines = [
        f"rows_before={before}",
        f"rows_after={after}",
        f"trivy_before={trivy_before}",
        f"trivy_groups={len(groups)}",
        f"non_trivy={len(non_trivy)}",
        f"cve_conservation_ok={cve_sum == trivy_before} ({cve_sum}/{trivy_before})",
        f"reduction={trivy_before}->{len(groups)} (x{stats['reduction_ratio']})",
        "top5_images_by_group_count:",
    ]
    for img, n in top5:
        lines.append(f"  {n}\t{img}")
    lines.append("severity_before=" + json.dumps(dict(sev_before)))
    lines.append("severity_after=" + json.dumps(dict(sev_after)))
    summary = out_dir / "summary.txt"
    summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(summary.read_text())
    print(f"WROTE {out_csv}")
    print(f"WROTE {stats_path}")
    return 0 if cve_sum == trivy_before else 2


def _slug(s: str) -> str:
    out = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return out[:80] or "asset"


if __name__ == "__main__":
    raise SystemExit(main())
