"""E: opt-in CISO export rollup, one risk/control/vulnerability per POA&M parent.

The pack SoR stays one row per CVE. fixstack only rewrites poam.csv, so the CISO
export keeps ~one risk scenario per CVE. With ``rollup_poam_dir`` set, the
wizard path folds every member of a multi-member POA&M parent into one
RSK-/CTL-/VULN-rollup-<poam_id> row. Singletons and non-POA&M rows pass
through unchanged. Default off: nothing here runs.
The member->parent mapping is written to the export metadata (rollup-map.json).
"""
from __future__ import annotations

import csv
import io
from collections import OrderedDict
from pathlib import Path
from typing import Any

LEVELS = ["", "Very Low", "Low", "Moderate", "Medium", "High", "Very High"]
SEV = ["", "Information", "Low", "Medium", "High", "Critical"]
ROLLED_DISPOSITIONS = ("rolled_into", "renamed_")


def _read(path: Path, delimiter: str | None = None) -> tuple[list[str], list[dict[str, str]], str]:
    text = path.read_text(encoding="utf-8")
    if delimiter is None:
        head = text.splitlines()[0] if text else ""
        delimiter = ";" if head.count(";") > head.count(",") else ","
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
    rows = [{k: (v or "") for k, v in r.items()} for r in reader]
    return list(reader.fieldnames or []), rows, delimiter


def _write(path: Path, fields: list[str], rows: list[dict[str, str]], delimiter: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, delimiter=delimiter, lineterminator="\n",
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def _max(values: list[str], order: list[str]) -> str:
    best = ""
    for v in values:
        v = (v or "").strip()
        if v in order and order.index(v) > order.index(best if best in order else ""):
            best = v
    return best or next((v for v in values if v), "")


def parent_groups(poam_dir: Path) -> "OrderedDict[str, dict[str, Any]]":
    """parent poam_id -> {"members": [ref suffix], "row": poam.csv row}."""
    poam_dir = Path(poam_dir)
    _, members, _ = _read(poam_dir / "poam_members.csv")
    mig: dict[str, str] = {}
    mpath = poam_dir / "poam-id-migration.csv"
    if mpath.is_file():
        for r in _read(mpath)[1]:
            disp = r.get("disposition") or ""
            if r.get("new_id") and disp.startswith(ROLLED_DISPOSITIONS):
                mig[r["old_id"]] = r["new_id"]
    plan = {r["poam_id"]: r for r in _read(poam_dir / "poam.csv")[1] if r.get("poam_id")}
    groups: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
    for m in members:
        ref = (m.get("finding_ref_id") or "").strip()
        egp = (m.get("egp_id") or m.get("poam_id") or "").strip()
        if not ref.startswith("VULN-") or not egp:
            continue
        parent = mig.get(egp, egp)
        if parent not in plan:
            continue
        g = groups.setdefault(parent, {"members": [], "row": plan[parent]})
        key = ref[len("VULN-"):]
        if key not in g["members"]:
            g["members"].append(key)
    return OrderedDict((k, v) for k, v in sorted(groups.items()) if len(v["members"]) > 1)


def rollup_ciso_dir(src: Path, poam_dir: Path, out: Path) -> dict[str, Any]:
    """Write a rolled copy of ``src`` (pack ciso-assistant/) into ``out``."""
    src, out = Path(src), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    groups = parent_groups(poam_dir)
    member_to_parent = {k: p for p, g in groups.items() for k in g["members"]}

    def fold(name: str, prefix: str, build) -> tuple[int, int]:
        path = src / name
        if not path.is_file():
            return 0, 0
        fields, rows, delim = _read(path)
        kept: list[dict[str, str]] = []
        bucket: "OrderedDict[str, list[dict[str, str]]]" = OrderedDict()
        for r in rows:
            rid = r.get("ref_id") or ""
            key = rid[len(prefix):] if rid.startswith(prefix) else None
            parent = member_to_parent.get(key) if key is not None else None
            if parent is None:
                kept.append(r)
                continue
            if parent not in bucket:
                bucket[parent] = []
                kept.append({"__parent__": parent})
            bucket[parent].append(r)
        out_rows = [build(r["__parent__"], bucket[r["__parent__"]], fields) if "__parent__" in r else r
                    for r in kept]
        _write(out / name, fields, out_rows, delim)
        return len(rows), len(out_rows)

    def _desc(parent: str, rows: list[dict[str, str]]) -> str:
        refs = ", ".join(r.get("ref_id") or "" for r in rows)
        return f"Rollup of {len(rows)} findings on POA&M {parent}: {refs}"[:4000]

    def _title(parent: str) -> str:
        return (groups[parent]["row"].get("weakness") or parent).lstrip("'")

    def b_vuln(parent: str, rows: list[dict[str, str]], fields: list[str]) -> dict[str, str]:
        r = dict(rows[0])
        assets = list(OrderedDict.fromkeys(a for x in rows for a in [x.get("assets") or ""] if a))
        r.update(ref_id=f"VULN-rollup-{parent}", name=_title(parent), description=_desc(parent, rows),
                 severity=_max([x.get("severity") or "" for x in rows], SEV),
                 assets="|".join(assets), applied_controls=f"CTL-rollup-{parent}")
        return r

    def b_ctl(parent: str, rows: list[dict[str, str]], fields: list[str]) -> dict[str, str]:
        r = dict(rows[0])
        r.update(ref_id=f"CTL-rollup-{parent}", name=f"Remediate: {_title(parent)}",
                 description=_desc(parent, rows))
        if "priority" in fields:
            pr = [x.get("priority") or "" for x in rows if (x.get("priority") or "").isdigit()]
            r["priority"] = min(pr, key=int) if pr else r.get("priority", "")
        return r

    def b_risk(parent: str, rows: list[dict[str, str]], fields: list[str]) -> dict[str, str]:
        r = dict(rows[0])
        r.update(ref_id=f"RSK-rollup-{parent}", name=_title(parent), description=_desc(parent, rows),
                 additional_controls=f"CTL-rollup-{parent}")
        for col in ("current_impact", "current_proba", "current_risk",
                    "residual_impact", "residual_proba", "residual_risk"):
            if col in fields:
                r[col] = _max([x.get(col) or "" for x in rows], LEVELS)
        assets = list(OrderedDict.fromkeys(x.get("assets") or "" for x in rows if x.get("assets")))
        if "assets" in fields:
            r["assets"] = rows[0].get("assets") if len(assets) == 1 else "|".join(assets)
        return r

    counts = {
        "vulnerabilities": fold("vulnerabilities.csv", "VULN-", b_vuln),
        "applied_controls": fold("applied_controls.csv", "CTL-vuln-", b_ctl),
        "risk_scenarios": fold("risk_scenarios.csv", "RSK-vuln-", b_risk),
    }
    for name in ("assets.csv", "evidences.csv", "findings.csv"):
        if (src / name).is_file():
            (out / name).write_bytes((src / name).read_bytes())
    return {
        "enabled": True,
        "basis": "poam_parent",
        "groups": len(groups),
        "members_folded": sum(len(g["members"]) for g in groups.values()),
        "counts_before_after": {k: {"before": a, "after": b} for k, (a, b) in counts.items()},
        "map": {p: [f"VULN-{k}" for k in g["members"]] for p, g in groups.items()},
    }
