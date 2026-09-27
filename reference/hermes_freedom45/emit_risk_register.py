#!/usr/bin/env python3
"""Emit risk register + POA&M from env-eval sensory findings (and optional pack rows).

Product core: quick env scan → risk register + POA&M leave-behind.
No network. No RR API. Defensive only.
"""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from control_map import map_finding


def _map_controls(title: str, sensor: str = "", description: str = "") -> tuple[list[str], str, str, str]:
    h = map_finding(title=title, sensor=sensor, description=description)
    return list(h.controls), h.action, h.priority, h.rule_id


def _sev_rank(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get((s or "info").lower(), 0)


def findings_from_sensory(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for fi in data.get("findings") or []:
        if not isinstance(fi, dict):
            continue
        title = str(fi.get("title") or fi.get("name") or "finding")
        sensor = str(fi.get("sensor") or "")
        desc = str(fi.get("description") or "")
        sev = str(fi.get("severity") or "info").lower()
        asset = str(fi.get("target") or data.get("client_target") or "unknown")
        ctrls, action, prio, rule_id = _map_controls(title, sensor, desc)
        # prefer finding remediation if present and action is generic
        rem = str(fi.get("remediation") or "").strip()
        if rem and rule_id != "unmapped":
            # keep mapped action as primary; append specific if different
            if rem.lower() not in action.lower():
                action = f"{action} | Detail: {rem[:400]}"
        elif rem and rule_id == "unmapped":
            action = rem[:800]
        # pull framework tags from finding.controls if present
        extra_ctrls = []
        fc = fi.get("controls") or fi.get("control_map") or {}
        if isinstance(fc, dict):
            for fw, ids in fc.items():
                if isinstance(ids, list):
                    for i in ids:
                        extra_ctrls.append(f"{fw}:{i}" if ":" not in str(i) and "." not in str(i) else str(i))
        # merge unique
        seen = set()
        merged = []
        for c in list(ctrls) + extra_ctrls:
            if c and c not in seen and c != "UNMAPPED":
                seen.add(c)
                merged.append(c)
        if not merged:
            merged = ["UNMAPPED"]
        rid = str(fi.get("id") or f"rr-{abs(hash(title+asset))%10**10}")
        out.append(
            {
                "risk_id": rid,
                "title": title,
                "asset": asset,
                "severity": sev,
                "likelihood": "medium" if _sev_rank(sev) >= 2 else "low",
                "impact": sev if _sev_rank(sev) >= 2 else "low",
                "status": "open",
                "sensor": sensor,
                "description": desc[:2000],
                "control_refs": merged,
                "control_rule": rule_id,
                "remediation_priority": prio,
                "recommended_action": action or rem,
                "owner": "",
                "due_date": "",
                "source": "env-eval",
            }
        )
    return out


def write_register(rows: list[dict[str, Any]], dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    # sort critical first
    rows = sorted(rows, key=lambda r: -_sev_rank(str(r.get("severity"))))
    (dest / "risk_register.json").write_text(
        json.dumps(
            {
                "schema": "evergreen.risk_register.v1",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "count": len(rows),
                "risks": rows,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    fields = [
        "risk_id",
        "title",
        "asset",
        "severity",
        "likelihood",
        "impact",
        "status",
        "control_refs",
        "control_rule",
        "remediation_priority",
        "recommended_action",
        "owner",
        "due_date",
        "sensor",
        "source",
        "description",
    ]
    with (dest / "risk_register.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            row = dict(r)
            row["control_refs"] = ";".join(row.get("control_refs") or [])
            w.writerow(row)

    # POA&M view
    poam_fields = [
        "weakness",
        "asset",
        "severity",
        "control_refs",
        "control_rule",
        "remediation_priority",
        "recommended_action",
        "owner",
        "milestone",
        "status",
        "source",
        "risk_id",
    ]
    with (dest / "poam.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=poam_fields)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "weakness": r.get("title"),
                    "asset": r.get("asset"),
                    "severity": r.get("severity"),
                    "control_refs": ";".join(r.get("control_refs") or []),
                    "control_rule": r.get("control_rule") or "",
                    "remediation_priority": r.get("remediation_priority") or "",
                    "recommended_action": r.get("recommended_action"),
                    "owner": r.get("owner") or "",
                    "milestone": r.get("due_date") or "",
                    "status": r.get("status") or "open",
                    "source": r.get("source"),
                    "risk_id": r.get("risk_id"),
                }
            )
    poam_json = [
        {
            "weakness": r.get("title"),
            "asset": r.get("asset"),
            "severity": r.get("severity"),
            "control_refs": r.get("control_refs"),
            "recommended_action": r.get("recommended_action"),
            "owner": r.get("owner") or "",
            "status": r.get("status") or "open",
            "risk_id": r.get("risk_id"),
            "source": r.get("source"),
        }
        for r in rows
    ]
    (dest / "poam.json").write_text(json.dumps(poam_json, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="env-eval sensory → risk register + POA&M")
    ap.add_argument("--sensory", required=True, help="path to sensory-for-feed.json or sensory.json")
    ap.add_argument("--out", required=True, help="output directory")
    args = ap.parse_args()
    sensory = Path(args.sensory)
    out = Path(args.out)
    rows = findings_from_sensory(sensory)
    write_register(rows, out)
    print(f"risk_register risks={len(rows)} out={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
