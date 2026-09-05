#!/usr/bin/env python3
"""DEMO farm lab: plan → fixture discover → ingest → Layer C. Not pack in/.

Never --live. Never POST /api/risks. Estate is DEMO fixtures, not a client.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SENSORS = ("cloud", "nmap", "vuln", "wazuh", "identity", "easm", "k8s", "code", "saas")
COLLECTORS = (
    "cloud_prowler.py",
    "inventory_nmap.py",
    "vuln_scan.py",
    "host_wazuh.py",
    "identity_ad.py",
    "easm.py",
    "k8s_kubescape.py",
    "code_secrets.py",
    "saas_idp.py",
    "grc_loader.py",
)


def farm_lab(root: Path | None = None) -> dict:
    root = Path(root or ROOT)
    keys = (
        "IN_DIR",
        "OUT_DIR",
        "DROPBOX_ORCH_DIR",
        "DROPBOX_DEMO",
        "DROPBOX_LIVE",
        "DRY_RUN",
        "GRC_LIVE_SCAN",
        "CISO_PUSH",
        "RISKREADY_PUSH",
        "PYTHONPATH",
    )
    saved = {key: os.environ.get(key) for key in keys}
    try:
        return _farm_lab(root)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _farm_lab(root: Path) -> dict:
    work = root / "farm" / "work"
    work_in = work / "in"
    work_out = work / "out"
    orch = work / "orch"
    for folder in (work_in, work_out, orch):
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)

    os.environ["IN_DIR"] = str(work_in)
    os.environ["OUT_DIR"] = str(work_out)
    os.environ["DROPBOX_ORCH_DIR"] = str(orch)
    os.environ["DROPBOX_DEMO"] = "1"
    os.environ["DROPBOX_LIVE"] = "0"
    os.environ["DRY_RUN"] = "1"
    os.environ["GRC_LIVE_SCAN"] = "0"
    os.environ["CISO_PUSH"] = "0"
    os.environ["RISKREADY_PUSH"] = "0"
    os.environ.setdefault("PYTHONPATH", str(root))

    from dropbox.orchestrator.pipeline import ingest_stage, orchestrate
    from dropbox.scope import load_scope

    scope = load_scope()
    plan = orchestrate(scope, live=False, dest_in=work_in)

    disc = orch / "discover"
    disc.mkdir(parents=True, exist_ok=True)
    fixture_nmap = root / "fixtures" / "demo" / "nmap"
    if fixture_nmap.is_dir():
        for path in fixture_nmap.iterdir():
            if path.is_file() and path.suffix.lower() in {".gnmap", ".xml", ".nmap"}:
                shutil.copy2(path, disc / path.name)
    ingest = ingest_stage(scope, dest_in=work_in)

    src = root / "fixtures" / "demo"
    for sensor in SENSORS:
        dest = work_in / sensor
        dest.mkdir(parents=True, exist_ok=True)
        fixture = src / sensor
        if not fixture.is_dir():
            continue
        for path in fixture.iterdir():
            if path.is_file() and not (dest / path.name).exists():
                shutil.copy2(path, dest / path.name)
    (work_in / "nmap" / "FARM-DEMO.txt").write_text("DEMO — not a client estate\n", encoding="utf-8")

    env = os.environ.copy()
    env["IN_DIR"] = str(work_in)
    env["OUT_DIR"] = str(work_out)
    env["PYTHONPATH"] = str(root)
    for name in COLLECTORS:
        proc = subprocess.run(
            [sys.executable, str(root / "collectors" / name)],
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"{name} exit {proc.returncode}: {(proc.stderr or proc.stdout)[-400:]}")

    summary_path = work_out / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    poam = work_out / "poam" / "poam.csv"
    stamp = {
        "status": "pass",
        "demo": True,
        "label": "DEMO — not a client estate",
        "pack_in_used": False,
        "in_dir": str(work_in),
        "out_dir": str(work_out),
        "plan": {
            "shards": (plan.get("discover") or {}).get("shard_count"),
            "batches": (plan.get("deepen") or {}).get("batch_count"),
            "destroyed": (plan.get("discover") or {}).get("destroyed"),
            "live": False,
        },
        "ingest_copied": list(ingest.get("copied") or []),
        "counts": {
            "assets": summary.get("assets"),
            "findings": summary.get("findings"),
            "vulnerabilities": summary.get("vulnerabilities"),
            "evidences": summary.get("evidences"),
            "poam": _poam_rows(poam),
            "demo": summary.get("demo"),
        },
        "poam": str(poam),
        "note": "farm-lab is DEMO fixtures. Not a client estate. Not pack in/.",
    }
    if summary.get("demo") is not True:
        stamp["status"] = "fail"
        stamp["reason"] = "summary.demo is not true"
    (work / "farm-lab.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    return stamp


def _poam_rows(path: Path) -> int:
    if not path.is_file():
        return 0
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return max(0, len(lines) - 1)


def main() -> int:
    stamp = farm_lab()
    print(json.dumps(stamp, indent=2))
    print(
        f"FARM_LAB={stamp['status']} demo={stamp['demo']} "
        f"assets={stamp['counts']['assets']} findings={stamp['counts']['findings']} "
        f"poam={stamp['counts']['poam']}"
    )
    if stamp.get("status") != "pass":
        return 1
    print("Estate is DEMO fixtures. Not a client.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
