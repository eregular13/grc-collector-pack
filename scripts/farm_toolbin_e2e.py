#!/usr/bin/env python3
"""DEMO quiet→loud e2e: FARM_TOOL_BIN=lab stubs. Not pack in/. No internet.

plan → discover (stub nmap) → deepen (stub nessus, small batch) →
external plan-only → ingest → Layer C under farm/work/e2e.
Stubs write fixture-shaped stdout. LICENSE-LOCK names are not invoked.
Does not start compose. Does not POST /api/risks.
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
ENV_KEYS = (
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
    "FARM_TOOL_BIN",
    "PATH",
)


def _poam_rows(path: Path) -> int:
    if not path.is_file():
        return 0
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return max(0, len(lines) - 1)


def farm_toolbin_e2e(root: Path | None = None) -> dict:
    root = Path(root or ROOT)
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    try:
        return _run(root)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _run(root: Path) -> dict:
    lab = root / "farm" / "tool-bin" / "lab"
    work = root / "farm" / "work" / "e2e"
    work_in = work / "in"
    work_out = work / "out"
    orch = work / "orch"
    for folder in (work_in, work_out, orch):
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)

    os.environ["FARM_TOOL_BIN"] = str(lab)
    os.environ["PATH"] = str(lab) + os.pathsep + os.environ.get("PATH", "")
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

    from dropbox.orchestrator.pipeline import orchestrate
    from dropbox.scope import GateError, load_scope
    from farm.adapters.stubs import run_slot

    scope = load_scope(root / "dropbox" / "SCOPE.yaml")
    for name in ("nmap", "nessuscli", "curl", "testssl", "lynis"):
        if name not in scope.allow_tools:
            scope.allow_tools.append(name)
    if not scope.stage_deepen:
        raise RuntimeError("DEMO SCOPE must have orchestrator.stages.deepen true for toolbin-e2e")

    summary = orchestrate(scope, live=True, dest_in=work_in)
    if summary.get("external", {}).get("live") is True:
        raise RuntimeError("external stage must stay plan-only")

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
    (work_in / "nmap" / "FARM-E2E-DEMO.txt").write_text(
        "DEMO — farm-toolbin-e2e stubs. Not a client estate. Not pack in/.\n",
        encoding="utf-8",
    )

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

    nmap_hits = sorted(p.name for p in (work_in / "nmap").glob("dropbox-discover-*") if p.is_file())
    vuln_hits = sorted(p.name for p in (work_in / "vuln").glob("dropbox-deepen-*") if p.is_file())
    summary_path = work_out / "summary.json"
    counts = json.loads(summary_path.read_text(encoding="utf-8"))
    poam = work_out / "poam" / "poam.csv"
    ciso = work_out / "ciso-assistant"
    ciso_files = sorted(p.name for p in ciso.glob("*.csv")) if ciso.is_dir() else []
    pack_leaks = [
        str(p.relative_to(root))
        for p in (root / "in").rglob("*")
        if p.is_file() and p.name != ".gitkeep"
    ]
    lock_ok = True
    try:
        run_slot("nuclei", work / "lock.out", list(scope.allow_tools) + ["nuclei"], live=True)
        lock_ok = False
    except GateError as exc:
        lock_ok = "LICENSE-LOCK" in str(exc)

    stamp = {
        "status": "pass",
        "demo": True,
        "label": "DEMO — farm-toolbin-e2e stubs, not a client estate",
        "pack_in_used": False,
        "pack_in_leaks": pack_leaks,
        "in_dir": str(work_in),
        "out_dir": str(work_out),
        "farm_tool_bin": str(lab),
        "live_discover": (summary.get("discover") or {}).get("mode") == "live",
        "live_deepen": (summary.get("deepen") or {}).get("mode") == "live",
        "external_plan_only": bool((summary.get("external") or {}).get("plan_only")),
        "discover_tool": (summary.get("discover") or {}).get("tool") or "",
        "deepen_tool": (summary.get("deepen") or {}).get("tool") or "",
        "artifacts": {"nmap": nmap_hits, "vuln": vuln_hits},
        "ciso_files": ciso_files,
        "license_lock_ok": lock_ok,
        "counts": {
            "assets": counts.get("assets"),
            "findings": counts.get("findings"),
            "vulnerabilities": counts.get("vulnerabilities"),
            "evidences": counts.get("evidences"),
            "poam": _poam_rows(poam),
            "demo": counts.get("demo"),
        },
        "poam": str(poam),
        "note": "DEMO stubs only. No internet. No compose. Not pack in/.",
    }
    if pack_leaks:
        stamp["status"] = "fail"
        stamp["reason"] = "pack in/ was written"
    elif not nmap_hits:
        stamp["status"] = "fail"
        stamp["reason"] = "discover artifacts missing under in/nmap/"
    elif not vuln_hits:
        stamp["status"] = "fail"
        stamp["reason"] = "deepen artifacts missing under in/vuln/"
    elif not poam.is_file() or not ciso_files:
        stamp["status"] = "fail"
        stamp["reason"] = "CISO/POA&M outputs missing"
    elif counts.get("demo") is not True:
        stamp["status"] = "fail"
        stamp["reason"] = "summary.demo is not true"
    elif not stamp["external_plan_only"]:
        stamp["status"] = "fail"
        stamp["reason"] = "external was not plan-only"
    elif not lock_ok:
        stamp["status"] = "fail"
        stamp["reason"] = "LICENSE-LOCK did not refuse nuclei"
    elif not stamp["live_discover"] or not stamp["live_deepen"]:
        stamp["status"] = "fail"
        stamp["reason"] = "discover/deepen stub invoke did not run"
    (work / "farm-toolbin-e2e.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    return stamp


def main() -> int:
    stamp = farm_toolbin_e2e()
    print(json.dumps(stamp, indent=2))
    print(
        f"FARM_TOOLBIN_E2E={stamp['status']} demo={stamp['demo']} "
        f"assets={stamp['counts']['assets']} poam={stamp['counts']['poam']} "
        f"external_plan_only={stamp.get('external_plan_only')}"
    )
    if stamp.get("status") != "pass":
        return 1
    print("Estate is DEMO stubs + fixtures. Not a client. Not pack in/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
