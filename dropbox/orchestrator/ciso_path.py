"""CISO SoR path: landed KEEP-minimum files → existing collectors → loader.

Never falls back to fixtures/demo. Never POSTs. No invented prices.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from dropbox.orchestrator.estate import (
    assert_pack_in_unchanged,
    fingerprint,
    is_pack_in,
    pack_in_dir,
    write_pack_in_requested,
)
from dropbox.orchestrator.keepmin import inventory_keepmin, landed_sensors
from dropbox.scope import ROOT, load_scope

SENSOR_COLLECTORS = {
    "cloud": "cloud_prowler.py",
    "nmap": "inventory_nmap.py",
    "vuln": "vuln_scan.py",
    "wazuh": "host_wazuh.py",
    "identity": "identity_ad.py",
    "saas": "saas_idp.py",
    "honeypot": "honeypot.py",
}
CISO_CSVS = (
    "assets.csv",
    "applied_controls.csv",
    "evidences.csv",
    "findings.csv",
    "vulnerabilities.csv",
    "risk_scenarios.csv",
)

ENV_KEYS = (
    "IN_DIR",
    "OUT_DIR",
    "DRY_RUN",
    "GRC_LIVE_SCAN",
    "CISO_PUSH",
    "RISKREADY_PUSH",
    "DROPBOX_LIVE",
    "DROPBOX_DEMO",
    "PYTHONPATH",
)


def _has_input_files(sensor_dir: Path) -> bool:
    if not sensor_dir.is_dir():
        return False
    for path in sensor_dir.iterdir():
        if path.is_file() and path.name not in {".gitkeep", ".DS_Store", "SAMPLE.txt", "README.md"}:
            return True
    return False


def _land_keepmin(rows: list[dict[str, Any]], dest_in: Path) -> list[dict[str, Any]]:
    """Copy KEEP-minimum files into Layer C sensor dirs. Never subprocess."""
    landed: list[dict[str, Any]] = []
    for row in rows:
        src = Path(str(row.get("path") or ""))
        sensor = str(row.get("sensor") or "")
        if not sensor or not src.is_file():
            continue
        dest = dest_in / sensor
        dest.mkdir(parents=True, exist_ok=True)
        target = dest / src.name
        if src.resolve() != target.resolve():
            shutil.copy2(src, target)
        item = dict(row)
        item["dest"] = str(target)
        landed.append(item)
    return landed


def run_ciso_path(
    dest_in: Path,
    dest_out: Path,
    *,
    scope_path: Path | None = None,
    write_pack_in: bool | None = None,
) -> dict[str, Any]:
    """Parse only sensors that already have KEEP-minimum files. No demo fallback.

    Default file-drop is read-only against pack in/. Landing copies go under
    dest_out/in unless the operator opts in with --write-pack-in.
    """
    scope = load_scope(scope_path)
    dest_in = Path(dest_in)
    dest_out = Path(dest_out)
    dest_out.mkdir(parents=True, exist_ok=True)
    allow_write = write_pack_in_requested(explicit=write_pack_in)
    pack_before = fingerprint(pack_in_dir())
    rows = inventory_keepmin(dest_in)
    has_sensors = any(_has_input_files(dest_in / sensor) for sensor in SENSOR_COLLECTORS)
    if has_sensors:
        stage_in = dest_in
        landed = rows
    elif is_pack_in(dest_in) and allow_write:
        stage_in = dest_in
        landed = _land_keepmin(rows, stage_in)
    else:
        stage_in = dest_out / "in"
        landed = _land_keepmin(rows, stage_in)
    sensors = sorted(s for s in landed_sensors(landed) if s in SENSOR_COLLECTORS)
    sensors = [s for s in sensors if _has_input_files(stage_in / s)]
    sample = any(row.get("sample") for row in rows) or "DEMO" in scope.client_name.upper()
    caller_push = os.environ.get("CISO_PUSH", "0") == "1"
    caller_dry = os.environ.get("DRY_RUN", "1") == "1"
    posted = bool(caller_push and not caller_dry)
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    ran: list[str] = []
    try:
        os.environ["IN_DIR"] = str(stage_in)
        os.environ["OUT_DIR"] = str(dest_out)
        os.environ["DRY_RUN"] = "1"
        os.environ["GRC_LIVE_SCAN"] = "0"
        os.environ["CISO_PUSH"] = "1" if caller_push else "0"
        os.environ["RISKREADY_PUSH"] = "0"
        os.environ["DROPBOX_LIVE"] = "0"
        os.environ["DROPBOX_DEMO"] = "1" if sample else "0"
        os.environ.setdefault("PYTHONPATH", str(ROOT))
        env = os.environ.copy()
        env["IN_DIR"] = str(stage_in)
        env["OUT_DIR"] = str(dest_out)
        env["PYTHONPATH"] = str(ROOT)
        for sensor in sensors:
            name = SENSOR_COLLECTORS[sensor]
            proc = subprocess.run(
                [sys.executable, str(ROOT / "collectors" / name)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"{name} exit {proc.returncode}: {(proc.stderr or proc.stdout)[-400:]}")
            ran.append(name)
        if ran:
            loader = subprocess.run(
                [sys.executable, str(ROOT / "collectors" / "grc_loader.py")],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            if loader.returncode != 0:
                raise RuntimeError(
                    f"grc_loader exit {loader.returncode}: {(loader.stderr or loader.stdout)[-400:]}"
                )
            ran.append("grc_loader.py")
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    summary: dict[str, Any] = {}
    summary_path = dest_out / "summary.json"
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    ciso_dir = dest_out / "ciso-assistant"
    ciso_files = [
        str(ciso_dir / name) for name in CISO_CSVS if (ciso_dir / name).is_file()
    ]
    quote = {
        "kind": "quote-shaped",
        "posted": posted,
        "http": False,
        "price": None,
        "currency": None,
        "owner_due": "blank — human fills",
        "note": "no invented prices",
        "ciso_dir": str(ciso_dir),
        "poam_dir": str(dest_out / "poam"),
        "simplerisk_dir": str(dest_out / "simplerisk"),
    }
    quote_path = dest_out / "quote-shaped.json"
    quote_path.write_text(json.dumps(quote, indent=2) + "\n", encoding="utf-8")
    pack_after = fingerprint(pack_in_dir())
    pack_in_written = pack_before != pack_after
    if pack_in_written and not allow_write:
        assert_pack_in_unchanged(pack_before, pack_after, context="ciso")
    return {
        "ok": True,
        "live": False,
        "plan_only": True,
        "scope_gated": True,
        "client": scope.client_name,
        "demo": sample,
        "sample": sample,
        "client_keep": False if sample else bool(rows) and not sample,
        "dest_in": str(stage_in),
        "dest_out": str(dest_out),
        "landed": [row.get("name") for row in landed],
        "sensors": sensors,
        "collectors": ran,
        "counts": {
            "assets": summary.get("assets", 0),
            "findings": summary.get("findings", 0),
            "poam": summary.get("poam", 0),
            "demo": summary.get("demo"),
        },
        "posted": posted,
        "http": False,
        "ciso_push": "1" if caller_push else "0",
        "write_pack_in": allow_write,
        "pack_in_written": pack_in_written,
        "file_drop_read_only": not allow_write,
        "sor": "ciso-assistant",
        "ciso_dir": str(ciso_dir),
        "ciso_files": ciso_files,
        "clica": "Desktop: clica or CISO UI import of out/ciso-assistant/*.csv — do not invent FindingsAssessment UUIDs",
        "push_ciso": "Desktop: bash push_ciso.sh (no make/gh) after CSVs exist; dry unless CISO_PUSH=1 and DRY_RUN!=1",
        "wrap": "review-only",
        "quote": quote,
        "quote_path": str(quote_path),
        "note": (
            "Operator SoR is out/ciso-assistant/*.csv. Empty sensors do not "
            "load fixtures/demo. Default file-drop reads pack in/ only "
            "(--write-pack-in to land). This path never HTTP. RISKREADY_PUSH "
            "ignored. posted false unless CISO_PUSH=1 and DRY_RUN!=1."
        ),
    }
