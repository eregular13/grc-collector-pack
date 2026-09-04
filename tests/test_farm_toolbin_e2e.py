"""DEMO farm-toolbin-e2e: quiet→loud stubs under farm/work/e2e. Not pack in/."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dropbox.scope import GateError
from farm.adapters.stubs import run_slot

ROOT = Path(__file__).resolve().parents[1]


def test_farm_toolbin_e2e_quiet_to_loud_under_farm_work() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "farm_toolbin_e2e.py")],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    stamp_path = ROOT / "farm" / "work" / "e2e" / "farm-toolbin-e2e.json"
    stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["demo"] is True
    assert stamp["pack_in_used"] is False
    assert stamp["pack_in_leaks"] == []
    assert stamp["external_plan_only"] is True
    assert stamp["live_discover"] is True
    assert stamp["live_deepen"] is True
    assert stamp["discover_tool"] == "nmap"
    assert stamp["deepen_tool"] in {"nessus", "nessuscli"}
    assert stamp["artifacts"]["nmap"]
    assert stamp["artifacts"]["vuln"]
    assert stamp["ciso_files"]
    assert stamp["license_lock_ok"] is True
    assert stamp["counts"]["demo"] is True
    assert stamp["counts"]["assets"] >= 20
    assert stamp["counts"]["findings"] >= 20
    assert stamp["counts"]["evidences"] >= 8
    assert stamp["counts"]["poam"] >= 8
    work_in = Path(stamp["in_dir"])
    assert "farm/work/e2e" in stamp["in_dir"]
    assert any((work_in / "nmap").glob("dropbox-discover-*"))
    assert any((work_in / "vuln").glob("dropbox-deepen-*"))
    assert Path(stamp["poam"]).is_file()
    ciso = Path(stamp["out_dir"]) / "ciso-assistant"
    assert list(ciso.glob("*.csv"))
    pack = [p for p in (ROOT / "in").rglob("*") if p.is_file() and p.name != ".gitkeep"]
    assert pack == []
    gnmap = next((work_in / "nmap").glob("dropbox-discover-*.gnmap"))
    text = gnmap.read_text(encoding="utf-8")
    assert "DEMO" in text
    assert "app-01.demo.internal" in text


def test_farm_toolbin_e2e_license_lock_still_refuses() -> None:
    dest = ROOT / "farm" / "work" / "e2e-lock.out"
    with pytest.raises(GateError, match="LICENSE-LOCK"):
        run_slot("nuclei", dest, ["nuclei", "nmap"], target="10.20.30.5", live=True)
    with pytest.raises(GateError, match="LICENSE-LOCK"):
        run_slot("openvas", dest, ["openvas", "nessus"], target="10.20.30.5", live=True)
