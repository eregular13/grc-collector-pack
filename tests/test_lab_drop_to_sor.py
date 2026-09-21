"""LAB dest_in -> CISO without fixture reseed. LAB/DEMO != SAMPLE != client."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from scripts.prove_ciso import LAB_HONESTY_OK_LINE, prove_ciso
from shared.ciso_shape import assert_risk_register_and_poam
from tests.test_lab_prove_lock import stage_lab_drop_dest_in

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lab_drop_to_sor.sh"
PS1 = ROOT / "scripts" / "lab_drop_to_sor.ps1"


def test_lab_drop_scripts_document_honesty_and_call_use_existing_in() -> None:
    sh = SCRIPT.read_text(encoding="utf-8")
    ps1 = PS1.read_text(encoding="utf-8")
    assert SCRIPT.is_file()
    assert PS1.is_file()
    assert os.access(SCRIPT, os.X_OK)
    for blob in (sh, ps1):
        assert "DRY_RUN" in blob and "1" in blob
        assert "GRC_LIVE_SCAN" in blob
        assert "CISO_PUSH" in blob
        assert "RISKREADY_PUSH" in blob
        assert "DROPBOX_LIVE" in blob
        assert "PYTHONIOENCODING" in blob
        assert "prove_ciso" in blob
        assert "--use-existing-in" in blob
        assert "elapsed" in blob
        assert "ciso-assistant" in blob
        assert "poam" in blob
        assert "LAB" in blob
        assert "SAMPLE" in blob
        assert "reseed" in blob.lower() or "fixtures/pack_drop" in blob
    assert "export DRY_RUN=1" in sh
    assert "export GRC_LIVE_SCAN=0" in sh
    assert "export CISO_PUSH=0" in sh
    assert "export RISKREADY_PUSH=0" in sh
    assert "export DROPBOX_LIVE=0" in sh
    assert "export PYTHONIOENCODING=utf-8" in sh
    assert 'PYTHONIOENCODING = "utf-8"' in ps1 or "$env:PYTHONIOENCODING" in ps1
    assert "scripts/prove_ciso.py" in sh
    assert "--verify-only" in sh
    assert "/api/risks" in sh
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "lab-drop-to-sor:" not in makefile
    readme_head = "".join((ROOT / "README.md").read_text(encoding="utf-8").splitlines()[:12])
    assert "lab_drop_to_sor" not in readme_head


def test_lab_honesty_ok_line_is_ascii_cp1252() -> None:
    assert LAB_HONESTY_OK_LINE.isascii()
    LAB_HONESTY_OK_LINE.encode("cp1252")
    assert "\u2260" not in LAB_HONESTY_OK_LINE
    assert "\u2192" not in LAB_HONESTY_OK_LINE
    assert "!=" in LAB_HONESTY_OK_LINE
    assert "LAB_DROP_HONESTY=ok" in LAB_HONESTY_OK_LINE
    for path in (SCRIPT, PS1):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("echo ", "Write-Host ")):
                stripped.encode("cp1252")
                assert "\u2260" not in stripped
                assert "\u2192" not in stripped


def test_lab_drop_to_sor_sh_uses_existing_in(tmp_path: Path) -> None:
    work = tmp_path / "lab-work"
    dest_in = work / "in"
    marker = stage_lab_drop_dest_in(dest_in)
    before = {p.relative_to(dest_in) for p in dest_in.rglob("*") if p.is_file()}
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DRY_RUN"] = "0"
    env["CISO_PUSH"] = "1"
    env["RISKREADY_PUSH"] = "1"
    env["GRC_LIVE_SCAN"] = "1"
    env["DROPBOX_LIVE"] = "1"
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--work", str(work)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    after = {p.relative_to(dest_in) for p in dest_in.rglob("*") if p.is_file()}
    assert after == before
    assert marker.is_file()
    assert not (dest_in / "nmap" / "pack_drop" / "rustscan").exists()
    stamp = json.loads((work / "prove-ciso.json").read_text(encoding="utf-8"))
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["lab"] is True
    assert stamp["sample"] is False
    assert stamp["seeded"] is False
    assert stamp["use_existing_in"] is True
    assert stamp["client"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    assert "LAB" in stamp["estate"]
    shape = assert_risk_register_and_poam(work / "out")
    assert shape["findings"] >= 1
    assert shape["risk_scenarios"] >= 1
    assert shape["poam_rows"] >= 1
    blob = (proc.stdout or "") + (proc.stderr or "")
    blob.encode("cp1252")
    assert "\u2260" not in blob
    assert "\u2192" not in blob
    assert "--use-existing-in" in blob
    assert "LAB/DEMO" in blob
    assert LAB_HONESTY_OK_LINE in blob or "LAB_DROP_HONESTY=ok" in blob


def test_lab_drop_verify_only_after_prove(tmp_path: Path) -> None:
    work = tmp_path / "lab-work"
    stage_lab_drop_dest_in(work / "in")
    stamp = prove_ciso(root=ROOT, dest=work, use_existing_in=True)
    assert stamp["status"] == "pass", stamp.get("reason")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DRY_RUN"] = "1"
    env["CISO_PUSH"] = "0"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--verify-only", "--work", str(work)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert LAB_HONESTY_OK_LINE in blob or "LAB_DROP_HONESTY=ok" in blob
    blob.encode("cp1252")
    assert "\u2260" not in blob
