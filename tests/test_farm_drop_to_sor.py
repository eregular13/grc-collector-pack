"""Cold-start Covey pack_drop → CISO farm leave-behind. SAMPLE/DEMO ≠ client."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts.prove_ciso import (
    CISO_CSVS,
    HONESTY_OK_LINE,
    FarmDropHonestyError,
    verify_farm_drop_sor,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "farm_drop_to_sor.sh"
PS1 = ROOT / "scripts" / "farm_drop_to_sor.ps1"


def _honest_prove(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    ciso = folder / "out" / "ciso-assistant"
    ciso.mkdir(parents=True, exist_ok=True)
    (folder / "prove-ciso.json").write_text(
        json.dumps(
            {
                "status": "pass",
                "demo": True,
                "sample": True,
                "client": False,
                "client_keep": False,
                "estate": "SAMPLE/DEMO — not a client estate",
                "paying_day": "FAIL",
                "posted": False,
                "http": False,
                "wrap": "review-only",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    for name in CISO_CSVS:
        (ciso / name).write_text("ref_id,name\nDEMO-1,sample\n", encoding="utf-8")


def test_farm_drop_to_sor_scripts_force_safety_env() -> None:
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
        assert "elapsed" in blob
        assert "ciso-assistant" in blob
        assert "SAMPLE" in blob
        assert "sample_to_sor" in blob
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
    assert "farm-drop-to-sor:" in makefile
    assert "scripts/farm_drop_to_sor.sh" in makefile


def test_readme_and_operator_first_lines_point_at_farm_drop_twin() -> None:
    readme_head = "".join((ROOT / "README.md").read_text(encoding="utf-8").splitlines()[:12])
    op_head = "".join((ROOT / "keep" / "OPERATOR.md").read_text(encoding="utf-8").splitlines()[:16])
    prove_head = "".join((ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8").splitlines()[:16])
    covey_head = "".join(
        (ROOT / "docs" / "COVEY_PACK_DROP.md").read_text(encoding="utf-8").splitlines()[:12]
    )
    assert "farm_drop_to_sor.sh" in readme_head
    assert "farm-drop-to-sor" in readme_head or "farm_drop_to_sor" in readme_head
    assert "farm_drop_to_sor.ps1" in readme_head
    assert "sample_to_sor.sh" in readme_head
    assert "SAMPLE" in readme_head
    assert "farm_drop_to_sor.sh" in op_head
    assert "farm_drop_to_sor.ps1" in op_head
    assert "sample_to_sor.sh" in op_head
    assert "primary" in op_head.lower() or "KEEP" in op_head
    assert "farm_drop_to_sor.sh" in prove_head
    assert "prove_ciso" in prove_head or "prove/work" in prove_head
    assert "farm_drop_to_sor.sh" in covey_head
    assert "sample_to_sor" in covey_head
    assert "SAMPLE" in covey_head or "DEMO" in covey_head


def test_farm_drop_honesty_ok_line_is_ascii_cp1252() -> None:
    """DESKTOP-222GHQV Windows cp1252 cannot print U+2260; success line must be ASCII."""
    assert HONESTY_OK_LINE.isascii()
    HONESTY_OK_LINE.encode("cp1252")
    assert "\u2260" not in HONESTY_OK_LINE
    assert "!=" in HONESTY_OK_LINE
    assert "FARM_DROP_HONESTY=ok" in HONESTY_OK_LINE
    src = (ROOT / "scripts" / "prove_ciso.py").read_text(encoding="utf-8")
    for literal in (
        'print("FARM_DROP_HONESTY=ok',
        "print('FARM_DROP_HONESTY=ok",
        "print(HONESTY_OK_LINE)",
    ):
        if literal.startswith("print(HONESTY"):
            assert literal in src
    assert "HONESTY_OK_LINE" in src
    for path in (SCRIPT, PS1):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("echo ", "Write-Host ")):
                stripped.encode("cp1252")
                assert "\u2260" not in stripped
                assert "\u2192" not in stripped


def test_verify_only_stdout_encodes_under_cp1252(tmp_path: Path) -> None:
    work = tmp_path / "work"
    _honest_prove(work)
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
    assert HONESTY_OK_LINE in blob or "FARM_DROP_HONESTY=ok" in blob
    blob.encode("cp1252")
    assert "\u2260" not in blob


def test_verify_farm_drop_sor_fail_closed_on_paying_day_pass(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    _honest_prove(dest)
    assert verify_farm_drop_sor(dest)["ok"] is True

    dishonest = {
        "paying_day": "PASS",
        "sample": False,
        "demo": False,
        "client": True,
        "client_keep": True,
        "posted": True,
        "estate": "client estate",
    }
    for key, value in dishonest.items():
        doc = json.loads((dest / "prove-ciso.json").read_text(encoding="utf-8"))
        doc[key] = value
        (dest / "prove-ciso.json").write_text(json.dumps(doc) + "\n", encoding="utf-8")
        with pytest.raises(FarmDropHonestyError, match="FARM_DROP_HONESTY_FAIL"):
            verify_farm_drop_sor(dest)
        _honest_prove(dest)

    (dest / "out" / "ciso-assistant" / "findings.csv").unlink()
    (dest / "out" / "ciso-assistant" / "assets.csv").unlink()
    for name in CISO_CSVS:
        path = dest / "out" / "ciso-assistant" / name
        if path.is_file():
            path.unlink()
    with pytest.raises(FarmDropHonestyError, match="missing CISO"):
        verify_farm_drop_sor(dest)


def test_farm_drop_to_sor_verify_only_fail_closed(tmp_path: Path) -> None:
    work = tmp_path / "work"
    _honest_prove(work)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DRY_RUN"] = "1"
    env["CISO_PUSH"] = "0"
    honest = subprocess.run(
        ["bash", str(SCRIPT), "--verify-only", "--work", str(work)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert honest.returncode == 0, honest.stderr or honest.stdout
    assert "elapsed=" in honest.stdout
    assert str(work / "out" / "ciso-assistant") in honest.stdout
    assert "SAMPLE/DEMO" in honest.stdout or "SAMPLE" in honest.stdout

    doc = json.loads((work / "prove-ciso.json").read_text(encoding="utf-8"))
    doc["paying_day"] = "PASS"
    doc["client"] = True
    doc["sample"] = False
    (work / "prove-ciso.json").write_text(json.dumps(doc) + "\n", encoding="utf-8")
    bad = subprocess.run(
        ["bash", str(SCRIPT), "--verify-only", "--work", str(work)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode != 0
    blob = (bad.stderr or "") + (bad.stdout or "")
    assert "FARM_DROP_HONESTY_FAIL" in blob or "paying_day" in blob


def test_farm_drop_to_sor_sh_isolated_prove(tmp_path: Path) -> None:
    work = tmp_path / "prove-work"
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
    assert "elapsed=" in proc.stdout
    assert "ciso=" in proc.stdout
    assert str(work / "out" / "ciso-assistant") in proc.stdout
    stamp = json.loads((work / "prove-ciso.json").read_text(encoding="utf-8"))
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["sample"] is True
    assert stamp["client"] is False
    assert stamp["client_keep"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    assert stamp["pack_in_written"] is False
    for name in ("assets.csv", "findings.csv"):
        assert (work / "out" / "ciso-assistant" / name).is_file()
