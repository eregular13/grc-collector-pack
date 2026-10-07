"""ITERATION-1 #7: prove_ciso FAIL prints named checks + reasons."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from dropbox.scope import ROOT
from scripts.prove_ciso import prove_ciso

PY = sys.executable


def _write_lab_banner(dest_in: Path) -> None:
    (dest_in / "LAB.txt").write_text(
        "LAB — not a client estate. DEMO ok. SAMPLE != LAB.\n", encoding="utf-8"
    )


def test_prove_ciso_empty_lab_fail_has_named_checks(tmp_path: Path) -> None:
    """Empty-ish LAB dest_in fails with failing_checks (not silent fail)."""
    dest = tmp_path / "work"
    dest_in = dest / "in"
    dest_in.mkdir(parents=True)
    _write_lab_banner(dest_in)
    (dest_in / "nmap").mkdir(parents=True)
    (dest_in / "nmap" / "placeholder.xml").write_text(
        '<?xml version="1.0"?><nmaprun></nmaprun>\n', encoding="utf-8"
    )
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    assert stamp.get("status") == "fail"
    failing = stamp.get("failing_checks") or []
    assert isinstance(failing, list) and len(failing) >= 1
    names = {item.get("check") for item in failing if isinstance(item, dict)}
    assert names & {
        "lab_poam",
        "lab_risk_scenarios",
        "lab_weaknesses",
        "register_shape",
        "ciso_files",
        "fixture_ok",
    }
    reason = stamp.get("reason") or {}
    assert reason.get("failing_checks")


def test_prove_ciso_cli_prints_fail_checks(tmp_path: Path) -> None:
    dest = tmp_path / "cli-work"
    dest_in = dest / "in"
    dest_in.mkdir(parents=True)
    _write_lab_banner(dest_in)
    (dest_in / "nmap").mkdir(parents=True)
    (dest_in / "nmap" / "placeholder.xml").write_text(
        '<?xml version="1.0"?><nmaprun></nmaprun>\n', encoding="utf-8"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DRY_RUN"] = "1"
    env["GRC_LIVE_SCAN"] = "0"
    env["CISO_PUSH"] = "0"
    cp = subprocess.run(
        [
            PY,
            str(ROOT / "scripts" / "prove_ciso.py"),
            "--work",
            str(dest),
            "--use-existing-in",
        ],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
    )
    assert cp.returncode != 0
    blob = (cp.stdout or "") + (cp.stderr or "")
    assert "PROVE_CISO=fail" in blob or '"status": "fail"' in blob
    assert "PROVE_CISO_FAIL" in blob or "failing_checks" in blob


def test_prove_ciso_vuln_only_nikto_reports_or_passes(tmp_path: Path) -> None:
    """Vuln-only drop (nikto under in/vuln) must pass OR fail with named reasons."""
    samples = ROOT / "fixtures" / "samples" / "nikto"
    dest = tmp_path / "vuln-only"
    dest_in = dest / "in"
    vuln = dest_in / "vuln"
    vuln.mkdir(parents=True)
    _write_lab_banner(dest_in)
    copied = False
    if samples.is_dir():
        for path in sorted(samples.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".xml", ".csv", ".json"}:
                target = vuln / path.name
                target.write_bytes(path.read_bytes())
                copied = True
                break
    if not copied:
        (vuln / "nikto_syn.xml").write_text(
            '<?xml version="1.0"?>\n'
            "<niktoscan>\n"
            '  <scandetails targetip="10.9.8.7" '
            'targethostname="filesrv.corp.local" '
            'starttime="2026-10-05 12:00:00">\n'
            '    <item id="1" osvdbid="0">\n'
            "      <description>Synthetic nikto finding for prove reason test.</description>\n"
            "      <uri>/</uri>\n"
            "      <namelink>http://filesrv.corp.local/</namelink>\n"
            "    </item>\n"
            "  </scandetails>\n"
            "</niktoscan>\n",
            encoding="utf-8",
        )
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    if stamp.get("status") == "pass":
        return
    failing = stamp.get("failing_checks") or []
    assert failing, "FAIL must include failing_checks"
    for item in failing:
        assert item.get("check"), item
        assert item.get("reason"), item
