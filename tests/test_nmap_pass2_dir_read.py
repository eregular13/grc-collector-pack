"""Fail-before/pass-after: in/pass2/ nmap second-pass data is read, not dropped.

Lab drops can carry a second nmap pass (--script vuln) under in/pass2/ with
.xml/.nmap/.gnmap/.console copies. No collector reads pass2/, so before it was
silently ignored (no UNREAD_SENSOR_DIR guard) and the pass-2 CVEs never reached
POA&M. Now the XML is landed into nmap/ and an unknown dir still fails closed.
Synthetic data only (203.0.113.20, host-a.example.test, CVE-2099-*).
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

from tests.test_nmap_pass2_same_port import _xml

ROOT = Path(__file__).resolve().parents[1]


def _run(work: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHON=sys.executable, SOURCE_DATE_EPOCH="1790007200", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        ["bash", str(ROOT / "scripts" / "lab_drop_to_sor.sh"), "--work", str(work)],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
    )


def _drop(tmp_path: Path, extra_dir: str, with_xml: bool = True) -> Path:
    work = tmp_path / "w"
    (work / "in" / "nmap").mkdir(parents=True)
    (work / "in" / "LAB.txt").write_text("LAB/DEMO -- not a client estate. Synthetic.\n", encoding="utf-8")
    (work / "in" / "nmap" / "nmap-pass1.xml").write_text(_xml(1790000000, False), encoding="utf-8")
    p2 = work / "in" / extra_dir
    p2.mkdir()
    if with_xml:
        (p2 / "nmap_pass2.xml").write_text(_xml(1790003600, True), encoding="utf-8")
    (p2 / "nmap_pass2.nmap").write_text("# Nmap 7.94 scan (text copy)\n22/tcp open ssh\n", encoding="utf-8")
    (p2 / "nmap_pass2.console").write_text("Starting Nmap 7.94\n", encoding="utf-8")
    return work


def test_pass2_dir_cves_reach_poam(tmp_path: Path) -> None:
    work = _drop(tmp_path, "pass2")
    proc = _run(work)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]
    with (work / "out" / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        weak = [r["weakness"] for r in csv.DictReader(fh)]
    assert "CVE-2099-0001" in weak, weak


def test_unknown_dir_still_fails_closed(tmp_path: Path) -> None:
    work = _drop(tmp_path, "pass3")
    proc = _run(work)
    assert proc.returncode != 0
    assert "UNREAD_SENSOR_DIR" in proc.stdout + proc.stderr
    assert "pass3" in proc.stdout + proc.stderr


def test_pass2_without_xml_fails_closed(tmp_path: Path) -> None:
    work = _drop(tmp_path, "pass2", with_xml=False)
    proc = _run(work)
    assert proc.returncode != 0
    assert "UNREAD_SENSOR_DIR" in proc.stdout + proc.stderr


def test_inventory_keepmin_dir_with_unknown_file_fails_closed(tmp_path: Path) -> None:
    """A KEEP-min dir counts as read only when every file in it was landed."""
    work = tmp_path / "w"
    inv = work / "in" / "inventory"
    inv.mkdir(parents=True)
    (work / "in" / "LAB.txt").write_text("LAB/DEMO -- not a client estate. Synthetic.\n", encoding="utf-8")
    (inv / "nmap-pass1.xml").write_text(_xml(1790000000, False), encoding="utf-8")
    ok = _run(work)
    assert ok.returncode == 0, (ok.stdout + ok.stderr)[-2000:]
    (inv / "notes.bin").write_bytes(b"\x00\x01 not a scan")
    bad = _run(work)
    assert bad.returncode != 0
    assert "UNREAD_SENSOR_DIR" in bad.stdout + bad.stderr
