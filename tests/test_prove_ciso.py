"""CISO Assistant export prove: fixture pack_drop + honeypot. SAMPLE ≠ client."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from dropbox.orchestrator.ciso_path import run_ciso_path
from dropbox.orchestrator.estate import fingerprint, pack_in_dir
from dropbox.orchestrator.keepmin import KEEP_MINIMUM
from scripts.prove_ciso import prove_ciso, seed_prove_in

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
DOCS = ROOT / "docs" / "PROVE_CISO.md"


def _status() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (ROOT / "STATUS.md").read_text(encoding="utf-8").splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def test_prove_ciso_pack_drop_and_honeypot_to_sor(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    pack_before = fingerprint(pack_in_dir())
    stamp = prove_ciso(root=ROOT, dest=dest)
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["sample"] is True
    assert stamp["client"] is False
    assert stamp["client_keep"] is False
    assert stamp["demo"] is True
    assert "SAMPLE" in stamp["estate"] and "not a client" in stamp["estate"].lower()
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    assert stamp["http"] is False
    assert stamp["wrap"] == "review-only"
    assert stamp["sor"] == "ciso-assistant"
    assert stamp["pack_in_used"] is False
    assert stamp["pack_in_written"] is False
    assert stamp["live"] is False
    assert stamp["hitl"] is True
    sensors = set(stamp["sensors"] or [])
    assert "nmap" in sensors
    assert "honeypot" in sensors
    assert "grc_loader.py" in (stamp["collectors"] or [])
    ciso = Path(stamp["out_dir"]) / "ciso-assistant"
    assert (ciso / "assets.csv").is_file()
    assert (ciso / "findings.csv").is_file()
    assert (ciso / "evidences.csv").is_file()
    assets = (ciso / "assets.csv").read_text(encoding="utf-8")
    findings = (ciso / "findings.csv").read_text(encoding="utf-8")
    evid = (ciso / "evidences.csv").read_text(encoding="utf-8")
    assert "filesrv.corp.local" in assets
    assert "SMB" in findings
    assert "demo" in findings.lower() or "SAMPLE" in findings
    assert "deception-sensor" in findings.lower()
    assert "compromised" not in findings.lower() or "not" in findings.lower()
    assert "covey" in evid.lower() or "pack_drop" in evid.lower() or "honeypot" in evid.lower()
    assert int((stamp["counts"] or {}).get("assets") or 0) >= 2
    assert int((stamp["counts"] or {}).get("findings") or 0) >= 2
    assert fingerprint(pack_in_dir()) == pack_before
    pack_files = [p for p in (ROOT / "in").rglob("*") if p.is_file() and p.name != ".gitkeep"]
    assert pack_files == []
    banner = (Path(stamp["in_dir"]) / "SAMPLE.txt").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO" in banner
    assert "not a client" in banner.lower()


def test_ciso_path_sees_pack_drop_without_keepmin(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    seed_prove_in(dest_in, ROOT)
    result = run_ciso_path(dest_in, tmp_path / "out", scope_path=SCOPE)
    assert "nmap" in result["sensors"]
    assert "honeypot" in result["sensors"]
    assert result["sample"] is True
    assert result["client_keep"] is False
    assert result["posted"] is False
    assert result["http"] is False
    assert result["sor"] == "ciso-assistant"
    assert result["pack_in_written"] is False
    assert (tmp_path / "out" / "ciso-assistant" / "findings.csv").is_file()
    keepmin_names = set(KEEP_MINIMUM)
    assert "honeypot" not in keepmin_names
    assert "covey" not in keepmin_names


def test_prove_ciso_cli_and_docs() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["CISO_PUSH"] = "0"
    env["DRY_RUN"] = "1"
    env["RISKREADY_PUSH"] = "1"
    env["GRC_LIVE_SCAN"] = "0"
    proc = subprocess.run(
        [sys_executable(), str(ROOT / "scripts" / "prove_ciso.py")],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    work = ROOT / "prove" / "work"
    stamp = json.loads((work / "prove-ciso.json").read_text(encoding="utf-8"))
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["paying_day"] == "FAIL"
    assert stamp["sample"] is True
    assert stamp["client"] is False
    assert (work / "out" / "ciso-assistant" / "assets.csv").is_file()
    docs = DOCS.read_text(encoding="utf-8")
    assert "python3 scripts/prove_ciso.py" in docs
    assert "python3 -m dropbox ciso" in docs
    assert "out/ciso-assistant" in docs
    assert "SAMPLE" in docs and "not a client" in docs.lower()
    assert "paying-day" in docs.lower() and "FAIL" in docs
    assert "HITL" in docs
    assert "/api/risks" in docs
    assert "never" in docs.lower() or "do not" in docs.lower()
    src = (ROOT / "scripts" / "prove_ciso.py").read_text(encoding="utf-8")
    assert "/api/risks" not in src or "Never POSTs" in src
    assert "import socket" not in src
    assert "CISO_PUSH" in src and '"0"' in src


def test_prove_ciso_does_not_stamp_paying_day_pass() -> None:
    status = _status()
    assert status.get("paying_day") == "FAIL"
    docs = DOCS.read_text(encoding="utf-8")
    assert "paying-day PASS" in docs or "paying_day: PASS" in docs
    assert any(
        tok in docs.lower()
        for tok in ("not a paying-day pass", "stays fail", "do not stamp", "≠ pass")
    )
    for line in docs.splitlines():
        low = line.lower()
        if "paying-day pass" in low or "paying_day: pass" in low:
            assert any(tok in low for tok in ("not", "never", "do not", "fail", "≠"))


def test_fixture_banners_are_sample_not_client() -> None:
    meta = (ROOT / "fixtures" / "pack_drop" / "nmap" / "meta.json").read_text(encoding="utf-8")
    note = (ROOT / "fixtures" / "pack_drop" / "nmap" / "evidence" / "note.md").read_text(
        encoding="utf-8"
    )
    sample = (ROOT / "fixtures" / "pack_drop" / "nmap" / "SAMPLE.txt").read_text(encoding="utf-8")
    hp = (ROOT / "fixtures" / "demo" / "honeypot" / "SAMPLE.txt").read_text(encoding="utf-8")
    hp_meta = (ROOT / "fixtures" / "demo" / "honeypot" / "meta.json").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO — not a client estate" in meta
    assert "SAMPLE/DEMO — not a client estate" in note
    assert "not a client" in sample.lower() and "SAMPLE" in sample
    assert "not a client" in hp.lower() and "SAMPLE" in hp
    assert "SAMPLE/DEMO — not a client estate" in hp_meta


def sys_executable() -> str:
    import sys

    return sys.executable
