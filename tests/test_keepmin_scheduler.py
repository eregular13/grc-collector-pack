"""Themis KEEP-minimum scheduler + CISO path. Argus fail-closed."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from dropbox.orchestrator.keepmin import KEEP_MINIMUM, VANITY_SCHEDULE, refuse_vanity
from dropbox.orchestrator.permissions import classify, may_ingest, may_invoke
from dropbox.orchestrator.scheduler import schedule
from dropbox.scope import GateError

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "dropbox" / "SCOPE.yaml"


def _signed_scope(tmp_path: Path, name: str = "Contoso Labs") -> Path:
    att = tmp_path / "consent.md"
    att.write_text("signed keep-minimum\n", encoding="utf-8")
    digest = hashlib.sha256(att.read_bytes()).hexdigest()
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: "
        + name
        + "\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - lynis\n  - curl\n"
        "orchestrator:\n  stages:\n    discover: true\n    deepen: false\n",
        encoding="utf-8",
    )
    return scope


def test_permissions_deny_ask_allow() -> None:
    assert classify("nuclei") == "deny"
    assert classify("nikto") == "deny"
    assert classify("nmap") == "ask"
    assert classify("hardeningkitty") == "allow"
    assert classify("lynis") == "ask" or classify("lynis") == "allow"
    assert may_ingest("hardeningkitty", file_on_disk=False) is True
    assert may_ingest("nuclei", file_on_disk=False) is False
    assert may_ingest("nuclei", file_on_disk=True) is True
    assert may_invoke("nmap", hitl=False, live_ready=True, demo_scope=False) is False
    assert may_invoke("nmap", hitl=True, live_ready=False, demo_scope=False) is False
    assert may_invoke("nmap", hitl=True, live_ready=True, demo_scope=True) is False


def test_vanity_refused_unless_landed() -> None:
    assert refuse_vanity("nuclei", file_on_disk=False)
    assert refuse_vanity("trivy", file_on_disk=False)
    assert refuse_vanity("nessus", file_on_disk=False)
    assert refuse_vanity("hexstrike", file_on_disk=False)
    assert refuse_vanity("hardeningkitty", file_on_disk=False) is None
    for name in KEEP_MINIMUM:
        assert name not in VANITY_SCHEDULE


def test_schedule_dry_run_empty_in_does_not_load_demo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "in" / "nmap").mkdir(parents=True)
    (tmp_path / "in" / "nmap" / ".gitkeep").write_text("", encoding="utf-8")
    data = schedule(SCOPE, live=False, dest_in=tmp_path / "in", dest_out=tmp_path / "out")
    assert data["live"] is False
    assert data["plan_only"] is True
    assert data["http"] is False
    assert data["posted"] is False
    assert data["file_drop_default"] is True
    assert data["keep_minimum"] == list(KEEP_MINIMUM)
    assert data["sor"]["collectors"] == []
    assert int(data["sor"]["counts"].get("assets") or 0) == 0
    assert data["client_keep_real"] == "0/4"
    assert data["farm_mcp_pack_truth"] is False
    assert data["pack_truth"] == "evergreen_assessment_mcp"
    assert data["hexstrike"] == "pattern-only"


def test_schedule_refuses_vanity_and_live_on_demo(tmp_path: Path) -> None:
    data = schedule(
        SCOPE,
        live=False,
        dest_in=tmp_path / "in",
        dest_out=tmp_path / "out",
        extra=["nuclei", "trivy", "nessus"],
    )
    refused = {row["slot"]: row["reason"] for row in data["refused"]}
    assert "nuclei" in refused
    assert "trivy" in refused
    assert "nessus" in refused
    planned = {row["slot"] for row in data["planned"]}
    assert "nuclei" not in planned
    hex_data = schedule(
        SCOPE,
        live=False,
        dest_in=tmp_path / "in",
        dest_out=tmp_path / "out",
        extra=["hexstrike"],
    )
    assert any(row["slot"] == "hexstrike" for row in hex_data["refused"])
    with pytest.raises(GateError, match="DEMO"):
        schedule(SCOPE, live=True, dest_in=tmp_path / "in", dest_out=tmp_path / "out")


def test_schedule_live_refused_without_live_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FARM_TOOL_BIN", str(tmp_path / "empty-bin"))
    monkeypatch.setenv("PATH", "/nonexistent-keepmin-live")
    (tmp_path / "empty-bin").mkdir()
    scope = _signed_scope(tmp_path)
    with pytest.raises(GateError, match="live_ready"):
        schedule(scope, live=True, dest_in=tmp_path / "in", dest_out=tmp_path / "out")


def test_ciso_path_keep_samples_not_client_keep(tmp_path: Path) -> None:
    from dropbox.orchestrator.ciso_path import run_ciso_path

    dest_out = tmp_path / "out"
    result = run_ciso_path(ROOT / "fixtures" / "keep-samples", dest_out, scope_path=SCOPE)
    assert result["http"] is False
    assert result["sample"] is True
    assert result["client_keep"] is False
    assert result["collectors"]
    assert "grc_loader.py" in result["collectors"]
    assert result["quote"]["price"] is None
    assert result["quote"]["posted"] is False
    assert result["posted"] is False
    assert result["sor"] == "ciso-assistant"
    assert result["ciso_files"]
    assert result["pack_in_written"] is False
    assert result["file_drop_read_only"] is True
    assert all(name.endswith(".csv") for name in result["ciso_files"])
    assert (dest_out / "quote-shaped.json").is_file()
    assert (dest_out / "ciso-assistant" / "assets.csv").is_file()


def test_schedule_cli_refuses_vanity_and_demo_live(tmp_path: Path) -> None:
    """Process e2e: schedule dry-run refuses vanity extras; DEMO --live exits 2."""
    empty_in = tmp_path / "in"
    empty_in.mkdir()
    out = tmp_path / "sched-out"
    proc = subprocess.run(
        [
            "python3",
            "-m",
            "dropbox",
            "schedule",
            "--scope",
            str(SCOPE),
            "--in-dir",
            str(empty_in),
            "--out-dir",
            str(out),
            "--extra",
            "nuclei,trivy,nessus,hexstrike",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout[proc.stdout.find("{") :])
    refused = {row["slot"]: row["reason"] for row in data["refused"]}
    assert "nuclei" in refused
    assert "trivy" in refused
    assert "nessus" in refused
    assert "hexstrike" in refused
    planned = {row["slot"] for row in data["planned"]}
    assert "nuclei" not in planned
    assert data["live"] is False
    assert data["plan_only"] is True
    live = subprocess.run(
        [
            "python3",
            "-m",
            "dropbox",
            "schedule",
            "--scope",
            str(SCOPE),
            "--in-dir",
            str(empty_in),
            "--out-dir",
            str(out),
            "--live",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert live.returncode == 2
    blob = (live.stderr or "") + (live.stdout or "")
    assert "DEMO" in blob
    assert "SCOPE gate" in blob or "HITL" in blob or "live" in blob.lower()


def test_ciso_cli_sor_posted_false_riskready_no_http(tmp_path: Path) -> None:
    """Process e2e: python3 -m dropbox ciso writes SoR CSVs; posted/http stay false."""
    import os

    out = tmp_path / "ciso-out"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["CISO_PUSH"] = "0"
    env["DRY_RUN"] = "1"
    env["RISKREADY_PUSH"] = "1"
    env["GRC_LIVE_SCAN"] = "0"
    env["DROPBOX_LIVE"] = "0"
    proc = subprocess.run(
        [
            "python3",
            "-m",
            "dropbox",
            "ciso",
            "--scope",
            str(SCOPE),
            "--in-dir",
            str(ROOT / "fixtures" / "keep-samples"),
            "--out-dir",
            str(out),
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout[proc.stdout.find("{") :])
    assert data["posted"] is False
    assert data["http"] is False
    assert data["sor"] == "ciso-assistant"
    assert data["ciso_files"]
    assert (out / "ciso-assistant" / "assets.csv").is_file()
    assert (out / "ciso-assistant" / "findings.csv").is_file()
    assert "clica" in data["clica"]
    assert "push_ciso" in data["push_ciso"] or "push_ciso.sh" in data["push_ciso"]


def test_schedule_cli_scope_and_keep_samples(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "schedule", "--scope", str(empty)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "SCOPE gate" in proc.stderr
    out = tmp_path / "sched-out"
    proc = subprocess.run(
        [
            "python3",
            "-m",
            "dropbox",
            "schedule",
            "--scope",
            str(SCOPE),
            "--in-dir",
            str(ROOT / "fixtures" / "keep-samples"),
            "--out-dir",
            str(out),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout[proc.stdout.find("{") :])
    assert data["client_keep_real"] == "0/4"
    assert data["sor"]["sample"] is True
    assert data["live"] is False
    assert data["pack_in_written"] is False
    assert data["file_drop_read_only"] is True


def test_schedule_and_ciso_never_write_pack_in(tmp_path: Path) -> None:
    """Estate protect: schedule/ciso read pack in/; never mutate it."""
    from dropbox.orchestrator.ciso_path import run_ciso_path
    from dropbox.orchestrator.estate import fingerprint, pack_in_dir

    pack = pack_in_dir()
    before = fingerprint(pack)
    data = schedule(SCOPE, live=False, dest_in=pack, dest_out=tmp_path / "sched-out")
    after = fingerprint(pack)
    assert before == after
    assert data["pack_in_written"] is False
    assert data["file_drop_read_only"] is True
    assert data["write_pack_in"] is False
    assert data["live"] is False
    ciso = run_ciso_path(pack, tmp_path / "ciso-out", scope_path=SCOPE)
    assert fingerprint(pack) == before
    assert ciso["pack_in_written"] is False
    assert ciso["file_drop_read_only"] is True
    armed = schedule(
        SCOPE,
        live=False,
        dest_in=tmp_path / "in",
        dest_out=tmp_path / "flag-out",
        write_pack_in=True,
    )
    assert armed["write_pack_in"] is True
    assert armed["file_drop_read_only"] is False
    assert fingerprint(pack) == before


def test_schedule_cli_never_writes_pack_in(tmp_path: Path) -> None:
    from dropbox.orchestrator.estate import fingerprint, pack_in_dir

    pack = pack_in_dir()
    before = fingerprint(pack)
    proc = subprocess.run(
        [
            "python3",
            "-m",
            "dropbox",
            "schedule",
            "--scope",
            str(SCOPE),
            "--in-dir",
            str(pack),
            "--out-dir",
            str(tmp_path / "cli-out"),
            "--extra",
            "nuclei,hexstrike",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout[proc.stdout.find("{") :])
    assert data["pack_in_written"] is False
    assert data["file_drop_read_only"] is True
    assert fingerprint(pack) == before
    refused = {row["slot"] for row in data["refused"]}
    assert "nuclei" in refused
    assert "hexstrike" in refused
