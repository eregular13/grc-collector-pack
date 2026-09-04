"""SCOPE fail-closed, BYO adapters, status CLI, worker tear-down."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from dropbox.orchestrator import byo
from dropbox.orchestrator.farm import Farm
from dropbox.orchestrator.pipeline import deepen_stage, orchestrate
from dropbox.orchestrator.shard import batch_hosts
from dropbox.scope import GateError, load_scope

ROOT = Path(__file__).resolve().parents[1]


def _write_scope(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "SCOPE.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _consent(tmp_path: Path, text: str = "ok\n") -> tuple[Path, str]:
    att = tmp_path / "consent.md"
    att.write_text(text, encoding="utf-8")
    return att, hashlib.sha256(att.read_bytes()).hexdigest()


def _valid_scope(tmp_path: Path, extra_orch: str = "", cidrs: str | None = None) -> Path:
    att, digest = _consent(tmp_path)
    cidr_block = cidrs if cidrs is not None else "    - 10.20.30.0/24\n"
    return _write_scope(
        tmp_path,
        "client:\n  name: X\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  cidrs:\n"
        + cidr_block
        + "  hosts:\n    - 127.0.0.1\nexternal:\n  hosts:\n    - vpn.example.com\n"
        "allow_tools:\n  - nmap\n"
        "orchestrator:\n  deepen_batch: 3\n  max_workers: 2\n"
        + extra_orch,
    )


def test_empty_scope_refuses_live(tmp_path: Path) -> None:
    empty = tmp_path / "SCOPE.yaml"
    empty.write_text("", encoding="utf-8")
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "orchestrate", "--live", "--scope", str(empty)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "SCOPE gate" in proc.stderr


def test_unsigned_scope_refuses_live(tmp_path: Path) -> None:
    scope = _write_scope(
        tmp_path,
        "client:\n  name: X\nconsent:\n  attestation_path: missing.md\n"
        "  attestation_sha256: 00dead\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n",
    )
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "orchestrate", "--live", "--scope", str(scope)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "SCOPE gate" in proc.stderr


def test_open_internet_cidr_refuses_live(tmp_path: Path) -> None:
    att, digest = _consent(tmp_path)
    scope = _write_scope(
        tmp_path,
        "client:\n  name: X\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  cidrs:\n    - 0.0.0.0/0\n"
        "external:\n  hosts:\n    - vpn.example.com\n",
    )
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "orchestrate", "--live", "--scope", str(scope)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "open-internet" in proc.stderr


def test_live_deepen_without_stage_flag_exits_nonzero(tmp_path: Path) -> None:
    scope = _valid_scope(tmp_path, extra_orch="  stages:\n    discover: true\n    deepen: false\n")
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "orchestrate", "--live", "--scope", str(scope)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "stages.deepen" in proc.stderr


def test_deepen_batch_enforced_at_gate(tmp_path: Path) -> None:
    for bad in (1, 6):
        path = _valid_scope(tmp_path, extra_orch=f"  deepen_batch: {bad}\n")
        with pytest.raises(GateError, match="deepen_batch"):
            load_scope(path)
    ok = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    assert 2 <= ok.deepen_batch <= 5
    with pytest.raises(ValueError):
        batch_hosts(["a", "b"], 1)
    with pytest.raises(ValueError):
        batch_hosts(["a", "b"], 6)


def test_max_workers_default_is_two() -> None:
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    assert scope.max_workers == 2


def test_orchestrate_destroys_discover_and_deepen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DROPBOX_ORCH_DIR", str(tmp_path / "orch"))
    monkeypatch.setattr("dropbox.orchestrator.pipeline._which", lambda name: None)
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    farm = Farm(max_workers=scope.max_workers)
    deepen_stage(scope, farm, live=False)
    assert farm.alive("deepen") == []
    assert sum(1 for w in farm.workers if w.stage == "deepen" and w.status == "destroyed") >= 1
    summary = orchestrate(scope, live=False)
    assert summary["discover"]["alive"] == 0
    assert summary["discover"]["destroyed"] >= 1
    assert summary["deepen"]["destroyed"] >= 1


def test_byo_requires_allow_tools_even_if_on_path() -> None:
    exe, reason = byo.which_allowed("nmap", [], which=lambda n: "/usr/bin/nmap")
    assert exe is None
    assert "allow_tools" in reason
    exe, reason = byo.which_allowed("nmap", ["nmap"], which=lambda n: None)
    assert exe is None
    assert "PATH" in reason
    exe, reason = byo.which_allowed("nmap", ["nmap"], which=lambda n: "/usr/bin/nmap")
    assert exe == "/usr/bin/nmap"


def test_byo_adapter_never_fetches() -> None:
    text = (ROOT / "dropbox" / "orchestrator" / "byo.py").read_text(encoding="utf-8")
    code = "\n".join(
        ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#") and "FORBIDDEN" not in ln
    )
    assert "urllib" not in text
    assert "http.client" not in text
    assert "apt-get install" not in code
    blob = ""
    for path in (ROOT / "dropbox").rglob("*.py"):
        blob += path.read_text(encoding="utf-8")
    assert "apt-get install nmap" not in blob
    assert "apt-get install nessus" not in blob
    assert "will not download" in blob


def test_status_cli_prints_stops_and_demo_label() -> None:
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "status", "--scope", str(ROOT / "dropbox" / "SCOPE.yaml")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "quiet→loud" in proc.stdout or "quiet" in proc.stdout
    assert "stage graph" in proc.stdout
    assert "discover (quiet)" in proc.stdout and "ingest (parse-only)" in proc.stdout
    assert "integrity stops" in proc.stdout
    assert "max_workers=2" in proc.stdout
    assert "allow_tools ∩ PATH" in proc.stdout
    assert "missing" in proc.stdout or "present" in proc.stdout
    assert "last integrity stop" in proc.stdout
    assert "DEMO" in proc.stdout
    assert "not a client" in proc.stdout.lower() or "not a client estate" in proc.stdout
