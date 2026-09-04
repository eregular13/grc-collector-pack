"""SCOPE gate, stay-out, and demo ingest. No live scan. No wrap."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from dropbox.runners import refuse_offscope_external, write_inventory, write_lynis, write_tls_headers
from dropbox.scope import FORBIDDEN_TOOLS, GateError, load_scope
from dropbox.yaml_lite import load_yaml

ROOT = Path(__file__).resolve().parents[1]


def test_example_scope_loads() -> None:
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    assert "DEMO" in scope.client_name
    assert scope.internal_cidrs
    assert scope.external_hosts
    assert "nmap" in scope.allow_tools
    assert "nessus" in scope.allow_tools
    assert scope.stage_deepen is True
    assert scope.allows_internal_target("127.0.0.1")
    assert not scope.allows_internal_target("8.8.8.8")


def test_gate_missing_scope(tmp_path: Path) -> None:
    with pytest.raises(GateError, match="no SCOPE file"):
        load_scope(tmp_path / "missing.yaml")


def test_gate_missing_consent(tmp_path: Path) -> None:
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: X\nconsent:\n  attestation_path: no-such.md\n"
        "  attestation_sha256: abc\nengagement:\n  start: 2026-09-01\n  end: 2026-12-31\n"
        "internal:\n  hosts:\n    - 127.0.0.1\nexternal:\n  hosts:\n    - vpn.example.com\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="attestation missing"):
        load_scope(scope)


def test_gate_hash_mismatch(tmp_path: Path) -> None:
    att = tmp_path / "consent.md"
    att.write_text("nope\n", encoding="utf-8")
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: X\nconsent:\n  attestation_path: "
        + str(att)
        + "\n  attestation_sha256: 00deadbeef\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="hash mismatch"):
        load_scope(scope)


def test_gate_missing_external(tmp_path: Path) -> None:
    att = tmp_path / "consent.md"
    att.write_text("ok\n", encoding="utf-8")
    digest = hashlib.sha256(att.read_bytes()).hexdigest()
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: X\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\nexternal:\n  hosts: []\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="external"):
        load_scope(scope)


def test_gate_forbidden_allow_tool(tmp_path: Path) -> None:
    att = tmp_path / "consent.md"
    att.write_text("ok\n", encoding="utf-8")
    digest = hashlib.sha256(att.read_bytes()).hexdigest()
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: X\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\nallow_tools:\n  - nuclei\n",
        encoding="utf-8",
    )
    with pytest.raises(GateError, match="LICENSE-LOCK"):
        load_scope(scope)


def test_external_only_named_targets() -> None:
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    assert scope.allows_external_target("vpn.example.com")
    assert scope.allows_external_target("staging.example.com")
    assert scope.allows_external_target("192.0.2.10")
    assert not scope.allows_external_target("evil.example.net")
    assert not scope.allows_external_target("8.8.8.8")
    with pytest.raises(GateError, match="not in SCOPE"):
        refuse_offscope_external(scope, "https://scan-the-internet.invalid")
    assert not scope.allows_external_target("*.example.com")
    assert not scope.allows_external_target("10.0.0.0/24")
    assert not scope.allows_external_target("0.0.0.0/0")


def test_external_scope_refuses_wildcard_and_cidr(tmp_path: Path) -> None:
    import hashlib

    att = tmp_path / "consent.md"
    att.write_text("ok\n", encoding="utf-8")
    digest = hashlib.sha256(att.read_bytes()).hexdigest()
    header = (
        "client:\n  name: X\nconsent:\n  attestation_path: "
        + str(att)
        + f"\n  attestation_sha256: {digest}\nengagement:\n  start: 2026-09-01\n"
        "  end: 2026-12-31\ninternal:\n  hosts:\n    - 127.0.0.1\n"
    )
    wild = tmp_path / "wild.yaml"
    wild.write_text(header + "external:\n  hosts:\n    - '*.example.com'\n", encoding="utf-8")
    with pytest.raises(GateError, match="wildcard"):
        load_scope(wild)
    cidr = tmp_path / "cidr.yaml"
    cidr.write_text(header + "external:\n  hosts:\n    - 10.0.0.0/24\n", encoding="utf-8")
    with pytest.raises(GateError, match="CIDR"):
        load_scope(cidr)


def test_demo_ingest_writes_existing_formats(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IN_DIR", str(tmp_path))
    monkeypatch.setenv("DROPBOX_DEMO", "1")
    monkeypatch.setenv("DROPBOX_LIVE", "0")
    scope = load_scope(ROOT / "dropbox" / "SCOPE.yaml")
    gnmap = write_inventory(scope, demo=True)
    tls = write_tls_headers(scope, demo=True, live=False)
    lynis = write_lynis(scope, demo=True)
    assert gnmap.is_file()
    text = gnmap.read_text(encoding="utf-8")
    assert "Host:" in text and "Ports:" in text
    assert "nmap" not in text.lower() or "Not Nmap" in text
    rows = tls.read_text(encoding="utf-8").strip().splitlines()
    assert rows
    assert "vpn.example.com" in tls.read_text(encoding="utf-8")
    assert lynis and lynis.is_file()
    from collectors.easm import parse_file as parse_easm
    from collectors.inventory_nmap import parse_file as parse_nmap

    nmap_recs = parse_nmap(gnmap)
    easm_recs = parse_easm(tls)
    assert any(r["kind"] == "asset" for r in nmap_recs)
    assert any(r["kind"] == "asset" for r in easm_recs)


def test_cli_gate_and_missing(tmp_path: Path) -> None:
    ok = subprocess.run(
        ["python3", "-m", "dropbox", "gate", "--scope", str(ROOT / "dropbox" / "SCOPE.yaml")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr
    assert "SCOPE gate OK" in ok.stdout
    bad = subprocess.run(
        ["python3", "-m", "dropbox", "gate", "--scope", str(tmp_path / "nope.yaml")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode == 2
    assert "SCOPE gate" in bad.stderr


def test_image_and_dropbox_do_not_ship_forbidden_scanners() -> None:
    from dropbox.scanner_free import assert_image_files_scanner_free

    assert_image_files_scanner_free()
    blob = ""
    for rel in ("Dockerfile", "docker-compose.yml", "docker-compose.dropbox.yml"):
        path = ROOT / rel
        if path.exists():
            blob += path.read_text(encoding="utf-8").lower()
    for tool in ("nmap", "nuclei", "openvas", "nessus", "zeek", "bloodhound", "pingcastle"):
        assert f"apt-get install {tool}" not in blob
        assert f"apt install {tool}" not in blob
        assert f"apk add {tool}" not in blob
    runners = (ROOT / "dropbox" / "runners.py").read_text(encoding="utf-8")
    assert "Not Nmap" in runners
    assert not any(line.strip().startswith(("nmap ", "nuclei ", "nessus ")) for line in runners.splitlines())
    assert "FORBIDDEN_TOOLS" in (ROOT / "dropbox" / "scope.py").read_text(encoding="utf-8")
    _ = FORBIDDEN_TOOLS


def test_dropbox_lab_cli_uses_work_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work-in"
    monkeypatch.setenv("DROPBOX_WORK_IN", str(work))
    proc = subprocess.run(
        ["python3", "-m", "dropbox", "lab", "--scope", str(ROOT / "dropbox" / "SCOPE.yaml")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (work / "nmap" / "dropbox-inventory.gnmap").is_file()
    assert (work / "easm" / "dropbox-tls.jsonl").is_file()
    assert (work / "cloud" / "prowler.json").is_file()
    assert not (ROOT / "in" / "nmap" / "dropbox-inventory.gnmap").exists()


def test_yaml_lite_round_trip_scope() -> None:
    data = load_yaml((ROOT / "dropbox" / "SCOPE.yaml").read_text(encoding="utf-8"))
    assert data["client"]["name"].startswith("DEMO")
    assert "10.20.30.0/23" in data["internal"]["cidrs"]
