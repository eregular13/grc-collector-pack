"""LAB_PROVE_LOCK: operator dest_in through prove --use-existing-in.

fixtures/lab-drop/ is a scan-shaped LAB dest_in (not SAMPLE keep, not client).
Pytest copies it into a temp work/in and runs prove_ciso --use-existing-in /
lab_drop_to_sor. Default prove seed remains a different code path.
LAB/DEMO != SAMPLE != client. paying_day FAIL.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.prove_ciso import (
    ExistingInError,
    dest_in_is_populated,
    prove_ciso,
    seed_prove_in,
    unexpected_demo_adapter_trees,
)
from shared.ciso_shape import assert_risk_register_and_poam

ROOT = Path(__file__).resolve().parents[1]
LAB_DROP = ROOT / "fixtures" / "lab-drop"
LAB_PACK = LAB_DROP / "nmap" / "pack_drop"
DOCS = ROOT / "docs" / "PROVE_CISO.md"
SCRIPT = ROOT / "scripts" / "lab_drop_to_sor.sh"

LAB_NET = "192.168.64."
SAMPLE_NMAP_NETS = ("10.0.0.", "172.16.10.")
HOST_CLASSES = (
    "lab-gw.lab.internal",
    "lab-loader.lab.internal",
    "lab-db.lab.internal",
    "lab-web.lab.internal",
    "lab-win.lab.internal",
    "lab-iot.lab.internal",
    "lab-ftp.lab.internal",
)
MIN_LAB_HOSTS = 8
MIN_LAB_PORTS = 12
MIN_LAB_FINDINGS = 12
MIN_LAB_POAM = 3


def _jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        row = json.loads(text)
        assert isinstance(row, dict)
        rows.append(row)
    return rows


def stage_lab_drop_dest_in(dest_in: Path) -> Path:
    """Copy fixtures/lab-drop into dest_in. LAB != SAMPLE. Does not seed pack_drop."""
    dest_in.mkdir(parents=True, exist_ok=True)
    for path in LAB_DROP.rglob("*"):
        if not path.is_file():
            continue
        target = dest_in / path.relative_to(LAB_DROP)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    marker = dest_in / "OPERATOR_LAB_MARKER.txt"
    marker.write_text("do-not-reseed\n", encoding="utf-8")
    return marker


def _honesty_stamps(stamp: dict) -> None:
    assert stamp.get("status") == "pass", stamp.get("reason")
    assert stamp.get("seeded") is False
    assert stamp.get("use_existing_in") is True
    assert stamp.get("lab") is True
    assert stamp.get("sample") is False
    assert stamp.get("client") is False
    assert stamp.get("client_keep") is False
    assert stamp.get("demo") is True
    assert stamp.get("paying_day") == "FAIL"
    assert stamp.get("posted") is False
    estate = str(stamp.get("estate") or "")
    assert "LAB" in estate
    assert "not a client" in estate.lower()
    assert "SAMPLE" not in estate


def test_lab_drop_fixture_is_lab_not_sample_not_client() -> None:
    assert LAB_DROP.is_dir()
    assert (LAB_DROP / "LAB.txt").is_file()
    assert not (LAB_DROP / "SAMPLE.txt").exists()
    assert not (LAB_PACK / "SAMPLE.txt").exists()
    assert (LAB_PACK / "LAB.txt").is_file()
    assert (LAB_PACK / "meta.json").is_file()
    assert (LAB_PACK / "assets.jsonl").is_file()
    assert (LAB_PACK / "findings.jsonl").is_file()
    assert (LAB_PACK / "evidence" / "note.md").is_file()

    meta = json.loads((LAB_PACK / "meta.json").read_text(encoding="utf-8"))
    assert meta["schema"] == "covey.pack_drop.v1"
    assert meta["adapter"] == "nmap"
    assert meta["demo"] is True
    assert meta.get("lab") is True
    assert meta.get("sample") is False
    assert meta.get("client") is False
    note = str(meta.get("note") or "").lower()
    assert "lab" in note and "demo" in note
    assert "not a client" in note
    assert "not sample" in note

    banner = (LAB_DROP / "LAB.txt").read_text(encoding="utf-8")
    assert "LAB/DEMO" in banner
    assert "not a client" in banner.lower()
    assert "not SAMPLE" in banner or "Not SAMPLE" in banner
    assert "use-existing-in" in banner or "lab_drop_to_sor" in banner
    assert "CVE" in banner or "paying-day" in banner.lower()
    banner.encode("cp1252")
    assert "\u2260" not in banner

    blob = "".join(
        path.read_text(encoding="utf-8")
        for path in (
            LAB_PACK / "meta.json",
            LAB_PACK / "assets.jsonl",
            LAB_PACK / "findings.jsonl",
            LAB_PACK / "LAB.txt",
            LAB_PACK / "evidence" / "note.md",
        )
    )
    assert re.search(r"CVE-\d{4}-\d+", blob) is None
    assert "client KEEP" not in blob
    assert "client estate" not in blob.lower() or "not a client" in blob.lower()
    assert "SAMPLE keep" not in blob or "Not SAMPLE keep" in blob
    assert "LAB" in blob
    assert LAB_NET in blob
    for net in SAMPLE_NMAP_NETS:
        assert net not in blob, f"LAB fixture leaked SAMPLE nmap net {net}"


def test_lab_drop_fixture_is_scan_shaped() -> None:
    assets = _jsonl(LAB_PACK / "assets.jsonl")
    findings = _jsonl(LAB_PACK / "findings.jsonl")
    hosts = [row for row in assets if row.get("kind") == "asset"]
    assert len(hosts) >= MIN_LAB_HOSTS
    names = {row.get("name") for row in hosts}
    for host in HOST_CLASSES:
        assert host in names, host
    ips = {str(row.get("ip") or "") for row in hosts}
    assert all(ip.startswith(LAB_NET) for ip in ips), ips
    assert len(ips) >= MIN_LAB_HOSTS
    ports: list[dict] = []
    products = 0
    for row in hosts:
        assert row.get("id", "").startswith("labdrop-")
        assert "LAB" in (row.get("labels") or [])
        assert "SAMPLE" not in (row.get("labels") or [])
        raw = row.get("ports") or []
        assert isinstance(raw, list) and raw
        for item in raw:
            assert isinstance(item, dict)
            ports.append(item)
            if str(item.get("product") or "").strip():
                products += 1
    assert len(ports) >= MIN_LAB_PORTS
    assert products >= 8
    port_ids = {str(item.get("port")) for item in ports}
    assert {"21", "22", "23", "80", "445", "3389"} <= port_ids
    assert all(row.get("kind") != "service" for row in assets)
    assert len(findings) >= MIN_LAB_FINDINGS
    assert findings[0]["id"].startswith("labdrop-")
    assert any(row.get("name") == "Telnet exposed" for row in findings)
    assert any(row.get("name") == "FTP exposed" for row in findings)
    assert any(row.get("name") == "SMB 445 exposed" for row in findings)
    for row in findings:
        assert row.get("kind") == "finding"
        assert row.get("id", "").startswith("labdrop-")
        assert "LAB" in (row.get("labels") or [])
        assert "SAMPLE" not in (row.get("labels") or [])
        assert row.get("category") == "exposure"
        extra = row.get("extra") or {}
        assert extra.get("port")
        assert extra.get("service")
        assert str(extra.get("ip") or "").startswith(LAB_NET)


def test_prove_use_existing_in_on_lab_drop_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    marker = stage_lab_drop_dest_in(dest_in)
    before = {p.relative_to(dest_in) for p in dest_in.rglob("*") if p.is_file()}
    calls: list[str] = []

    def _boom(*_args: object, **_kwargs: object) -> dict:
        calls.append("seed_prove_in")
        raise AssertionError("seed_prove_in must not run when use_existing_in")

    monkeypatch.setattr("scripts.prove_ciso.seed_prove_in", _boom)
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    assert calls == []
    _honesty_stamps(stamp)
    after = {p.relative_to(dest_in) for p in dest_in.rglob("*") if p.is_file()}
    assert after == before
    assert marker.is_file()
    assert marker.read_text(encoding="utf-8") == "do-not-reseed\n"
    assert not (dest_in / "nmap" / "pack_drop" / "rustscan").exists()
    assert not (dest_in / "SAMPLE.txt").exists()
    assert (dest_in / "LAB.txt").is_file()
    assert unexpected_demo_adapter_trees(dest_in) == []
    shape = assert_risk_register_and_poam(Path(stamp["out_dir"]))
    assert shape["findings"] >= MIN_LAB_FINDINGS
    assert shape["risk_scenarios"] >= 1
    assert shape["poam_rows"] >= MIN_LAB_POAM
    assert stamp["counts"]["findings"] == shape["findings"]
    assert stamp["counts"]["poam"] == shape["poam_rows"]
    assert stamp["counts"]["risk_scenarios"] == shape["risk_scenarios"]
    assets_csv = (Path(stamp["out_dir"]) / "ciso-assistant" / "assets.csv").read_text(
        encoding="utf-8"
    )
    findings_csv = (Path(stamp["out_dir"]) / "ciso-assistant" / "findings.csv").read_text(
        encoding="utf-8"
    )
    assert "lab-web.lab.internal" in assets_csv
    assert LAB_NET in assets_csv
    assert "SMB" in findings_csv or "445" in findings_csv
    assert "filesrv.corp.local" not in assets_csv
    assert "10.0.0." not in assets_csv
    seed = stamp.get("seed") or {}
    assert seed.get("seeded") is False
    assert seed.get("use_existing_in") is True
    assert seed.get("lab") is True
    assert seed.get("sample") is False
    assert seed.get("client") is False


def test_lab_drop_to_sor_on_lab_drop_fixture(tmp_path: Path) -> None:
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
    stamp = json.loads((work / "prove-ciso.json").read_text(encoding="utf-8"))
    _honesty_stamps(stamp)
    shape = assert_risk_register_and_poam(work / "out")
    assert shape["findings"] >= MIN_LAB_FINDINGS
    assert shape["risk_scenarios"] >= 1
    assert shape["poam_rows"] >= MIN_LAB_POAM
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert "--use-existing-in" in blob
    assert "LAB/DEMO" in blob
    assert "did not reseed" in blob.lower() or "fixtures/pack_drop" in blob


def test_use_existing_in_fail_closed_on_empty_in(tmp_path: Path) -> None:
    dest = tmp_path / "empty"
    dest_in = dest / "in"
    dest_in.mkdir(parents=True)
    (dest_in / "LAB.txt").write_text("banner only\n", encoding="utf-8")
    (dest_in / "SAMPLE.txt").write_text("banner only\n", encoding="utf-8")
    assert dest_in_is_populated(dest_in) is False
    with pytest.raises(ExistingInError, match="EXISTING_IN_FAIL"):
        prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    names = {p.name for p in dest_in.iterdir()}
    assert names == {"LAB.txt", "SAMPLE.txt"}
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["CISO_PUSH"] = "0"
    env["DRY_RUN"] = "1"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "prove_ciso.py"), "--work", str(dest), "--use-existing-in"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert "EXISTING_IN_FAIL" in blob
    wrapper = subprocess.run(
        ["bash", str(SCRIPT), "--work", str(dest)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert wrapper.returncode != 0
    wrap_blob = (wrapper.stdout or "") + (wrapper.stderr or "")
    assert "EXISTING_IN_FAIL" in wrap_blob


def test_default_seed_path_is_not_lab_drop(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    marker = stage_lab_drop_dest_in(dest_in)
    stamp = prove_ciso(root=ROOT, dest=dest)
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["sample"] is True
    assert stamp.get("lab") is False
    assert stamp.get("seeded") is True
    assert stamp.get("use_existing_in") is False
    assert stamp["client"] is False
    assert stamp["estate"] == "SAMPLE/DEMO — not a client estate"
    assert not marker.is_file()
    assert not (dest_in / "LAB.txt").exists()
    assert (dest_in / "SAMPLE.txt").is_file()
    assert (dest_in / "nmap" / "pack_drop" / "rustscan" / "meta.json").is_file()
    assert (dest_in / "nmap" / "pack_drop" / "SAMPLE.txt").is_file()
    assets_csv = (Path(stamp["out_dir"]) / "ciso-assistant" / "assets.csv").read_text(
        encoding="utf-8"
    )
    assert "filesrv.corp.local" in assets_csv
    assert "lab-web.lab.internal" not in assets_csv
    assert LAB_NET not in assets_csv
    seed = stamp.get("seed") or {}
    assert seed.get("sample") is True
    nmap_assets = (dest_in / "nmap" / "pack_drop" / "assets.jsonl").read_text(encoding="utf-8")
    assert "lab-web.lab.internal" not in nmap_assets
    src = inspect_seed_source()
    assert "fixtures" in src and "pack_drop" in src
    assert "lab-drop" not in src


def inspect_seed_source() -> str:
    import inspect

    return inspect.getsource(seed_prove_in)


def test_docs_lab_section_points_desktop_at_use_existing_in() -> None:
    docs = DOCS.read_text(encoding="utf-8")
    assert "## Lab / live dest_in" in docs or "## Lab" in docs
    assert "--use-existing-in" in docs
    assert "lab_drop_to_sor" in docs
    assert "lab_drop_to_sor.sh" in docs
    assert "lab_drop_to_sor.ps1" in docs
    assert "fixtures/lab-drop" in docs
    assert "no fixture reseed" in docs.lower() or "does **not** rmtree/reseed" in docs
    assert "DEMO wipe" in docs or "wipes" in docs
    assert "LAB_SHAPE_FAIL" in docs
    assert "LAB/DEMO" in docs
    assert "not a client" in docs.lower()
    assert "farm_drop_to_sor" in docs
    assert "sample_to_sor" in docs
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "lab-drop-to-sor:" not in makefile
    readme_head = "".join((ROOT / "README.md").read_text(encoding="utf-8").splitlines()[:12])
    assert "lab_drop_to_sor" not in readme_head
