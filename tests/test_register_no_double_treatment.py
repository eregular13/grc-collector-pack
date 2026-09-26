"""No EGP/title-host appears as both mitigate and accept.

Collapsed pack_drop twins are merged_into:<survivor EGP> aliases, not
accepted risk. DEMO / farm / real samples. SAMPLE/DEMO/LAB != client KEEP.
Never POST /api/risks.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from collectors import identity_ad, inventory_nmap
from collectors.grc_loader import load
from shared.ciso_shape import (
    assert_count_consistency,
    assert_register_no_double_treatment,
    csv_rows,
)
from shared.egp_collapse import MERGED_INTO_PREFIX, is_merged_into_reason
from shared.io_util import out_dir, write_canonical
from shared.schema import CISO_REF_MAX

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
COLLECTORS = (
    "collectors.cloud_prowler",
    "collectors.inventory_nmap",
    "collectors.vuln_scan",
    "collectors.host_wazuh",
    "collectors.identity_ad",
    "collectors.easm",
    "collectors.k8s_kubescape",
    "collectors.code_secrets",
    "collectors.saas_idp",
    "collectors.dns_email",
    "collectors.honeypot",
)


def _assert_register(out: Path, *, poam: int | None = None) -> dict:
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    counts = assert_count_consistency(out, summary)
    overlap = assert_register_no_double_treatment(out)
    scenarios = csv_rows(out / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    refs = [row["ref_id"] for row in scenarios]
    assert len(set(refs)) == len(refs)
    assert max(len(ref) for ref in refs) <= CISO_REF_MAX
    ctl = [row["ref_id"] for row in csv_rows(out / "ciso-assistant" / "applied_controls.csv")]
    assert len(set(ctl)) == len(ctl)
    if ctl:
        assert max(len(ref) for ref in ctl) <= CISO_REF_MAX
    assert overlap["mitigate"] == counts["mitigate"] == counts["poam"] - int(summary.get("pending_carried") or 0)
    assert overlap["accept"] == overlap["non_merged_excluded"]
    assert overlap["controls"] == overlap["mitigate"]
    if poam is not None:
        assert counts["poam"] == poam
    excluded = csv_rows(out / "poam" / "excluded.csv")
    merged = [row for row in excluded if is_merged_into_reason(str(row.get("excluded_reason") or ""))]
    for row in merged:
        assert str(row["excluded_reason"]).startswith(MERGED_INTO_PREFIX)
        assert str(row.get("superseded_by") or "").startswith("EGP-")
    for row in scenarios:
        assert (row.get("existing_controls") or "") == ""
    return {**counts, **overlap, "summary": summary}


def test_demo_register_has_no_mitigate_accept_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    import importlib

    for name in COLLECTORS:
        importlib.import_module(name).main()
    load()
    report = _assert_register(tmp_path)
    assert not report["title_host_overlap"]
    assert not report["egp_overlap"]


def test_farm_register_has_no_mitigate_accept_overlap(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "farm_drop_to_sor.sh"
    work = tmp_path / "farm-work"
    proc = subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=False,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
            "DROPBOX_LIVE": "0",
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    report = _assert_register(work / "out", poam=73)
    ledger = json.loads((work / "out" / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    open_items = [
        it for it in (ledger.get("items") or {}).values() if str(it.get("status") or "") != "closed"
    ]
    assert len(open_items) == 109
    telnet = [
        row
        for row in csv_rows(work / "out" / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
        if (row.get("name") or "") == "Telnet exposed"
    ]
    assert any(
        row.get("treatment") == "mitigate" and row.get("assets") == "telnet-legacy.corp.local"
        for row in telnet
    )
    assert all(row.get("treatment") != "accept" for row in telnet)
    assert report["merged_aliases"] >= 1
    assert not report["title_host_overlap"]
    assert not report["egp_overlap"]


def test_sample_to_sor_register_has_no_mitigate_accept_overlap(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "sample_to_sor.sh"
    work = tmp_path / "sample-work"
    proc = subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=False,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
            "DROPBOX_LIVE": "0",
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    report = _assert_register(work / "out")
    assert not report["title_host_overlap"]
    assert not report["egp_overlap"]


def test_real_sample_filesrv_writable_share_is_not_accepted_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fixtures/samples smbmap FILESRV C$ must not be mitigate+accept."""
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    recs: list[dict] = []
    recs.extend(inventory_nmap.parse_file(SAMPLES / "smbmap.txt"))
    recs.extend(inventory_nmap.parse_file(SAMPLES / "nbtscan.txt"))
    recs.extend(identity_ad.parse_file(SAMPLES / "enum4linux" / "enum4linux-ng.json"))
    write_canonical("inventory-nmap", [r for r in recs if r.get("source") == "inventory-nmap"])
    write_canonical("identity-ad", [r for r in recs if r.get("source") == "identity-ad"])
    load()
    report = _assert_register(out_dir())
    scenarios = csv_rows(out_dir() / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    writable = [
        row
        for row in scenarios
        if "writable smb share c$" in (row.get("name") or "").lower()
    ]
    assert writable, "real-sample smbmap must emit Writable SMB share C$ on FILESRV"
    assert all(row.get("treatment") == "mitigate" for row in writable), writable
    assert all((row.get("existing_controls") or "") == "" for row in writable)
    hosts = {(row.get("name") or "", row.get("assets") or "") for row in writable}
    assert len(hosts) == len(writable)
    assert not report["title_host_overlap"]
    assert not report["egp_overlap"]
