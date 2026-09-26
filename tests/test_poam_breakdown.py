"""POA&M include_poam gate: every weakness has a named include/exclude reason."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from collectors.grc_loader import _dedupe, load
from shared.ciso_shape import assert_poam_breakdown
from shared.control_map import (
    POAM_EXCLUDE_REASONS,
    map_finding,
    poam_breakdown,
    poam_decision,
)
from shared.finding_types import dedupe_weaknesses
from shared.io_util import read_jsonl
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
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


def _finding(**kwargs):
    defaults = dict(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-x",
        name="finding",
        description="finding",
        severity="low",
        category="exposure",
        assets=["box"],
        extra={"port": "22", "service": "ssh"},
    )
    defaults.update(kwargs)
    return make_record(**defaults)


def test_poam_decision_names_low_exposure_and_honeypot() -> None:
    low = _finding()
    decision = poam_decision(low, lighter=False)
    assert decision["include"] is True
    assert decision["reason"] == "severity_low"
    assert map_finding(low)["include_poam"] is True
    lighter = poam_decision(low, lighter=True)
    assert lighter["include"] is False
    assert lighter["reason"] == "severity_low"

    honeypot = _finding(
        source="honeypot",
        ref_id="HPOT-1",
        name="Deception-sensor stage-1 hit",
        description="deception-sensor evidence / an agent-behavior signal.",
        severity="high",
        category="deception-sensor",
        extra={"honesty": "deception-sensor", "stage": 1},
    )
    decision = poam_decision(honeypot)
    assert decision["include"] is False
    assert decision["reason"] == "honeypot"
    assert map_finding(honeypot)["include_poam"] is False

    cost = _finding(
        source="cloud-prowler",
        ref_id="CLD-c7n-cpu",
        name="Cloud Custodian azure-vm-cpu-underutilized",
        description="Virtual machines with low CPU utilization",
        severity="medium",
        category="excluded",
        extra={
            "check_id": "azure-vm-cpu-underutilized",
            "exclude_reason": "NOT_A_WEAKNESS",
            "service": "azure.vm",
        },
    )
    decision = poam_decision(cost)
    assert decision["include"] is False
    assert decision["reason"] == "not_a_weakness"
    assert decision["reason"] in POAM_EXCLUDE_REASONS
    assert map_finding(cost)["include_poam"] is False


def test_poam_decision_includes_high_and_key_medium() -> None:
    high = _finding(
        source="cloud-prowler",
        ref_id="CLD-iam",
        name="IAM user has AdministratorAccess",
        description="User has AdministratorAccess attached.",
        severity="high",
        category="cloud-misconfiguration",
        extra={"check_id": "iam_user_administrator_access"},
    )
    decision = poam_decision(high)
    assert decision["include"] is True
    assert decision["reason"] == "severity_high_critical"

    smb = _finding(
        ref_id="NMAP-smb",
        name="SMB exposed",
        description="box has open TCP/445 (microsoft-ds).",
        severity="medium",
        extra={"port": "445", "service": "microsoft-ds"},
    )
    decision = poam_decision(smb)
    assert decision["include"] is True
    assert decision["reason"] == "key_medium"


def test_poam_breakdown_identity_no_silent_drop() -> None:
    rows = [
        _finding(ref_id="NMAP-22", name="SSH", extra={"port": "22", "service": "ssh"}),
        _finding(
            ref_id="NMAP-445",
            name="SMB",
            description="SMB 445",
            severity="medium",
            extra={"port": "445", "service": "microsoft-ds"},
        ),
        _finding(
            source="honeypot",
            ref_id="HPOT-1",
            name="honeypot",
            description="deception-sensor",
            severity="critical",
            category="deception-sensor",
            extra={"honesty": "deception-sensor"},
        ),
    ]
    breakdown = poam_breakdown(rows, lighter=False)
    assert_poam_breakdown(
        {
            **breakdown,
            "poam": breakdown["poam_included"],
            "weaknesses": breakdown["weaknesses_total"],
        }
    )
    assert breakdown["weaknesses_total"] == 3
    assert breakdown["poam_included"] == 2
    assert breakdown["excluded_by_reason"] == {"honeypot": 1}
    light = poam_breakdown(rows, lighter=True)
    assert light["poam_included"] == 1
    assert light["excluded_by_reason"] == {"severity_low": 1, "honeypot": 1}


def _assert_walk_matches_summary(out: Path, summary: dict) -> None:
    assert_poam_breakdown(summary)
    records: list[dict] = []
    folder = out / "canonical"
    if folder.is_dir():
        for path in sorted(folder.glob("*.jsonl")):
            records.extend(row for row in read_jsonl(path) if isinstance(row, dict))
    findings = [
        r
        for r in dedupe_weaknesses(_dedupe(records))
        if r.get("kind") in {"finding", "excluded"}
    ]
    if not findings:
        pytest.fail("canonical findings missing; cannot prove every exclusion is named")
    walked = poam_breakdown(findings)
    pending = int(summary.get("pending_carried") or 0)
    assert walked["weaknesses_total"] + pending == summary["weaknesses_total"] == len(findings) + pending
    assert walked["poam_included"] + pending == summary["poam_included"]
    assert walked["excluded_by_reason"] == summary["excluded_by_reason"]
    for rec in findings:
        decision = poam_decision(rec)
        included = bool(map_finding(rec).get("include_poam"))
        assert decision["include"] is included
        if included:
            continue
        assert decision["reason"], rec.get("ref_id")
        assert decision["reason"] in POAM_EXCLUDE_REASONS, (
            rec.get("ref_id"),
            decision["reason"],
            rec.get("severity"),
        )


def _run_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    import importlib

    for name in COLLECTORS:
        importlib.import_module(name).main()
    return load()


def test_poam_breakdown_identity_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = _run_lab(tmp_path, monkeypatch)
    _assert_walk_matches_summary(tmp_path, summary)


def test_poam_breakdown_identity_sample(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "sample_to_sor.sh"
    if not script.is_file():
        pytest.skip("sample_to_sor.sh absent")
    work = tmp_path / "sample-work"
    subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=True,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
        },
    )
    summary = json.loads((work / "out" / "summary.json").read_text(encoding="utf-8"))
    _assert_walk_matches_summary(work / "out", summary)


def test_poam_breakdown_identity_farm_drop(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "farm_drop_to_sor.sh"
    if not script.is_file():
        pytest.skip("farm_drop_to_sor.sh absent")
    work = tmp_path / "farm-work"
    subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=True,
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
    )
    summary = json.loads((work / "out" / "summary.json").read_text(encoding="utf-8"))
    _assert_walk_matches_summary(work / "out", summary)
