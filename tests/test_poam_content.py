"""Cold-review #2: weakness titles, CVE controls, CPG honesty, Critical SLA, inclusion."""

from __future__ import annotations

import csv
from datetime import date, timedelta
from pathlib import Path

import pytest

from collectors.grc_loader import load
from shared.control_map import (
    map_finding,
    poam_breakdown,
    poam_decision,
    weakness_name_for,
)
from shared.io_util import out_dir, write_canonical
from shared.poam_fields import SLA_DAYS, SLA_NOTE, poam_fields
from shared.schema import make_record


def _finding(**kwargs):
    extra = kwargs.pop("extra", {})
    defaults = dict(
        kind="finding",
        source=kwargs.pop("source", "cloud-prowler"),
        ref_id=kwargs.pop("ref_id", "CLD-x"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", "finding"),
        severity=kwargs.pop("severity", "high"),
        category=kwargs.pop("category", "cloud-misconfiguration"),
        assets=kwargs.pop("assets", ["demo"]),
        extra=extra,
    )
    defaults.update(kwargs)
    return make_record(**defaults)


def test_pass_style_check_titles_state_the_failure() -> None:
    cases = [
        (
            "Root account MFA enabled",
            "Root user has no MFA device.",
            {"check_id": "iam_root_mfa_enabled"},
            "root account has no mfa",
        ),
        (
            "S3 bucket prohibits public access",
            "Bucket ACL and policy allow public List/Get.",
            {"check_id": "s3_bucket_public_access"},
            "allows public access",
        ),
        (
            "RDS instance not publicly accessible",
            "RDS instance PubliclyAccessible=true.",
            {"check_id": "rds_instance_no_public_access"},
            "publicly accessible",
        ),
        (
            "Default security group restricts all traffic",
            "Default SG allows 0.0.0.0/0 on all ports.",
            {"check_id": "ec2_securitygroup_allow_ingress_from_internet_to_any_port"},
            "allows inbound",
        ),
        (
            "CloudTrail multi-region trail exists",
            "No multi-region CloudTrail trail.",
            {"check_id": "cloudtrail_multi_region_enabled"},
            "missing",
        ),
        (
            "IAM user does not have AdministratorAccess",
            "User has AdministratorAccess attached directly.",
            {"check_id": "iam_user_administrator_access"},
            "has standing administratoraccess",
        ),
    ]
    for name, desc, extra, needle in cases:
        rec = _finding(name=name, description=desc, extra=extra)
        mapped = map_finding(rec)
        weakness = weakness_name_for(rec, mapped)
        assert needle in weakness.lower(), (name, weakness)
        assert weakness.lower() != name.lower()
        assert "enabled" not in weakness.lower() or "not enabled" in weakness.lower()


def test_xz_backdoor_gets_si2_ra5_and_specific_fix() -> None:
    rec = _finding(
        source="vuln-scan",
        ref_id="VULN-cve-2024-3094",
        name="xz-utils supply chain backdoor",
        description="Malicious code in xz-utils liblzma.",
        severity="critical",
        category="vulnerability",
        assets=["app-server:latest"],
        extra={"cve": "CVE-2024-3094", "pkg": "xz-utils"},
    )
    mapped = map_finding(rec)
    assert {"SI-2", "RA-5"} <= set(mapped["nist_800_53"])
    assert "cis_7_7" in mapped["cis"]
    assert "csf_unmapped" not in mapped["csf"]
    assert "generic fallback" not in mapped["recommended_fix"].lower()
    assert "xz-utils" in mapped["recommended_fix"] or "liblzma" in mapped["recommended_fix"]
    assert "cpg_2_W" not in mapped["cpg"]


def test_generic_cve_gets_patch_family_and_upgrade_fix() -> None:
    rec = _finding(
        source="vuln-scan",
        ref_id="VULN-cve-2023-38545",
        name="curl SOCKS heap overflow",
        description="Heap buffer overflow in curl SOCKS handshake.",
        severity="high",
        category="vulnerability",
        extra={"cve": "CVE-2023-38545", "pkg": "curl"},
    )
    mapped = map_finding(rec)
    assert mapped["nist_800_53"] == ["SI-2", "RA-5"]
    assert "cis_7_3" in mapped["cis"]
    assert "curl" in mapped["recommended_fix"].lower()
    assert "CVE-2023-38545" in mapped["recommended_fix"]
    assert "generic fallback" not in mapped["recommended_fix"].lower()


def test_cpg_derived_from_800_53_or_dropped() -> None:
    smb = map_finding(
        _finding(
            source="inventory-nmap",
            ref_id="NMAP-445",
            name="SMB 445 exposed",
            description="filesrv has open TCP/445 (microsoft-ds).",
            category="exposure",
            extra={"port": "445", "service": "microsoft-ds"},
        )
    )
    assert "cpg_2_W" in smb["cpg"]
    mfa = map_finding(
        _finding(
            name="Root account MFA enabled",
            description="Root user has no MFA device.",
            extra={"check_id": "iam_root_mfa_enabled"},
        )
    )
    assert "cpg_2_W" not in mfa["cpg"]
    assert "cpg_1_E" not in mfa["cpg"]
    assert mfa["csf_function"] == "protect"
    enc = map_finding(
        _finding(
            name="S3 bucket server-side encryption",
            description="encryption not enforced",
            extra={"check_id": "s3_bucket_default_encryption"},
        )
    )
    assert enc["cpg"] == []
    assert enc["csf_function"] == "protect"


def test_critical_sla_is_shorter_than_high() -> None:
    assert SLA_DAYS["Critical"] == 15
    assert SLA_DAYS["High"] == 30
    assert SLA_DAYS["Moderate"] == 90
    assert SLA_DAYS["Low"] == 180
    assert "15" in SLA_NOTE and "Evergreen default" in SLA_NOTE
    assert "FedRAMP" not in SLA_NOTE and "A9" not in SLA_NOTE
    rec = _finding(
        severity="critical",
        extra={"check_id": "iam_root_mfa_enabled", "scan_time": "2026-09-01"},
    )
    fields = poam_fields(rec, map_finding(rec), date(2026, 9, 26))
    start = date.fromisoformat(fields["original_detection_date"])
    assert date.fromisoformat(fields["scheduled_completion_date"]) == start + timedelta(days=15)
    high = _finding(
        ref_id="CLD-high",
        severity="high",
        extra={"check_id": "iam_root_mfa_enabled", "scan_time": "2026-09-01"},
    )
    hfields = poam_fields(high, map_finding(high), date(2026, 9, 26))
    assert date.fromisoformat(hfields["scheduled_completion_date"]) == start + timedelta(days=30)


def test_lows_on_full_plan_infos_and_honeypot_excluded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    recs = [
        _finding(
            source="inventory-nmap",
            ref_id="NMAP-22",
            name="SSH exposed",
            description="box has open TCP/22 (ssh).",
            severity="low",
            category="exposure",
            extra={"port": "22", "service": "ssh"},
        ),
        _finding(
            source="inventory-nmap",
            ref_id="NMAP-info",
            name="Host discovered",
            description="banner only",
            severity="info",
            category="exposure",
            extra={"port": "80"},
        ),
        _finding(
            source="honeypot",
            ref_id="HPOT-1",
            name="Deception-sensor stage-1 hit",
            description="deception-sensor evidence / an agent-behavior signal.",
            severity="high",
            category="deception-sensor",
            extra={"honesty": "deception-sensor"},
        ),
        _finding(
            source="inventory-nmap",
            ref_id="NMAP-med",
            name="HTTP exposed",
            description="box has open TCP/80.",
            severity="medium",
            category="exposure",
            extra={"port": "80", "service": "http"},
        ),
    ]
    write_canonical("inventory-nmap", recs)
    summary = load()
    assert summary["poam_plan"] == "full"
    assert summary["weaknesses_total"] == summary["poam_included"] + summary["excluded"]
    assert summary["poam_included"] == 2  # low + non-key medium
    assert summary["excluded"] == 2
    assert summary["excluded_by_reason"] == {"severity_info": 1, "honeypot": 1}
    poam = out_dir() / "poam" / "poam.csv"
    with poam.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    refs = [r["finding_ref_id"] for r in rows]
    assert "NMAP-22" in refs
    assert "NMAP-med" in refs
    assert "NMAP-info" not in refs
    assert "HPOT-1" not in refs
    assert [r["severity"] for r in rows] == sorted(
        [r["severity"] for r in rows],
        key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}[s],
    )
    excluded = out_dir() / "poam" / "excluded.csv"
    with excluded.open(encoding="utf-8", newline="") as fh:
        ex = list(csv.DictReader(fh))
    assert {row["finding_ref_id"] for row in ex} == {"NMAP-info", "HPOT-1"}
    assert {row["excluded_reason"] for row in ex} == {"severity_info", "honeypot"}
    by_ref = {row["finding_ref_id"]: row for row in ex}
    assert by_ref["NMAP-info"]["severity"] == "info"
    assert by_ref["NMAP-info"]["severity"] != "low"
    assert by_ref["HPOT-1"]["severity"] == "high"
    md = (out_dir() / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "Pentera" not in md
    assert "full" in md.lower()
    assert "excluded.csv" in md


def test_lighter_plan_is_opt_in_and_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_POAM_LIGHTER", "1")
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    recs = [
        _finding(
            source="inventory-nmap",
            ref_id="NMAP-22",
            name="SSH exposed",
            description="box has open TCP/22 (ssh).",
            severity="low",
            category="exposure",
            extra={"port": "22", "service": "ssh"},
        ),
        _finding(
            source="inventory-nmap",
            ref_id="NMAP-80",
            name="HTTP exposed",
            description="box has open TCP/80.",
            severity="medium",
            category="exposure",
            extra={"port": "80", "service": "http"},
        ),
        _finding(
            source="inventory-nmap",
            ref_id="NMAP-445",
            name="SMB exposed",
            description="box has open TCP/445 (microsoft-ds).",
            severity="medium",
            category="exposure",
            extra={"port": "445", "service": "microsoft-ds"},
        ),
    ]
    write_canonical("inventory-nmap", recs)
    summary = load()
    assert summary["poam_plan"] == "lighter"
    assert "operator request" in summary["poam_plan_note"]
    assert summary["weaknesses_total"] == summary["poam_included"] + summary["excluded"]
    assert poam_breakdown(recs, lighter=True)["excluded_by_reason"] == {
        "severity_low": 1,
        "severity_medium_not_key": 1,
    }
    with (out_dir() / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        refs = [r["finding_ref_id"] for r in csv.DictReader(fh)]
    assert refs == ["NMAP-445"]
    with (out_dir() / "poam" / "excluded.csv").open(encoding="utf-8", newline="") as fh:
        ex = list(csv.DictReader(fh))
    assert {row["finding_ref_id"] for row in ex} == {"NMAP-22", "NMAP-80"}
    md = (out_dir() / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "lighter" in md.lower()
    assert "operator request" in md.lower()


def test_loader_writes_failure_titles_and_xz_controls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    recs = [
        _finding(
            ref_id="CLD-iam-root-mfa-enabled",
            name="Root account MFA enabled",
            description="Root user has no MFA device.",
            extra={"check_id": "iam_root_mfa_enabled", "scan_time": "2026-09-01"},
        ),
        _finding(
            source="vuln-scan",
            ref_id="VULN-cve-2024-3094",
            name="xz-utils supply chain backdoor",
            description="Malicious code in xz-utils liblzma.",
            severity="critical",
            category="vulnerability",
            assets=["app-server:latest"],
            extra={"cve": "CVE-2024-3094", "pkg": "xz-utils", "scan_time": "2026-09-01"},
        ),
    ]
    write_canonical("mixed", recs)
    load()
    with (out_dir() / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        ordered = list(csv.DictReader(fh))
    rows = {r["finding_ref_id"]: r for r in ordered}
    mfa = rows["CLD-iam-root-mfa-enabled"]
    assert mfa["weakness"] == "Root account has no MFA"
    assert mfa["weakness_source_id"] == "iam_root_mfa_enabled"
    xz = rows["VULN-cve-2024-3094"]
    assert "SI-2" in xz["controls"] and "RA-5" in xz["controls"]
    assert "generic fallback" not in xz["recommended_fix"].lower()
    assert xz["original_risk_rating"] == "Critical"
    start = date.fromisoformat(xz["original_detection_date"])
    assert date.fromisoformat(xz["scheduled_completion_date"]) == start + timedelta(days=15)
    assert ordered[0]["finding_ref_id"] == "VULN-cve-2024-3094"


def test_poam_decision_info_never_included() -> None:
    rec = _finding(
        source="inventory-nmap",
        ref_id="NMAP-info",
        name="Host discovered",
        severity="info",
        category="exposure",
        extra={"port": "80"},
    )
    assert poam_decision(rec)["include"] is False
    assert poam_decision(rec)["reason"] == "severity_info"


def _wazuh_alert(**kwargs):
    extra = {"rule_id": kwargs.pop("rule_id", "5710"), "telemetry": True}
    extra.update(kwargs.pop("extra", {}))
    return _finding(
        source="host-wazuh",
        ref_id=kwargs.pop("ref_id", "WAZ-alert-1"),
        name=kwargs.pop("name", "sshd: brute force trying to get access"),
        description=kwargs.pop("description", "sshd: brute force trying to get access"),
        severity=kwargs.pop("severity", "low"),
        category="incident",
        assets=kwargs.pop("assets", ["web-01"]),
        labels=kwargs.pop("labels", ["wazuh", "host", "alert"]),
        extra=extra,
        **kwargs,
    )


def test_poam_decision_telemetry_info_named() -> None:
    rec = _wazuh_alert(ref_id="WAZ-alert-info", severity="info")
    decision = poam_decision(rec)
    assert decision["include"] is False
    assert decision["reason"] == "telemetry_info"


def test_wazuh_multi_alert_lows_are_telemetry_not_poam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Aggregated Wazuh alerts stay off the POA&M unless level >= 12 or compromise."""
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    recs = [
        _wazuh_alert(ref_id="WAZ-alert-17001", extra={"rule_id": "5710", "rule_level": 5}),
        _wazuh_alert(ref_id="WAZ-alert-17002", extra={"rule_id": "5710", "rule_level": 5}),
        _wazuh_alert(ref_id="WAZ-alert-17003", extra={"rule_id": "5710", "rule_level": 5}),
        _wazuh_alert(
            ref_id="WAZ-alert-info",
            severity="info",
            name="Host login success",
            description="syslog: user login",
            extra={"rule_id": "5501", "rule_level": 3},
        ),
        _wazuh_alert(
            ref_id="WAZ-alert-other-host",
            extra={"rule_id": "5710", "rule_level": 5},
            assets=["db-01"],
        ),
    ]
    write_canonical("host-wazuh", recs)
    summary = load()
    assert summary["weaknesses_total"] == 5
    assert summary["poam_included"] == 0
    assert summary["excluded"] == 5
    assert summary["weaknesses_total"] == summary["poam_included"] + summary["excluded"]
    assert summary["excluded_by_reason"] == {
        "telemetry": 4,
        "telemetry_info": 1,
    }
    assert summary["weaknesses_total"] == summary["poam_included"] + sum(
        summary["excluded_by_reason"].values()
    )
    with (out_dir() / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    refs = [r["finding_ref_id"] for r in rows]
    assert refs == []
    with (out_dir() / "poam" / "excluded.csv").open(encoding="utf-8", newline="") as fh:
        ex = list(csv.DictReader(fh))
    by_ref = {row["finding_ref_id"]: row["excluded_reason"] for row in ex}
    assert by_ref["WAZ-alert-17001"] == "telemetry"
    assert by_ref["WAZ-alert-17002"] == "telemetry"
    assert by_ref["WAZ-alert-17003"] == "telemetry"
    assert by_ref["WAZ-alert-other-host"] == "telemetry"
    assert by_ref["WAZ-alert-info"] == "telemetry_info"
    walked = poam_breakdown(recs)
    assert walked["poam_included"] == 0
    assert walked["excluded_by_reason"] == {
        "telemetry": 4,
        "telemetry_info": 1,
    }
