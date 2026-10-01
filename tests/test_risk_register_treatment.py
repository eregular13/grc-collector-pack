"""Risk register must not mark POA&M-excluded rows mitigate.

Genuine excluded findings (honeypot, not_a_weakness, telemetry, info,
superseded) stay on the register as treatment=accept. Accept reason lives
in excluded.csv, not existing_controls. Collapsed pack_drop twins
(merged_into:<EGP>) stay off the register. SAMPLE/DEMO/LAB only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from collectors.grc_loader import load
from shared.ciso_shape import csv_rows
from shared.control_map import (
    EXCLUDED_TREATMENT,
    INCLUDED_TREATMENT,
    poam_decision,
    risk_register_treatment,
)
from shared.io_util import out_dir, write_canonical
from shared.schema import (
    CISO_REF_MAX,
    make_record,
    ref_slug,
    residual_level,
    scenario_level,
    slug,
)


def _finding(**kwargs):
    extra = kwargs.pop("extra", {})
    defaults = dict(
        kind="finding",
        source=kwargs.pop("source", "inventory-nmap"),
        ref_id=kwargs.pop("ref_id", "NMAP-x"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", "finding"),
        severity=kwargs.pop("severity", "high"),
        category=kwargs.pop("category", "exposure"),
        assets=kwargs.pop("assets", ["demo"]),
        extra=extra,
    )
    defaults.update(kwargs)
    return make_record(**defaults)


def test_risk_register_treatment_helper_splits_include_and_exclude() -> None:
    included = risk_register_treatment({"include": True, "reason": "severity_high_critical"})
    assert included["treatment"] == INCLUDED_TREATMENT == "mitigate"
    assert included["existing_controls"] == ""
    assert included["attach_control"] is True
    assert included["on_register"] is True

    for reason in (
        "honeypot",
        "not_a_weakness",
        "telemetry",
        "telemetry_info",
        "severity_info",
        "superseded_by_specific",
        "NOT_A_WEAKNESS",
    ):
        stamp = risk_register_treatment({"include": False, "reason": reason})
        assert stamp["treatment"] == EXCLUDED_TREATMENT == "accept"
        assert stamp["existing_controls"] == ""
        assert stamp["justification"] == reason
        assert stamp["attach_control"] is False
        assert stamp["on_register"] is True

    merged = risk_register_treatment(
        {"include": False, "reason": "merged_into:EGP-ABCDEF1234"}
    )
    assert merged["on_register"] is False
    assert merged["treatment"] == ""
    assert merged["existing_controls"] == ""
    assert merged["attach_control"] is False
    assert merged["justification"] == "merged_into:EGP-ABCDEF1234"


def test_uncapped_identity_slug_keeps_long_custodian_refs_distinct() -> None:
    a = "CLD-excl-stop-underutilized-azure-vms-subscription-aaaa-vm-1"
    b = "CLD-excl-stop-underutilized-azure-vms-subscription-bbbb-vm-2"
    assert slug(a) == slug(b)
    assert slug(a, maxlen=None) != slug(b, maxlen=None)
    assert slug(a, maxlen=None).startswith("cld-excl-stop-underutilized-azure-vms-subscription-")
    ra, rb = ref_slug(a), ref_slug(b)
    assert ra != rb
    assert len(f"RSK-{ra}") <= CISO_REF_MAX
    assert len(f"RSK-{rb}") <= CISO_REF_MAX
    long_mitigate = (
        "CLD-account-maintain-different-contact-details-to-security-"
        "billing-and-operations-account-unknown"
    )
    assert len(f"RSK-{slug(long_mitigate, maxlen=None)}") > CISO_REF_MAX
    assert len(f"RSK-{ref_slug(long_mitigate)}") <= CISO_REF_MAX
    assert ref_slug("NMAP-smb") == slug("NMAP-smb", maxlen=None)


def test_loader_excluded_scenarios_are_accept_not_mitigate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    recs = [
        _finding(
            ref_id="NMAP-smb",
            name="SMB exposed",
            description="box has open TCP/445 (microsoft-ds).",
            severity="high",
            extra={"port": "445", "service": "microsoft-ds"},
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
            ref_id="NMAP-info",
            name="Host discovered",
            description="banner only",
            severity="info",
            extra={"port": "80"},
        ),
        _finding(
            source="host-wazuh",
            ref_id="WAZ-alert-5710",
            name="sshd: authentication failed",
            description="brute-force telemetry, not a control failure.",
            severity="medium",
            category="alert",
            extra={"telemetry": True, "rule_id": "5710", "rule_level": 10},
        ),
        _finding(
            ref_id="NMAP-open-udp",
            name="UDP 123 open|filtered",
            description="open|filtered is not a confirmed listener.",
            severity="low",
            extra={"not_a_weakness": True, "port": "123", "protocol": "udp"},
        ),
    ]
    write_canonical("inventory-nmap", recs)
    summary = load()
    assert summary["risk_scenarios"] == summary["weaknesses"] == 5
    assert summary["excluded"] == 4
    assert summary["poam"] == 1

    scenarios = csv_rows(out_dir() / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    by_ref = {row["ref_id"]: row for row in scenarios}
    controls = {row["ref_id"] for row in csv_rows(out_dir() / "ciso-assistant" / "applied_controls.csv")}
    excluded = csv_rows(out_dir() / "poam" / "excluded.csv")
    excluded_reason = {row["finding_ref_id"]: row["excluded_reason"] for row in excluded}

    included = by_ref["RSK-nmap-smb"]
    assert poam_decision(recs[0])["include"] is True
    assert included["treatment"] == "mitigate"
    assert included["existing_controls"] == ""
    assert included["additional_controls"].startswith("CTL-")
    assert included["additional_controls"] in controls
    assert included["residual_risk"] == residual_level(scenario_level("high"))
    assert included["residual_risk"] != included["current_risk"]

    expect = {
        "RSK-hpot-1": ("HPOT-1", "honeypot"),
        "RSK-nmap-info": ("NMAP-info", "severity_info"),
        "RSK-waz-alert-5710": ("WAZ-alert-5710", "telemetry"),
        "RSK-nmap-open-udp": ("NMAP-open-udp", "not_a_weakness"),
    }
    for rsk, (finding_ref, reason) in expect.items():
        row = by_ref[rsk]
        assert excluded_reason[finding_ref] == reason
        assert row["treatment"] == "accept"
        assert row["existing_controls"] == ""
        assert row["additional_controls"] == ""
        assert row["residual_impact"] == row["current_impact"]
        assert row["residual_proba"] == row["current_proba"]
        assert row["residual_risk"] == row["current_risk"]
        assert "CTL-" not in (row["additional_controls"] or "")

    assert "CTL-hpot-1" not in controls
    assert "CTL-nmap-info" not in controls
    assert "CTL-waz-alert-5710" not in controls
    assert "CTL-nmap-open-udp" not in controls
    assert sum(1 for row in scenarios if row["treatment"] == "accept") == len(excluded)


def test_kind_excluded_row_is_accept_on_the_register(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    recs = [
        _finding(
            ref_id="CLD-sec",
            name="privileged pod",
            description="security-context-pods FAIL",
            severity="high",
            category="cloud-misconfiguration",
            extra={"check_id": "security-context-pods"},
        ),
        {
            "kind": "excluded",
            "source": "cloud-prowler",
            "ref_id": "CLD-cpu-waste",
            "name": "azure-vm-cpu-underutilized",
            "description": "cost/ops, not a weakness",
            "severity": "medium",
            "category": "excluded",
            "assets": ["vm-1"],
            "labels": ["not-a-weakness"],
            "extra": {"exclude_reason": "not_a_weakness", "check_id": "azure-vm-cpu-underutilized"},
        },
    ]
    write_canonical("cloud-prowler", recs)
    summary = load()
    assert summary["poam"] == 1
    assert summary["excluded"] == 1
    assert summary["kind_excluded"] == 1
    assert summary["risk_scenarios"] == 2
    scenarios = {row["ref_id"]: row for row in csv_rows(out_dir() / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")}
    assert scenarios["RSK-cld-sec"]["treatment"] == "mitigate"
    waste = scenarios["RSK-cld-cpu-waste"]
    assert waste["treatment"] == "accept"
    assert waste["existing_controls"] == ""
    assert waste["additional_controls"] == ""
    assert waste["residual_risk"] == waste["current_risk"]


def test_real_custodian_register_is_36_not_8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#173 kind:excluded + #181 accept: 8 POA&M / 28 excluded / 36 scenarios."""
    from collectors import cloud_prowler, host_wazuh

    root = Path(__file__).resolve().parents[1]
    cloud: list[dict] = []
    for rel in (
        "fixtures/samples/cloud/security-context-pods/resources.json",
        "fixtures/samples/cloud/stop-underutilized-azure-vms/resources.json",
        "fixtures/samples/cloud/stop-underutilized-aws-instances/resources.json",
        "fixtures/samples/cloud/check-ebs-snapshot-public/resources.json",
        "fixtures/samples/cloud/s3-encryption-missing/resources.json",
        "fixtures/samples/prowler/example_output_aws.ocsf.json",
    ):
        cloud.extend(cloud_prowler.parse_file(root / rel))
    osquery: list[dict] = []
    for name in (
        "osqueryd.results.sample.log",
        "osqueryd.results.darwin.log",
        "msticpy.osqueryd.results.log",
        "msticpy.osqueryd.snapshots.log",
    ):
        osquery.extend(host_wazuh.parse_file(root / "fixtures" / "samples" / "osquery" / name))
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    write_canonical("cloud-prowler", cloud)
    write_canonical("host-wazuh", osquery)
    summary = load()
    assert summary["poam"] == 8, summary
    assert summary["excluded"] == 28, summary.get("excluded_by_reason")
    assert summary["kind_excluded"] == 28
    assert summary["risk_scenarios"] == 36
    assert summary["findings"] + summary["kind_excluded"] == 36
    scenarios = csv_rows(out_dir() / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    refs = [row["ref_id"] for row in scenarios]
    assert len(set(refs)) == len(refs) == 36
    assert max(len(ref) for ref in refs) <= CISO_REF_MAX
    controls = csv_rows(out_dir() / "ciso-assistant" / "applied_controls.csv")
    ctl_refs = [row["ref_id"] for row in controls]
    assert len(set(ctl_refs)) == len(ctl_refs)
    assert max(len(ref) for ref in ctl_refs) <= CISO_REF_MAX
    accept = [row for row in scenarios if row.get("treatment") == "accept"]
    mitigate = [row for row in scenarios if row.get("treatment") == "mitigate"]
    assert len(accept) == 28
    assert len(mitigate) == 8
    excluded = csv_rows(out_dir() / "poam" / "excluded.csv")
    reasons = {str(row.get("excluded_reason") or "") for row in excluded}
    assert "not_a_weakness" in reasons
    assert "unmapped" in reasons
    assert all((row.get("existing_controls") or "") == "" for row in accept)
    assert all((row.get("additional_controls") or "") == "" for row in accept)
    assert all(row.get("residual_risk") == row.get("current_risk") for row in accept)
    assert all(str(row.get("additional_controls") or "").startswith("CTL-") for row in mitigate)


def test_pack_drop_twin_is_merged_into_not_accept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#180 twin shares one EGP; #181 must not accept the alias."""
    from shared.egp_collapse import MERGED_INTO_PREFIX
    from shared.poam_ledger import fp_v1

    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    xml = _finding(
        ref_id="NMAP-dc-445-tcp",
        name="SMB 445 exposed",
        description="dc.corp.local has open TCP/445 (microsoft-ds).",
        severity="high",
        assets=["dc.corp.local"],
        extra={
            "port": "445",
            "protocol": "tcp",
            "service": "microsoft-ds",
            "ip": "10.0.0.10",
            "check_id": "nmap-port-445/tcp",
            "tool": "nmap",
        },
    )
    twin = _finding(
        ref_id="NMAP-nmap-10-microsoftds-445",
        name="SMB 445 exposed",
        description="dc.corp.local has open TCP/445 (microsoft-ds).",
        severity="high",
        assets=["dc.corp.local"],
        extra={
            "port": "445",
            "protocol": "tcp",
            "service": "microsoft-ds",
            "ip": "10.0.0.10",
            "id": "nmap-10-microsoftds-445",
            "adapter": "nmap",
            "pack_drop": "covey",
        },
    )
    assert fp_v1(xml) == fp_v1(twin)
    write_canonical("inventory-nmap", [xml, twin])
    summary = load()
    assert summary["poam"] == 1
    assert summary["excluded"] == 1
    assert summary["risk_scenarios"] == 1
    excluded = csv_rows(out_dir() / "poam" / "excluded.csv")
    assert len(excluded) == 1
    assert str(excluded[0]["excluded_reason"]).startswith(MERGED_INTO_PREFIX)
    assert str(excluded[0]["superseded_by"]).startswith("EGP-")
    scenarios = csv_rows(out_dir() / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    assert len(scenarios) == 1
    assert scenarios[0]["treatment"] == "mitigate"
    assert scenarios[0]["existing_controls"] == ""
    assert scenarios[0]["name"] == "SMB 445 exposed"
    controls = csv_rows(out_dir() / "ciso-assistant" / "applied_controls.csv")
    assert len(controls) == 1


def test_same_egp_info_twin_is_merged_not_accept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Info + Low pack_drop twins share one EGP; info is an alias, not accept."""
    from shared.egp_collapse import MERGED_INTO_PREFIX
    from shared.poam_ledger import fp_v1

    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    low = _finding(
        ref_id="NMAP-naabu-c40-svc-22",
        name="Open TCP/22 observed",
        description="10.0.0.40 has open TCP/22.",
        severity="low",
        assets=["10.0.0.40"],
        extra={
            "port": "22",
            "protocol": "tcp",
            "id": "naabu-c40-svc-22",
            "adapter": "naabu",
            "pack_drop": "covey",
        },
    )
    info = _finding(
        ref_id="NMAP-naabu-c40-tcp-22",
        name="Open TCP/22 observed",
        description="10.0.0.40 has open TCP/22.",
        severity="info",
        assets=["10.0.0.40"],
        extra={
            "port": "22",
            "protocol": "tcp",
            "id": "naabu-c40-tcp-22",
            "adapter": "naabu",
            "pack_drop": "covey",
        },
    )
    assert fp_v1(low) == fp_v1(info)
    write_canonical("inventory-nmap", [low, info])
    summary = load()
    assert summary["poam"] == 1
    assert summary["excluded"] == 1
    assert summary["risk_scenarios"] == 1
    excluded = csv_rows(out_dir() / "poam" / "excluded.csv")
    assert len(excluded) == 1
    assert str(excluded[0]["excluded_reason"]).startswith(MERGED_INTO_PREFIX)
    scenarios = csv_rows(out_dir() / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    assert len(scenarios) == 1
    assert scenarios[0]["treatment"] == "mitigate"
    assert scenarios[0]["existing_controls"] == ""
