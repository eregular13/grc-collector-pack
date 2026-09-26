"""Risk register must not mark POA&M-excluded rows mitigate.

Excluded findings (honeypot, not_a_weakness, telemetry, info, superseded)
stay on the register 1:1 with weaknesses, but treatment=accept with the
exclusion reason. No CTL- and residual stays current. SAMPLE/DEMO/LAB only.
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
from shared.schema import make_record, residual_level, scenario_level


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
        assert stamp["existing_controls"] == f"excluded:{reason}"
        assert stamp["attach_control"] is False


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
        assert row["existing_controls"] == f"excluded:{reason}"
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
