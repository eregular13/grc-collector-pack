"""Cold-review-5 §D: specific remediations + non-empty controls.

Pins BloodHound HasSession, CIS-CAT/XCCDF permitroot + firewall, Trivy
Dockerfile root USER, osquery ALF, Custodian public EBS snapshot, and
Greenbone/Nessus SSH weak crypto. SAMPLE/DEMO != client KEEP.
No POST /api/risks.
"""

from __future__ import annotations

from pathlib import Path

from collectors import cloud_prowler, host_wazuh, identity_ad, vuln_scan
from shared.control_map import map_finding
from shared.finding_types import finding_type
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
NESSUS = ROOT / "tests" / "fixtures" / "nessus"


def _assert_specific(mapped: dict, *, control: str, n53: set[str], tokens: tuple[str, ...]) -> None:
    assert mapped.get("generic") is False
    assert mapped["control_name"] == control
    assert "generic fallback" not in mapped["recommended_fix"].lower()
    got = set(mapped.get("nist_800_53") or [])
    assert n53 <= got, (control, got)
    blob = mapped["recommended_fix"].lower()
    assert all(tok in blob for tok in tokens), (control, blob)


def test_bloodhound_hassession_is_not_generic() -> None:
    rows = []
    for name in ("bhce_v6_sessions.json", "bhce_v6_computers.json"):
        recs = identity_ad.parse_file(SAMPLES / "bloodhound" / name)
        rows.extend(
            r for r in recs if r["kind"] == "finding" and "HasSession" in str(r.get("name") or "")
        )
    assert len(rows) >= 2, [r.get("name") for r in rows]
    for rec in rows:
        assert finding_type(rec) == "ad_session"
        mapped = map_finding(rec)
        _assert_specific(
            mapped,
            control="End privileged HasSession logons",
            n53={"AC-6", "AC-2"},
            tokens=("hassession", "workstation"),
        )


def test_xccdf_permitroot_and_firewall_are_not_generic() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "xccdf" / "rule-results.xml")
    findings = [r for r in recs if r["kind"] == "finding"]
    by_id = {r["extra"].get("id"): r for r in findings}
    permit = by_id["xccdf_sample_rule_ssh_permitroot"]
    firewall = by_id["xccdf_sample_rule_firewall"]
    assert finding_type(permit) == "ssh_root_login"
    assert finding_type(firewall) == "host_fw"
    _assert_specific(
        map_finding(permit),
        control="Disable SSH root login",
        n53={"IA-2", "CM-6"},
        tokens=("permitrootlogin",),
    )
    _assert_specific(
        map_finding(firewall),
        control="Enable a host firewall",
        n53={"SC-7", "CM-7"},
        tokens=("firewall",),
    )
    sca = next(
        r
        for r in host_wazuh.parse_file(SAMPLES / "wazuh" / "sca-checks.json")
        if r["kind"] == "finding"
    )
    smap = map_finding(sca)
    assert smap["control_name"] == "Disable SSH root login"
    assert {"IA-2"} <= set(smap.get("nist_800_53") or [])
    assert "permitrootlogin" in smap["recommended_fix"].lower()


def test_trivy_dockerfile_root_user_is_not_generic() -> None:
    recs = [r for r in vuln_scan.parse_file(SAMPLES / "trivy" / "dockerfile.json") if r["kind"] == "finding"]
    root = next(r for r in recs if "root" in str(r.get("name") or "").lower())
    assert finding_type(root) == "docker_nonroot"
    _assert_specific(
        map_finding(root),
        control="Run container images as a non-root USER",
        n53={"AC-6", "CM-7"},
        tokens=("user", "root"),
    )


def test_osquery_alf_firewall_disabled_is_not_generic() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "osquery" / "osqueryd.results.darwin.log")
    alf = next(r for r in recs if r["kind"] == "finding" and "Application firewall" in r["name"])
    assert finding_type(alf) == "host_fw"
    _assert_specific(
        map_finding(alf),
        control="Enable a host firewall",
        n53={"SC-7", "CM-7"},
        tokens=("firewall",),
    )


def test_custodian_ebs_snapshot_public_stamps_ac3_sc7_and_3s() -> None:
    recs = cloud_prowler.parse_file(SAMPLES / "cloud" / "check-ebs-snapshot-public" / "resources.json")
    ebs = next(r for r in recs if r["kind"] == "finding")
    assert finding_type(ebs) == "ebs_snapshot_public"
    mapped = map_finding(ebs)
    _assert_specific(
        mapped,
        control="Block public EBS snapshot sharing",
        n53={"AC-3", "SC-7"},
        tokens=("snapshot", "private"),
    )
    refs = " ".join(str(x) for x in (mapped.get("framework_refs") or []))
    stamps = " ".join(
        str(x)
        for x in (
            mapped.get("cpg"),
            mapped.get("cpg_id"),
            mapped.get("cpg_stamp"),
            refs,
        )
    )
    assert "3.S" in stamps or "cpg_3_S" in stamps or "3_S" in stamps, (stamps, refs)


def test_greenbone_ssh_weak_encryption_uses_scanner_solution() -> None:
    recs = [r for r in vuln_scan.parse_file(SAMPLES / "greenbone" / "one_vuln.csv") if r["kind"] == "finding"]
    weak = next(r for r in recs if "weak encryption" in r["name"].lower())
    mapped = map_finding(weak)
    _assert_specific(
        mapped,
        control="Disable weak SSH cryptographic algorithms",
        n53={"CM-6", "SC-13"},
        tokens=("disable the weak encryption algorithms",),
    )
    n53 = set(mapped.get("nist_800_53") or [])
    assert not {"SI-2", "RA-5"} <= n53
    assert "upgrade" not in mapped["recommended_fix"].lower()
    assert "package" not in mapped["recommended_fix"].lower()


def test_nessus_ssh_weak_mac_matches_greenbone_pattern() -> None:
    recs = [r for r in vuln_scan.parse_file(NESSUS / "ssh-weak-mac.nessus") if r["kind"] == "finding"]
    weak = next(r for r in recs if "weak mac" in r["name"].lower())
    mapped = map_finding(weak)
    _assert_specific(
        mapped,
        control="Disable weak SSH cryptographic algorithms",
        n53={"CM-6", "SC-13"},
        tokens=("disable the weak mac algorithms",),
    )
    n53 = set(mapped.get("nist_800_53") or [])
    assert not {"SI-2", "RA-5"} <= n53
    assert "upgrade" not in mapped["recommended_fix"].lower()
    assert "package" not in mapped["recommended_fix"].lower()


def test_unrelated_typed_cloud_row_stays_generic() -> None:
    rec = make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id="CLD-novel",
        name="Novel cloud check",
        description="unknown policy",
        extra={"check_id": "novel_unmapped_control_xyz"},
    )
    mapped = map_finding(rec)
    assert mapped.get("generic") is True
    assert "generic fallback" in mapped["recommended_fix"].lower()
