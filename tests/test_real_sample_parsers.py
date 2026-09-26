"""Parser tests against real-shaped tool output (fixtures/samples/).

Invented demo wrappers hid these: Prowler OCSF status/asset, Wazuh JSONL +
SCA, XCCDF rule-result severity, Trivy SARIF critical, enum4linux-ng keys.
SAMPLE/DEMO ≠ client KEEP. No POST /api/risks.
"""

from __future__ import annotations

from pathlib import Path

from collectors import cloud_prowler, host_wazuh, identity_ad, vuln_scan
from keep.adapters import detect_family
from shared.enum4linux import parse_enum4linux
from shared.sarif import iter_sarif_results, load_sarif

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
DEMO = ROOT / "fixtures" / "demo"


def test_prowler_ocsf_keeps_fail_and_resource_uid() -> None:
    recs = cloud_prowler.parse_file(SAMPLES / "prowler" / "example_output_aws.ocsf.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert findings, "v4/v5 OCSF status=New / status_code=FAIL must not drop every finding"
    assert "check" not in assets
    assert "<resource_uid>" in assets
    checks = {r["extra"].get("check_id") for r in findings}
    assert "accessanalyzer_enabled" in checks
    assert "account_maintain_current_contact_details" in checks
    analyzer = next(r for r in findings if r["extra"].get("check_id") == "accessanalyzer_enabled")
    assert analyzer["severity"] == "low"
    assert analyzer["assets"] == ["<resource_uid>"]
    assert all(r["extra"].get("status") in {"FAIL", "MANUAL"} for r in findings)
    assert detect_family(SAMPLES / "prowler" / "example_output_aws.ocsf.json") == "prowler"


def test_prowler_csv_semicolon() -> None:
    recs = cloud_prowler.parse_file(SAMPLES / "prowler" / "example_output_aws.csv")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert any(r["extra"].get("check_id") == "accessanalyzer_enabled" for r in findings)
    assert any(r["name"] == "<resource_uid>" for r in recs if r["kind"] == "asset")
    assert detect_family(SAMPLES / "prowler" / "example_output_aws.csv") == "prowler"


def test_wazuh_alerts_jsonl_maps_rule_level() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "wazuh" / "alerts.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    incidents = [r for r in recs if r["kind"] == "incident"]
    assert len(findings) == 3
    assert len(incidents) == 3
    assert {r["severity"] for r in findings} == {"low"}
    assert {r["severity"] for r in incidents} == {"low"}
    assert all("student-virtual-machine" in r["assets"] for r in findings)
    names = {r["name"] for r in findings}
    assert "Wazuh server started." in names
    assert "Systemd: Service exited due to a failure." in names


def test_wazuh_alerts_json_suffix_is_jsonl(tmp_path) -> None:
    dest = tmp_path / "alerts.json"
    dest.write_text(
        (SAMPLES / "wazuh" / "alerts.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    recs = host_wazuh.parse_file(dest)
    assert [r for r in recs if r["kind"] == "finding"]


def test_wazuh_alert_rule_level_bands(tmp_path) -> None:
    dest = tmp_path / "alerts.jsonl"
    dest.write_text(
        '{"rule":{"level":8,"description":"medium band","id":"8"},'
        '"agent":{"name":"web-01"},"id":"a8"}\n'
        '{"rule":{"level":12,"description":"high band","id":"12"},'
        '"agent":{"name":"web-01"},"id":"a12"}\n'
        '{"rule":{"level":15,"description":"critical band","id":"15"},'
        '"agent":{"name":"web-01"},"id":"a15"}\n',
        encoding="utf-8",
    )
    recs = host_wazuh.parse_file(dest)
    by_name = {r["name"]: r["severity"] for r in recs if r["kind"] == "finding"}
    assert by_name["medium band"] == "medium"
    assert by_name["high band"] == "high"
    assert by_name["critical band"] == "critical"


def test_wazuh_sca_failed_checks_not_fake_agents() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "wazuh" / "sca-checks.json")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    assert "19000" not in assets
    assert "19002" not in assets
    assert "wazuh-host" in assets
    assert len(findings) == 1
    assert "PermitRootLogin" in findings[0]["name"]
    assert "sca" in findings[0]["labels"]
    assert not any("cramfs" in r["name"].lower() for r in findings)
    assert not any("freevxfs" in r["name"].lower() for r in findings)


def test_xccdf_rule_result_severity_not_hardcoded_high() -> None:
    recs = host_wazuh.parse_file(SAMPLES / "xccdf" / "rule-results.xml")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 3
    by_id = {r["extra"].get("id"): r["severity"] for r in findings}
    assert by_id["xccdf_sample_rule_prelink"] == "low"
    assert by_id["xccdf_sample_rule_ssh_permitroot"] == "medium"
    assert by_id["xccdf_sample_rule_firewall"] == "high"
    assert not any("cramfs" in r["name"].lower() for r in findings)


def test_trivy_sarif_preserves_critical() -> None:
    path = SAMPLES / "sarif" / "trivy-critical.sarif"
    payload = load_sarif(path)
    assert payload
    rows = iter_sarif_results(payload)
    by_rule = {r["rule_id"]: r["severity"] for r in rows}
    assert by_rule["CVE-2023-0001"] == "critical"
    assert by_rule["CVE-2019-1549"] == "medium"
    recs = vuln_scan.parse_file(path)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any(r["extra"].get("rule") == "CVE-2023-0001" and r["severity"] == "critical" for r in findings)
    assert any(r["extra"].get("rule") == "CVE-2019-1549" and r["severity"] == "medium" for r in findings)


def test_enum4linux_ng_real_keys() -> None:
    path = SAMPLES / "enum4linux" / "enum4linux-ng.json"
    hosts = parse_enum4linux(path)
    assert hosts
    host = hosts[0]
    assert host["name"] != "{'host': '10.0.0.5'}"
    assert "{" not in host["name"]
    assert host["name"] == "DC01"
    assert host["addr"] == "10.0.0.5"
    assert host["null_session"] is True
    share_names = {s["name"] for s in host["shares"]}
    assert "NETLOGON" in share_names
    netlogon = next(s for s in host["shares"] if s["name"] == "NETLOGON")
    assert "WRITE" in netlogon["access"].upper()
    recs = identity_ad.parse_file(path)
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert any("null session" in n.lower() for n in names)
    assert any("NETLOGON" in n for n in names)
    assert not any("IPC$" in n for n in names)
    assert any(r["kind"] == "asset" and r["name"] == "DC01" for r in recs)


def test_enum4linux_demo_fixture_is_real_shaped() -> None:
    text = (DEMO / "identity" / "enum4linux-ng.txt").read_text(encoding="utf-8")
    assert '"null":' in text
    assert "null_session" not in text
    assert '"host":' in text
    recs = identity_ad.parse_file(DEMO / "identity" / "enum4linux-ng.txt")
    assert any(r["kind"] == "finding" and "null session" in r["name"].lower() for r in recs)
    assert any(r["kind"] == "asset" and r["name"] == "DC01.CORP.LOCAL" for r in recs)
