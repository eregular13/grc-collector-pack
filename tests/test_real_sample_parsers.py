"""Parser tests against real-shaped tool output (fixtures/samples/).

Invented demo wrappers hid these: Prowler OCSF status/asset, Wazuh JSONL +
SCA, XCCDF rule-result severity, Trivy SARIF critical, enum4linux-ng keys,
PingCastle RiskRules, Greenbone GMP, ScubaGear v1.8, testssl sections, Nikto 2.6.
SAMPLE/DEMO ≠ client KEEP. No POST /api/risks.
"""

from __future__ import annotations

from pathlib import Path

from collectors import cloud_prowler, host_wazuh, identity_ad, saas_idp, vuln_scan
from keep.adapters import detect_family
from shared.enum4linux import parse_enum4linux
from shared.nikto import is_nikto_payload, parse_nikto
from shared.sarif import iter_sarif_results, load_sarif
from shared.testssl import iter_testssl_findings

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
DEMO = ROOT / "fixtures" / "demo"


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "finding"]


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


def test_samples_sources_credits_public_fixtures() -> None:
    text = (SAMPLES / "SOURCES.md").read_text(encoding="utf-8")
    assert "SAMPLE/DEMO" in text
    assert "client KEEP" in text
    assert "DefectDojo" in text
    assert "ScubaGear" in text
    assert "/api/risks" in text
    assert "RiskReady" in text


def test_pingcastle_real_riskrules_and_healthcheck_group() -> None:
    recs = identity_ad.parse_file(SAMPLES / "pingcastle" / "one.xml")
    findings = _findings(recs)
    assets = {r["name"] for r in recs if r["kind"] == "asset"}
    assert "example.local" in assets
    assert "Backup Operators" in assets
    assert any(r["extra"].get("risk_id") == "A-MinPwdLen" for r in findings)
    minpwd = next(r for r in findings if r["extra"].get("risk_id") == "A-MinPwdLen")
    assert minpwd["severity"] == "medium"
    assert "less than 8" in minpwd["description"]
    assert "example.local" in minpwd["assets"]
    assert any(r["name"] == "Backup Operators privileged group" for r in findings)
    assert any("AS-REP" in r["name"] for r in findings)
    assert not any("contoso" in str(r.get("assets")) for r in recs)


def test_pingcastle_demo_fixture_still_parses() -> None:
    recs = identity_ad.parse_file(DEMO / "identity" / "pingcastle.xml")
    names = [r["name"] for r in recs]
    assert any("Backup Operators" in n for n in names)
    assert any(r["kind"] == "finding" and r["name"] == "Roastable SPN" for r in recs)
    assert any(r["kind"] == "finding" and "AS-REP" in r["name"] for r in recs)


def test_greenbone_gmp_xml_and_csv() -> None:
    xml_recs = vuln_scan.parse_file(SAMPLES / "greenbone" / "one_vuln.xml")
    xml_find = _findings(xml_recs)
    assert len(xml_find) == 1
    hit = xml_find[0]
    assert "Firefox" in hit["name"]
    assert hit["severity"] == "critical"
    assert hit["extra"].get("cve") == "CVE-2023-4573"
    assert "10.0.101.2" in hit["assets"]
    assert any(r["kind"] == "asset" and r["name"] == "10.0.101.2" for r in xml_recs)

    csv_recs = vuln_scan.parse_file(SAMPLES / "greenbone" / "one_vuln.csv")
    csv_find = _findings(csv_recs)
    assert len(csv_find) == 1
    assert "SSH Weak Encryption" in csv_find[0]["name"]
    assert csv_find[0]["severity"] == "medium"
    assert "10.0.0.8" in csv_find[0]["assets"]


def test_greenbone_demo_json_still_parses() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "greenbone.json")
    findings = _findings(recs)
    assert any("Heartbleed" in r["name"] for r in findings)


def test_scuba_v18_product_keyed_results() -> None:
    recs = saas_idp.parse_file(SAMPLES / "scuba" / "ScubaResults_sample.json")
    findings = _findings(recs)
    assert len(findings) == 2
    names = [r["name"] for r in findings]
    assert any("Legacy authentication" in n for n in names)
    assert any("phishing-resistant" in n.lower() for n in names)
    assert not any("Security defaults" in n for n in names)
    fail = next(r for r in findings if "Legacy" in r["name"])
    warn = next(r for r in findings if "phishing-resistant" in r["name"].lower())
    assert fail["severity"] == "high"
    assert warn["severity"] == "medium"
    assert all("example.onmicrosoft.com" in r["assets"] for r in findings)
    assert not any("contoso" in str(r.get("assets")).lower() for r in recs)
    assert not any(r.get("name") == "m365" for r in recs)


def test_graph_and_maester_unknown_tenant_not_contoso(tmp_path: Path) -> None:
    graph = tmp_path / "graph-notenants.json"
    graph.write_text(
        """{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#directoryRoles",
  "directoryRoles": [
    {"displayName": "Global Administrator", "members": [{"userPrincipalName": "ga@example.onmicrosoft.com"}]}
  ]
}
""",
        encoding="utf-8",
    )
    recs = saas_idp.parse_file(graph)
    findings = _findings(recs)
    assert findings
    assert all("contoso.onmicrosoft.com" not in str(r.get("assets")) for r in recs)
    assert any("unknown" in r["assets"] for r in findings)

    maester = tmp_path / "maester-notenants.json"
    maester.write_text(
        """{
  "TestResults": [
    {"Id": "MT.1035", "Passed": false, "Severity": "high",
     "Description": "Privileged users should have phishing-resistant MFA"}
  ]
}
""",
        encoding="utf-8",
    )
    recs = saas_idp.parse_file(maester)
    findings = _findings(recs)
    assert len(findings) == 1
    assert "unknown" in findings[0]["assets"]
    assert "contoso.onmicrosoft.com" not in str(findings[0]["assets"])


def test_testssl_all_sections_keep_low_medium() -> None:
    recs = vuln_scan.parse_file(SAMPLES / "testssl" / "finos_robmoff.at_443_vulnerable.json")
    findings = _findings(recs)
    ids = {r["name"] for r in findings}
    assert "SSLv3" in ids
    assert "TLS1" in ids
    assert "cert_expirationStatus" in ids
    assert "BREACH" in ids
    assert "LUCKY13" in ids
    assert "heartbleed" not in ids
    assert "TLS1_2" not in ids
    by_id = {r["name"]: r for r in findings}
    assert by_id["SSLv3"]["severity"] == "high"
    assert by_id["TLS1"]["severity"] == "low"
    assert by_id["BREACH"]["severity"] == "medium"
    assert by_id["LUCKY13"]["severity"] == "low"
    assert by_id["cert_expirationStatus"]["severity"] == "high"

    defaults = vuln_scan.parse_file(SAMPLES / "testssl" / "server-defaults.json")
    df = _findings(defaults)
    assert any(r["name"] == "cert_expirationStatus" and r["severity"] == "high" for r in df)
    warn = next(r for r in df if r["name"] == "cert_caIssuers")
    assert warn["severity"] == "info"
    assert "scan-error" in warn["labels"]


def test_testssl_demo_still_keeps_high() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "testssl.json")
    findings = _findings(recs)
    assert any("heartbleed" in r["name"].lower() or "CVE-2014-0160" in str(r) for r in findings)
    assert any("TLS1" in r["name"] or "TLS 1.0" in r["description"] for r in findings)
    assert not any("secure_renego" in r["name"] for r in findings)


def test_nikto_26_json_list_and_sensible_severity() -> None:
    payload = [
        {
            "host": "example.com",
            "vulnerabilities": [{"id": "999966", "url": "/", "msg": "BREACH attack"}],
        }
    ]
    assert is_nikto_payload(payload)

    recs = vuln_scan.parse_file(SAMPLES / "nikto" / "issue_9274.json")
    findings = _findings(recs)
    assert findings, "Nikto 2.6 list-of-hosts JSON must not be silently empty"
    msgs = " ".join(r["description"] for r in findings).lower()
    assert "x-frame-options" not in msgs
    assert "x-content-type-options" not in msgs
    assert "uncommon header" not in msgs
    assert "retrieved via header" not in msgs
    assert any("breach" in r["description"].lower() for r in findings)
    assert all(r["severity"] in {"low", "medium", "high", "critical"} for r in findings)
    assert not any(r["severity"] == "high" and "robots.txt" in r["description"] for r in findings)


def test_nikto_juice_shop_drops_soft404_backup_noise() -> None:
    recs = vuln_scan.parse_file(SAMPLES / "nikto" / "juice-shop-trim.json")
    findings = _findings(recs)
    assert not any("backup/cert file" in r["description"].lower() for r in findings)
    assert not any("strict-transport-security" in r["description"].lower() for r in findings)
    assert any("lfi" in r["description"].lower() or "directory-traversal" in r["description"].lower() for r in findings)
    lfi = next(r for r in findings if "lfi" in r["description"].lower() or "nextgen" in r["description"].lower())
    assert lfi["severity"] == "high"
    assert not any(r["severity"] == "high" and "backup" in r["description"].lower() for r in findings)


def test_nikto_xml_keeps_real_findings_not_headers() -> None:
    recs = vuln_scan.parse_file(SAMPLES / "nikto" / "nikto-output-trim.xml")
    findings = _findings(recs)
    blob = " ".join(r["description"] for r in findings).lower()
    assert "x-frame-options" not in blob
    assert any("put" in r["description"].lower() for r in findings)
    assert any("xss" in r["description"].lower() for r in findings)
    assert any("manager" in r["description"].lower() for r in findings)
    xss = next(r for r in findings if "xss" in r["description"].lower())
    assert xss["severity"] == "high"


def test_nikto_demo_txt_still_keeps_admin() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "nikto.txt")
    findings = _findings(recs)
    assert len(findings) == 1
    assert "Admin login" in findings[0]["name"]
    assert "X-Frame-Options" not in str(recs)


def test_iter_testssl_protocols_not_just_vulnerabilities() -> None:
    import json

    payload = json.loads(
        (SAMPLES / "testssl" / "finos_robmoff.at_443_vulnerable.json").read_text(encoding="utf-8")
    )
    rows = list(iter_testssl_findings(payload))
    ids = {r["id"] for r in rows}
    assert "SSLv3" in ids
    assert "TLS1" in ids
    assert "BREACH" in ids
    assert "heartbleed" not in ids


def test_parse_nikto_reads_list_of_hosts() -> None:
    rows = parse_nikto(SAMPLES / "nikto" / "issue_9274.json")
    assert rows is not None
    assert len(rows) == 7
    assert rows[0]["host"] == "example.com"
