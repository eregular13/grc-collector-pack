"""§8 real-shaped samples: PingCastle, Greenbone, ScubaGear, testssl, Nikto."""

from __future__ import annotations

from pathlib import Path

from collectors import identity_ad, saas_idp, vuln_scan
from shared.nikto import is_nikto_payload, parse_nikto
from shared.testssl import iter_testssl_findings

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
DEMO = ROOT / "fixtures" / "demo"


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "finding"]


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
