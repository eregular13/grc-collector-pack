from pathlib import Path

from collectors import cloud_prowler, code_secrets, easm, host_wazuh, identity_ad, inventory_nmap, k8s_kubescape, saas_idp, vuln_scan

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"


def test_prowler_asff() -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "prowler-asff.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert findings[0]["severity"] == "high"
    assert any("demo-public-assets" in str(r.get("assets")) for r in recs)
    assert any("demo-asff-open" in str(r.get("assets")) for r in recs)
    public = next(r for r in findings if "demo-asff-open" in str(r.get("assets")))
    assert public["extra"].get("check_id") == "s3_bucket_public_access"
    assert public["extra"].get("service") == "s3"
    assert public["severity"] == "high"
    refs = {r["ref_id"] for r in findings}
    assert len(refs) == len(findings)


def test_pingcastle_xml() -> None:
    recs = identity_ad.parse_file(DEMO / "identity" / "pingcastle.xml")
    names = [r["name"] for r in recs]
    assert any("Backup Operators" in n for n in names)
    assert any(r["kind"] == "finding" and r["name"] == "Roastable SPN" for r in recs)
    assert any(r["kind"] == "finding" and "AS-REP" in r["name"] for r in recs)


def test_greenbone() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "greenbone.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert any("Heartbleed" in r["name"] for r in findings)


def test_amass_jsonl() -> None:
    recs = easm.parse_file(DEMO / "easm" / "amass.jsonl")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "vpn.example.com" in assets
    assert "intranet.example.com" in assets


def test_osquery_coverage() -> None:
    recs = host_wazuh.parse_file(DEMO / "wazuh" / "osquery.json")
    names = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "laptop-04" in names
    assert any(r["kind"] == "finding" and "jump-unmanaged" in r["name"] for r in recs)


def test_trufflehog_jsonl() -> None:
    recs = code_secrets.parse_file(DEMO / "code" / "trufflehog.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("TruffleHog AWS" in r["name"] for r in findings)
    assert any(r["severity"] == "critical" for r in findings)
    blob = str(recs)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "ghp_" not in blob


def test_cloud_custodian() -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "custodian.json")
    assert any(r["kind"] == "asset" and r["name"] == "demo-unencrypted-tmp" for r in recs)
    assert any("Cloud Custodian" in r["name"] for r in recs if r["kind"] == "finding")


def test_steampipe_rows() -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "steampipe.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert any("nomega" in str(r.get("assets")) for r in findings)
    assert any(r["extra"].get("asset_type") == "SP" for r in recs if r["kind"] == "asset")


def test_nmap_gnmap() -> None:
    recs = inventory_nmap.parse_file(DEMO / "nmap" / "scan.gnmap")
    names = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "legacy-ftp.corp.local" in names
    assert any(r["kind"] == "finding" and "FTP" in r["name"] for r in recs)


def test_bloodhound_edges() -> None:
    recs = identity_ad.parse_file(DEMO / "identity" / "bloodhound-edges.json")
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert "BloodHound GenericAll" in names
    assert "BloodHound DCSync" in names
    assert any(r["severity"] == "critical" for r in recs if r["kind"] == "finding")


def test_fleet_hosts() -> None:
    recs = host_wazuh.parse_file(DEMO / "wazuh" / "fleet.json")
    names = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "fleet-laptop-07" in names
    assert any(r["kind"] == "finding" and "fleet-laptop-07" in r["name"] for r in recs)


def test_sarif() -> None:
    recs = code_secrets.parse_file(DEMO / "code" / "semgrep.sarif.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert any("SQL injection" in r["name"] for r in findings)
    assert any("services/payments/query.py" in r["assets"] for r in findings)


def test_vuln_sarif_suffix_and_poam_map() -> None:
    from shared.control_map import map_finding

    recs = vuln_scan.parse_file(DEMO / "vuln" / "demo.sarif")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    hit = findings[0]
    assert hit["severity"] == "high"
    assert "sarif" in hit["labels"]
    assert "command-injection" in str(hit.get("extra", {}).get("rule"))
    assert any(r["kind"] == "asset" and "app-01.demo.internal" in r["name"] for r in recs)
    mapped = map_finding(hit)
    assert mapped["include_poam"] is True
    assert "command injection" in mapped["control_name"].lower()


def test_code_sarif_extension(tmp_path) -> None:
    dest = tmp_path / "drop.sarif"
    dest.write_text((DEMO / "code" / "semgrep.sarif.json").read_text(encoding="utf-8"), encoding="utf-8")
    recs = code_secrets.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    from shared.control_map import map_finding

    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "SQL injection" in mapped["control_name"]


def test_empty_in_still_loads_demo_including_sarif(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in" / "vuln").mkdir(parents=True)
    files, demo = load_inputs("vuln-scan", (".json", ".jsonl", ".sarif"))
    assert demo is True
    names = {p.name for p in files}
    assert "nuclei.jsonl" in names
    assert "demo.sarif" in names


def test_minimal_asff_productfields_and_severity_string(tmp_path) -> None:
    from shared.control_map import map_finding

    dest = tmp_path / "minimal.asff.json"
    dest.write_text(
        """{
  "Findings": [
    {
      "Id": "asff-min-1",
      "GeneratorId": "ignored-generator",
      "Title": "S3 bucket allows public access",
      "Description": "demo-asff-min is reachable by AllUsers.",
      "Severity": "HIGH",
      "Compliance": {"Status": "FAILED"},
      "ProductFields": {
        "ProwlerCheckID": "s3_bucket_public_access",
        "ProwlerServiceName": "s3"
      },
      "Resources": [
        {"Id": "arn:aws:s3:::demo-asff-min", "Type": "AwsS3Bucket"}
      ]
    }
  ]
}
""",
        encoding="utf-8",
    )
    recs = cloud_prowler.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    hit = findings[0]
    assert hit["severity"] == "high"
    assert hit["extra"].get("check_id") == "s3_bucket_public_access"
    assert hit["extra"].get("service") == "s3"
    assert "demo-asff-min" in str(hit.get("assets"))
    mapped = map_finding(hit)
    assert mapped["include_poam"] is True
    assert "public" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_empty_in_still_loads_cloud_asff_and_scoutsuite(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-cloud"))
    (tmp_path / "empty-cloud" / "cloud").mkdir(parents=True)
    files, demo = load_inputs("cloud-prowler", (".json",))
    assert demo is True
    names = {p.name for p in files}
    assert "prowler-asff.json" in names
    assert "scoutsuite.json" in names
    recs = []
    for path in files:
        recs.extend(cloud_prowler.parse_file(path))
    assert any(r["kind"] == "finding" for r in recs)


def test_hardeningkitty_csv() -> None:
    recs = identity_ad.parse_file(DEMO / "identity" / "hardeningkitty.csv")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("password history" in r["name"] for r in findings)
    assert not any("Guest account" in r["name"] for r in findings)
    blob = str(recs)
    assert " actual=5" not in blob


def test_maester() -> None:
    recs = saas_idp.parse_file(DEMO / "saas" / "maester.json")
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert any("MT.1035" in n for n in names)
    assert not any("MT.1001" in n for n in names)


def test_testssl() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "testssl.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("heartbleed" in r["name"].lower() or "CVE-2014-0160" in str(r) for r in findings)


def test_ms_graph_directory_roles() -> None:
    recs = saas_idp.parse_file(DEMO / "saas" / "graph.json")
    assert any(r["kind"] == "finding" and "Graph" in r["name"] for r in recs)
    assert any("ga@contoso.onmicrosoft.com" in str(r.get("assets")) for r in recs)


def test_kube_bench() -> None:
    recs = k8s_kubescape.parse_file(DEMO / "k8s" / "kube-bench.json")
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert any("Anonymous" in n or "privileged" in n.lower() for n in names)


def test_httpx_jsonl() -> None:
    recs = easm.parse_file(DEMO / "easm" / "httpx.jsonl")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "vpn.example.com" in assets
    assert any(r["kind"] == "finding" and "vpn.example.com" in r["assets"] for r in recs)


def test_scoutsuite() -> None:
    from shared.control_map import map_finding

    recs = cloud_prowler.parse_file(DEMO / "cloud" / "scoutsuite.json")
    assert any(r["kind"] == "asset" and "demo-scout-public" in r["name"] for r in recs)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("ScoutSuite" in r["name"] for r in findings)
    assert any(r["extra"].get("service") == "s3" for r in findings)
    assert any("s3" in r["name"] for r in findings)
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "public" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_falco_jsonl() -> None:
    recs = k8s_kubescape.parse_file(DEMO / "k8s" / "falco.jsonl")
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert "Launch Privileged Container" in names
    assert any(r["severity"] == "critical" for r in recs if r["kind"] == "finding")
