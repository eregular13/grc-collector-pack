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
    assert not any("osquery disk" in r["name"].lower() for r in recs if r["kind"] == "finding")


def test_cis_cat_and_osquery_fail_only() -> None:
    from shared.control_map import map_finding

    recs = host_wazuh.parse_file(DEMO / "wazuh" / "cis-cat.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "PermitRootLogin" in findings[0]["name"]
    assert not any("firewall" in r["name"].lower() for r in findings)
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "root login" in mapped["control_name"].lower() or "permitrootlogin" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]

    oq = host_wazuh.parse_file(DEMO / "wazuh" / "osquery-checks.json")
    ofind = [r for r in oq if r["kind"] == "finding"]
    assert len(ofind) == 1
    assert "disk encryption" in ofind[0]["name"].lower() or "disk encryption" in ofind[0]["description"].lower()
    om = map_finding(ofind[0])
    assert om["include_poam"] is True
    assert "disk encryption" in om["control_name"].lower()
    assert "CVE-" not in om["recommended_fix"]


def test_cis_cat_xml_identity(tmp_path) -> None:
    dest = tmp_path / "cis-cat.xml"
    dest.write_text(
        """<?xml version="1.0"?>
        <Benchmark>
          <TestResult>
            <target>jump-unmanaged</target>
            <rule-result idref="5.2.10" title="Ensure SSH PermitRootLogin is no">
              <result>fail</result>
            </rule-result>
            <rule-result idref="1.1.1" title="Ensure cramfs is disabled">
              <result>pass</result>
            </rule-result>
          </TestResult>
        </Benchmark>""",
        encoding="utf-8",
    )
    recs = identity_ad.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "PermitRootLogin" in findings[0]["name"]


def test_empty_cis_osquery_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "empty-cis.json"
    dest.write_text("""{"benchmark":"CIS","target":"h","results":[]}""", encoding="utf-8")
    assert host_wazuh.parse_file(dest) == []
    dest.write_text("""{"queries":[]}""", encoding="utf-8")
    assert host_wazuh.parse_file(dest) == []


def test_empty_in_still_loads_cis_osquery(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-wazuh-cis"))
    (tmp_path / "empty-wazuh-cis" / "wazuh").mkdir(parents=True)
    files, demo = load_inputs("host-wazuh", (".json", ".xml", ".txt", ".log", ".dat"))
    assert demo is True
    names = {p.name for p in files}
    assert "cis-cat.json" in names
    assert "osquery-checks.json" in names
    assert "osquery.json" in names


def test_trufflehog_jsonl() -> None:
    recs = code_secrets.parse_file(DEMO / "code" / "trufflehog.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("TruffleHog AWS" in r["name"] for r in findings)
    assert any(r["severity"] == "critical" for r in findings)
    blob = str(recs)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "ghp_" not in blob


def test_gitleaks_json_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = code_secrets.parse_file(DEMO / "code" / "gitleaks.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert any("services/payments/config.py" in (r.get("assets") or []) for r in findings)
    blob = str(recs)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "credential" in mapped["control_name"].lower() or "secret" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_gitleaks_results_wrapper(tmp_path) -> None:
    dest = tmp_path / "gitleaks-wrap.json"
    dest.write_text(
        """{"results":[{"RuleID":"generic-api-key","Description":"Generic API Key",
        "File":"services/payments/config.py","StartLine":12}]}""",
        encoding="utf-8",
    )
    recs = code_secrets.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("generic-api-key" in r["description"] for r in findings)
    assert any(r["kind"] == "asset" and r["name"] == "services/payments/config.py" for r in recs)


def test_trufflehog_results_wrapper(tmp_path) -> None:
    dest = tmp_path / "hog-wrap.json"
    dest.write_text(
        """{"results":[{"DetectorName":"AWS","Verified":false,
        "SourceMetadata":{"Data":{"Filesystem":{"file":"infra/terraform.tfvars"}}}}]}""",
        encoding="utf-8",
    )
    recs = code_secrets.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("TruffleHog AWS" in r["name"] for r in findings)
    assert any(r["kind"] == "asset" and r["name"] == "infra/terraform.tfvars" for r in recs)


def test_checkov_failed_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = code_secrets.parse_file(DEMO / "code" / "checkov.json")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "infra/terraform.tfvars" in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "CKV_AWS_20" in findings[0]["description"]
    assert "versioning" not in findings[0]["name"].lower()
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "public" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_empty_code_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "empty-code.json"
    dest.write_text("[]", encoding="utf-8")
    assert code_secrets.parse_file(dest) == []
    dest.write_text("""{"findings":[],"leaks":[],"results":[]}""", encoding="utf-8")
    assert code_secrets.parse_file(dest) == []
    dest.write_text(
        """{"check_type":"terraform","results":{"failed_checks":[],"passed_checks":[{"check_id":"CKV_AWS_21","check_name":"ok","file_path":"/infra/x.tf"}]}}""",
        encoding="utf-8",
    )
    assert code_secrets.parse_file(dest) == []


def test_empty_in_still_loads_code(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-code"))
    (tmp_path / "empty-code" / "code").mkdir(parents=True)
    files, demo = load_inputs("code-secrets", (".json", ".jsonl", ".sarif"))
    assert demo is True
    names = {p.name for p in files}
    assert "gitleaks.json" in names
    assert "trufflehog.jsonl" in names
    assert "checkov.json" in names


def test_code_secrets_no_live_scan() -> None:
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "collectors" / "code_secrets.py").read_text(
        encoding="utf-8"
    )
    assert "import subprocess" not in src
    assert "Popen" not in src
    assert "gitleaks detect" not in src
    assert "checkov -" not in src
    assert "semgrep --" not in src
    assert "trufflehog git" not in src
    assert "socket.socket" not in src


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


def test_nmap_xml_risky_ports_map() -> None:
    from shared.control_map import map_finding

    recs = inventory_nmap.parse_file(DEMO / "nmap" / "scan.xml")
    findings = [r for r in recs if r["kind"] == "finding"]
    by_port = {str((r.get("extra") or {}).get("port")): r for r in findings}
    assert "445" in by_port and "3389" in by_port and "23" in by_port
    smb = map_finding(by_port["445"])
    assert smb["include_poam"] is True
    assert "SMB" in smb["control_name"] or "445" in smb["recommended_fix"]
    assert "CVE-" not in smb["recommended_fix"]
    rdp = map_finding(by_port["3389"])
    assert rdp["include_poam"] is True
    tel = map_finding(by_port["23"])
    assert tel["include_poam"] is True
    assert "Telnet" in tel["control_name"]


def test_lab_stub_gnmap_parses(tmp_path) -> None:
    import subprocess
    from pathlib import Path

    stub = Path(__file__).resolve().parents[1] / "farm" / "tool-bin" / "lab" / "nmap"
    out = subprocess.check_output([str(stub)], text=True)
    dest = tmp_path / "dropbox-discover-lab.gnmap"
    dest.write_text(out, encoding="utf-8")
    recs = inventory_nmap.parse_file(dest)
    assert any(r["kind"] == "asset" and r["name"] == "app-01.demo.internal" for r in recs)
    ssh = [r for r in recs if r["kind"] == "finding" and (r.get("extra") or {}).get("port") == "22"]
    assert ssh
    assert "demo" in recs[0]["labels"]
    src = (Path(__file__).resolve().parents[1] / "collectors" / "inventory_nmap.py").read_text(encoding="utf-8")
    assert "import subprocess" not in src
    assert "Popen" not in src
    assert "nmap -" not in src


def test_minimal_nmap_json(tmp_path) -> None:
    from shared.control_map import map_finding

    dest = tmp_path / "scan.json"
    dest.write_text(
        """{"hosts":[{"hostname":"filesrv.corp.local","ip":"10.0.0.50",
        "ports":[{"port":445,"state":"open","service":"microsoft-ds"},
                 {"port":445,"state":"filtered","service":"microsoft-ds"}]}]}""",
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any((r.get("extra") or {}).get("port") == "445" for r in findings)
    smb = next(r for r in findings if (r.get("extra") or {}).get("port") == "445")
    mapped = map_finding(smb)
    assert mapped["include_poam"] is True
    assert "CVE-" not in mapped["recommended_fix"]


def test_empty_in_still_loads_nmap(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-nmap"))
    (tmp_path / "empty-nmap" / "nmap").mkdir(parents=True)
    files, demo = load_inputs("inventory-nmap", (".xml", ".gnmap", ".txt", ".json", ".jsonl"))
    assert demo is True
    names = {p.name for p in files}
    assert "scan.gnmap" in names
    assert "scan.xml" in names
    assert "masscan.xml" in names
    assert "naabu.jsonl" in names


def test_masscan_xml_rdp_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = inventory_nmap.parse_file(DEMO / "nmap" / "masscan.xml")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "filesrv.corp.local" in assets
    assert "10.0.0.50" not in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert (findings[0].get("extra") or {}).get("port") == "3389"
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "rdp" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_masscan_json_and_empty(tmp_path) -> None:
    dest = tmp_path / "masscan.json"
    dest.write_text(
        """[{"ip":"10.0.0.50","ports":[{"port":445,"proto":"tcp","status":"open"},
         {"port":22,"proto":"tcp","status":"closed"}]}]""",
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any((r.get("extra") or {}).get("port") == "445" for r in findings)
    assert not any((r.get("extra") or {}).get("port") == "22" for r in findings)
    dest.write_text("[]", encoding="utf-8")
    assert inventory_nmap.parse_file(dest) == []
    dest.write_text('{"ip":"10.0.0.50","ports":[]}', encoding="utf-8")
    assert inventory_nmap.parse_file(dest) == []
    xml = tmp_path / "empty-masscan.xml"
    xml.write_text(
        '<?xml version="1.0"?><!--masscan--><nmaprun scanner="masscan"></nmaprun>',
        encoding="utf-8",
    )
    assert inventory_nmap.parse_file(xml) == []


def test_masscan_parser_no_live() -> None:
    for rel in ("collectors/inventory_nmap.py", "shared/masscan.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "import subprocess" not in src
        assert "Popen" not in src
        assert "masscan -p" not in src
        assert "masscan --" not in src
        assert "nmap -" not in src
        assert "urllib.request" not in src
        assert "socket.socket" not in src


def test_naabu_jsonl_telnet_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = inventory_nmap.parse_file(DEMO / "nmap" / "naabu.jsonl")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "filesrv.corp.local" in assets
    assert "10.0.0.50" not in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert (findings[0].get("extra") or {}).get("port") == "23"
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "telnet" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_rustscan_json_and_empty(tmp_path) -> None:
    dest = tmp_path / "rustscan.json"
    dest.write_text(
        '{"ip":"10.0.0.50","hostname":"filesrv.corp.local","ports":[445, 22]}',
        encoding="utf-8",
    )
    recs = inventory_nmap.parse_file(dest)
    ports = {(r.get("extra") or {}).get("port") for r in recs if r["kind"] == "finding"}
    assert "445" in ports
    assert "22" in ports
    dest.write_text("[]", encoding="utf-8")
    assert inventory_nmap.parse_file(dest) == []
    dest = tmp_path / "naabu-empty.jsonl"
    dest.write_text("", encoding="utf-8")
    assert inventory_nmap.parse_file(dest) == []
    dest.write_text('{"ip":"10.0.0.50","ports":[]}\n', encoding="utf-8")
    assert inventory_nmap.parse_file(dest) == []
    dest.write_text('{"ip":"10.0.0.50","port":22,"status":"closed"}\n', encoding="utf-8")
    assert inventory_nmap.parse_file(dest) == []


def test_fast_portscan_parser_no_live() -> None:
    for rel in ("collectors/inventory_nmap.py", "shared/fast_portscan.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "import subprocess" not in src
        assert "Popen" not in src
        assert "rustscan -" not in src
        assert "naabu -" not in src
        assert "nmap -" not in src
        assert "urllib.request" not in src
        assert "socket.socket" not in src


def test_bloodhound_edges() -> None:
    from shared.control_map import map_finding

    recs = identity_ad.parse_file(DEMO / "identity" / "bloodhound-edges.json")
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert "BloodHound GenericAll" in names
    assert "BloodHound DCSync" in names
    assert any(r["severity"] == "critical" for r in recs if r["kind"] == "finding")
    dcsync = next(r for r in recs if r["kind"] == "finding" and r["name"] == "BloodHound DCSync")
    mapped = map_finding(dcsync)
    assert mapped["include_poam"] is True
    assert "DCSync" in mapped["control_name"]
    assert "CVE-" not in mapped["recommended_fix"]
    gall = next(r for r in recs if r["kind"] == "finding" and r["name"] == "BloodHound GenericAll")
    assert map_finding(gall)["include_poam"] is True


def test_bloodhound_nodes_map() -> None:
    from shared.control_map import map_finding

    recs = identity_ad.parse_file(DEMO / "identity" / "bloodhound.json")
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert "Roastable SPN" in names
    assert "Backup Operators privileged group" in names
    assert "Unconstrained delegation" in names
    roast = next(r for r in recs if r["name"] == "Roastable SPN")
    mapped = map_finding(roast)
    assert mapped["include_poam"] is True
    assert "kerberoast" in mapped["control_name"].lower() or "service account" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_sharphound_ce_users_json(tmp_path) -> None:
    dest = tmp_path / "users.json"
    dest.write_text(
        """{"data":[{"ObjectIdentifier":"S-1-5-21-1000-2000-3000-1103",
        "Properties":{"name":"SVC-SQL@CORP.LOCAL","hasspn":true,
        "serviceprincipalnames":["MSSQLSvc/db.corp.local:1433"],
        "dontreqpreauth":true,"unconstraineddelegation":false,
        "highvalue":false},"Members":[],"Aces":[]}],
        "meta":{"type":"users","count":1,"version":6}}""",
        encoding="utf-8",
    )
    recs = identity_ad.parse_file(dest)
    assets = [r for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any(r["name"] == "SVC-SQL@CORP.LOCAL" for r in assets)
    assert any(r["name"] == "Roastable SPN" for r in findings)
    assert any(r["name"] == "AS-REP roastable account" for r in findings)
    assert not any("High-value" in r["name"] for r in findings)


def test_sharphound_ce_edges_and_aces(tmp_path) -> None:
    dest = tmp_path / "graph.json"
    dest.write_text(
        """{"data":[
        {"Source":"HELPDESK@CORP.LOCAL","Target":"DOMAIN ADMINS@CORP.LOCAL","EdgeType":"GenericAll"},
        {"ObjectIdentifier":"S-1-5-21-1000-2000-3000-512",
         "Properties":{"name":"CORP.LOCAL","highvalue":true},
         "Aces":[{"PrincipalName":"SVC-SQL@CORP.LOCAL","RightName":"DCSync"},
                 {"PrincipalName":"HELPDESK@CORP.LOCAL","RightName":"GenericRead"}]
        }
        ],"meta":{"type":"domains","count":1}}""",
        encoding="utf-8",
    )
    recs = identity_ad.parse_file(dest)
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert "BloodHound GenericAll" in names
    assert "BloodHound DCSync" in names
    assert not any("GenericRead" in n for n in names)


def test_empty_bloodhound_ce_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "empty-users.json"
    dest.write_text(
        """{"data":[],"meta":{"type":"users","count":0,"version":6}}""",
        encoding="utf-8",
    )
    recs = identity_ad.parse_file(dest)
    assert recs == []
    dest.write_text(
        """{"data":[{"ObjectIdentifier":"S-1-5-21-empty",
        "Properties":{"name":"EMPTY-GROUP@CORP.LOCAL"},
        "Members":[],"Aces":[]}],"meta":{"type":"groups","count":1}}""",
        encoding="utf-8",
    )
    recs = identity_ad.parse_file(dest)
    assert [r["kind"] for r in recs] == ["asset"]
    assert recs[0]["name"] == "EMPTY-GROUP@CORP.LOCAL"


def test_empty_in_still_loads_bloodhound(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-identity-bh"))
    (tmp_path / "empty-identity-bh" / "identity").mkdir(parents=True)
    files, demo = load_inputs("identity-ad", (".json", ".xml", ".csv"))
    assert demo is True
    names = {p.name for p in files}
    assert "bloodhound.json" in names
    assert "bloodhound-edges.json" in names


def test_identity_ad_no_ad_subprocess() -> None:
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "collectors" / "identity_ad.py").read_text(
        encoding="utf-8"
    )
    assert "import subprocess" not in src
    assert "Popen" not in src
    assert "ldap" not in src.lower()
    assert "winrm" not in src.lower()
    assert "bloodhound -" not in src
    assert "cis-cat -" not in src


def test_fleet_hosts() -> None:
    from shared.control_map import map_finding

    recs = host_wazuh.parse_file(DEMO / "wazuh" / "fleet.json")
    names = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "fleet-laptop-07" in names
    assert "fleet-build-01" in names
    offline = next(r for r in recs if r["kind"] == "finding" and "fleet-laptop-07" in r["name"])
    assert "disconnected" in offline["name"].lower() or "coverage" in offline["description"].lower()
    assert not any(r["kind"] == "finding" and "fleet-build-01" in r["name"] for r in recs)
    mapped = map_finding(offline)
    assert mapped["include_poam"] is True
    assert "coverage" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_fleet_api_disk_mdm_and_policies(tmp_path) -> None:
    from shared.control_map import map_finding

    dest = tmp_path / "hosts.json"
    dest.write_text(
        """{"data":{"hosts":[{"hostname":"mac-07","status":"online","primary_ip":"10.0.4.9",
        "disk_encryption_enabled":false,"mdm":{"enrollment_status":"Off"}},
        {"hostname":"mac-ok","status":"online","disk_encryption_enabled":true,
         "mdm":{"enrollment_status":"On (manual)"}}]},
        "policies":[{"name":"Gatekeeper enabled","response":"pass"},
                    {"name":"Full disk encryption","response":"fail","failing_host_count":1}]}""",
        encoding="utf-8",
    )
    recs = host_wazuh.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    names = [r["name"] for r in findings]
    assert any("Disk encryption" in n for n in names)
    assert any("MDM enrollment" in n for n in names)
    assert any("Full disk encryption" in n for n in names)
    assert not any("Gatekeeper" in n for n in names)
    assert not any("mac-ok" in n for n in names)
    enc = next(r for r in findings if "Disk encryption" in r["name"])
    mapped = map_finding(enc)
    assert mapped["include_poam"] is True
    assert "disk encryption" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_empty_fleet_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "empty-fleet.json"
    dest.write_text("""{"hosts":[],"policies":[]}""", encoding="utf-8")
    assert host_wazuh.parse_file(dest) == []


def test_empty_in_still_loads_fleet(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-wazuh"))
    (tmp_path / "empty-wazuh" / "wazuh").mkdir(parents=True)
    files, demo = load_inputs("host-wazuh", (".json", ".xml", ".txt", ".log", ".dat"))
    assert demo is True
    names = {p.name for p in files}
    assert "fleet.json" in names


def test_host_wazuh_no_live_agent() -> None:
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "collectors" / "host_wazuh.py").read_text(
        encoding="utf-8"
    )
    assert "import subprocess" not in src
    assert "Popen" not in src
    assert "fleetctl" not in src
    assert "osqueryi" not in src
    assert "cis-cat -" not in src


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


def test_nuclei_jsonl_maps_log4shell() -> None:
    from shared.control_map import map_finding

    recs = vuln_scan.parse_file(DEMO / "vuln" / "nuclei.jsonl")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) >= 3
    log4j = next(r for r in findings if "Log4j" in r["name"] or "44228" in r["ref_id"])
    mapped = map_finding(log4j)
    assert mapped["include_poam"] is True
    assert "Log4Shell" in mapped["control_name"] or "Log4j" in mapped["control_name"]
    assert "dropped" in mapped["recommended_fix"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_nuclei_json_wrapper_and_info_silent(tmp_path) -> None:
    dest = tmp_path / "scan.json"
    dest.write_text(
        """{"results":[
        {"template_id":"exposed-redis","info":{"name":"Redis without auth","severity":"high",
         "description":"Unauthenticated Redis"},"host":"10.0.0.40","matched_at":"10.0.0.40:6379"},
        {"template-id":"tech-detect","info":{"name":"nginx detect","severity":"info"},
         "host":"10.0.0.40"}
        ]}""",
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "Redis" in findings[0]["name"]
    assert not any("nginx" in r["name"] for r in findings)


def test_empty_nuclei_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "empty-nuclei.json"
    dest.write_text("""{"results":[]}""", encoding="utf-8")
    assert vuln_scan.parse_file(dest) == []


def test_vuln_scan_no_nuclei_subprocess() -> None:
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "collectors" / "vuln_scan.py").read_text(
        encoding="utf-8"
    )
    assert "import subprocess" not in src
    assert "Popen" not in src
    assert "nuclei -" not in src
    assert "nikto -" not in src
    assert "nessuscli scan" not in src
    assert "nessuscli --" not in src
    assert "socket.socket" not in src


def test_nikto_txt_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = vuln_scan.parse_file(DEMO / "vuln" / "nikto.txt")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "http://10.0.0.20" in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "Admin login" in findings[0]["name"]
    assert "X-Frame-Options" not in str(recs)
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "admin" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_nikto_json_and_xml(tmp_path) -> None:
    dest = tmp_path / "nikto.json"
    dest.write_text(
        """{"host":"http://10.0.0.20","vulnerabilities":[
        {"id":"000221","OSVDB":"3092","url":"/admin","msg":"Admin login page found."},
        {"id":"999957","OSVDB":"0","url":"/","msg":"The X-Frame-Options header is not present."}
        ]}""",
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "/admin" in findings[0]["description"]
    dest = tmp_path / "nikto.xml"
    dest.write_text(
        """<niktoscan><scandetails targethostname="http://10.0.0.20" targetip="10.0.0.20" targetport="80">
        <item id="000221" osvdbid="3092"><description>Admin login page found.</description><uri>/admin</uri></item>
        <item id="999957"><description>The X-Content-Type-Options header is not set.</description><uri>/</uri></item>
        </scandetails></niktoscan>""",
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert any(r["kind"] == "asset" and r["name"] == "http://10.0.0.20" for r in recs)


def test_empty_nikto_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "empty-nikto.json"
    dest.write_text("""{"host":"http://10.0.0.20","vulnerabilities":[]}""", encoding="utf-8")
    assert vuln_scan.parse_file(dest) == []
    dest = tmp_path / "empty-nikto.xml"
    dest.write_text(
        """<niktoscan><scandetails targethostname="h" targetip="10.0.0.20"></scandetails></niktoscan>""",
        encoding="utf-8",
    )
    assert vuln_scan.parse_file(dest) == []
    dest = tmp_path / "nessus-stub.txt"
    dest.write_text(
        "DEMO — not a real scanner. farm/tool-bin/lab/nessus\n"
        "<NessusClientData_v2><!-- DEMO fixture-shaped, not a scan --></NessusClientData_v2>\n",
        encoding="utf-8",
    )
    assert vuln_scan.parse_file(dest) == []


def test_nessus_xml_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = vuln_scan.parse_file(DEMO / "vuln" / "demo.nessus")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "http://10.0.0.20" in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "SMB" in findings[0]["name"]
    assert "Scan Information" not in str(recs)
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "smb" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_nessus_key_medium_rdp(tmp_path) -> None:
    dest = tmp_path / "rdp.nessus"
    dest.write_text(
        """<NessusClientData_v2><Report name="t">
        <ReportHost name="http://10.0.0.20">
        <ReportItem port="3389" svc_name="msrdp" protocol="tcp" severity="2"
         pluginID="58453" pluginName="Remote Desktop Protocol Server">
        <risk_factor>Medium</risk_factor>
        <description>RDP is reachable.</description>
        </ReportItem>
        <ReportItem port="80" svc_name="www" protocol="tcp" severity="2"
         pluginID="10107" pluginName="HTTP Server Type and Version">
        <risk_factor>Medium</risk_factor>
        <description>Banner only.</description>
        </ReportItem>
        </ReportHost></Report></NessusClientData_v2>""",
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert findings[0]["extra"].get("port") == "3389"


def test_empty_nessus_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "empty.nessus"
    dest.write_text("<NessusClientData_v2><Report name='t'></Report></NessusClientData_v2>", encoding="utf-8")
    assert vuln_scan.parse_file(dest) == []
    dest.write_text(
        """<NessusClientData_v2><Report name="t"><ReportHost name="http://10.0.0.20">
        <ReportItem port="0" severity="0" pluginID="19506" pluginName="Nessus Scan Information">
        <risk_factor>None</risk_factor></ReportItem>
        </ReportHost></Report></NessusClientData_v2>""",
        encoding="utf-8",
    )
    assert vuln_scan.parse_file(dest) == []


def test_nessus_parser_no_live() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for rel in ("collectors/vuln_scan.py", "shared/nessus.py"):
        src = (root / rel).read_text(encoding="utf-8")
        assert "import subprocess" not in src
        assert "Popen" not in src
        assert "nessuscli scan" not in src
        assert "nessuscli --" not in src
        assert "urllib.request" not in src
        assert "socket.socket" not in src


def test_empty_in_still_loads_demo_including_sarif(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in" / "vuln").mkdir(parents=True)
    files, demo = load_inputs(
        "vuln-scan", (".json", ".jsonl", ".sarif", ".txt", ".xml", ".nessus")
    )
    assert demo is True
    names = {p.name for p in files}
    assert "nuclei.jsonl" in names
    assert "demo.sarif" in names
    assert "nikto.txt" in names
    assert "demo.nessus" in names
    assert "sslscan.xml" in names


def test_sslscan_xml_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = vuln_scan.parse_file(DEMO / "vuln" / "sslscan.xml")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "TLS 1.0" in findings[0]["name"] or "TLS 1.0" in findings[0]["description"]
    assert findings[0]["assets"] == ["vpn.example.com"]
    assert not any("heartbleed" in r["name"].lower() for r in findings)
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "tls 1.0" in mapped["control_name"].lower()
    assert "live probe" in mapped["recommended_fix"].lower()
    easm_recs = easm.parse_file(DEMO / "vuln" / "sslscan.xml")
    assert any(r["kind"] == "finding" and r["assets"] == ["vpn.example.com"] for r in easm_recs)


def test_empty_sslscan_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "sslscan.xml"
    dest.write_text(
        """<?xml version="1.0"?>
        <document title="SSLScan Results">
         <ssltest host="vpn.example.com" port="443">
          <protocol type="tls" version="1.2" enabled="1"/>
          <heartbleed sslversion="TLSv1.2" vulnerable="0"/>
         </ssltest>
        </document>""",
        encoding="utf-8",
    )
    assert vuln_scan.parse_file(dest) == []
    dest.write_text("<document title='SSLScan Results'></document>", encoding="utf-8")
    assert vuln_scan.parse_file(dest) == []
    txt = tmp_path / "sslscan.txt"
    txt.write_text(
        "Testing SSL server www.example.com on port 443\n"
        "  SSL/TLS Protocols:\n"
        "TLSv1.2   enabled\n"
        "TLSv1.3   enabled\n",
        encoding="utf-8",
    )
    assert vuln_scan.parse_file(txt) == []
    assert easm.parse_file(txt) == []


def test_sslscan_text_tls10(tmp_path) -> None:
    dest = tmp_path / "report.txt"
    dest.write_text(
        "Testing SSL server vpn.example.com on port 443\n"
        "  SSL/TLS Protocols:\n"
        "SSLv2     disabled\n"
        "TLSv1.0   enabled\n"
        "TLSv1.2   enabled\n",
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "TLS 1.0" in findings[0]["name"]
    assert findings[0]["assets"] == ["vpn.example.com"]


def test_sslscan_parser_no_live() -> None:
    for rel in ("collectors/vuln_scan.py", "collectors/easm.py", "shared/sslscan.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "import subprocess" not in src
        assert "Popen" not in src
        assert "sslscan --" not in src
        assert "urllib.request" not in src
        assert "socket.socket" not in src


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
    from shared.control_map import map_finding

    recs = identity_ad.parse_file(DEMO / "identity" / "hardeningkitty.csv")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("password history" in r["name"] for r in findings)
    assert any("LM hash" in r["name"] for r in findings)
    assert not any("Guest account" in r["name"] for r in findings)
    assert {r["name"] for r in recs if r["kind"] == "asset"} == {"win-dc01"}
    blob = str(recs)
    assert " actual=5" not in blob
    hist = next(r for r in findings if "password history" in r["name"])
    mapped = map_finding(hist)
    assert mapped["include_poam"] is True
    assert "password history" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_minimal_hk_audit_csv(tmp_path) -> None:
    dest = tmp_path / "audit.csv"
    dest.write_text(
        "ID,Name,Severity,Result,RecommendedValue,TestedValue,ComputerName\n"
        "1.1,Enforce password history,High,Failed,24,5,win-hk-min\n"
        "2.3,Guest account status,Medium,Passed,Disabled,Disabled,win-hk-min\n",
        encoding="utf-8",
    )
    recs = identity_ad.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "password history" in findings[0]["name"]
    assert not any("Guest" in r["name"] for r in findings)
    assert "win-hk-min" in findings[0]["assets"]
    blob = str(recs)
    assert " actual=5" not in blob
    assert "[REDACTED]" in blob


def test_empty_in_still_loads_hk_csv(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-identity"))
    (tmp_path / "empty-identity" / "identity").mkdir(parents=True)
    files, demo = load_inputs("identity-ad", (".json", ".xml", ".csv"))
    assert demo is True
    names = {p.name for p in files}
    assert "hardeningkitty.csv" in names


def test_lynis_report() -> None:
    from collectors import host_wazuh
    from shared.control_map import map_finding

    recs = host_wazuh.parse_file(DEMO / "wazuh" / "lynis-report.txt")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("FIRE-4590" in r["name"] for r in findings)
    assert any("SSH-7408" in r["name"] for r in findings)
    assert not any("ACCT-9622" in r["name"] for r in findings)
    assert any(r["kind"] == "asset" and r["name"] == "jump-unmanaged" for r in recs)
    fw = next(r for r in findings if "FIRE-4590" in r["name"])
    mapped = map_finding(fw)
    assert mapped["include_poam"] is True
    assert "firewall" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_empty_in_still_loads_lynis_report(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-wazuh"))
    (tmp_path / "empty-wazuh" / "wazuh").mkdir(parents=True)
    files, demo = load_inputs("host-wazuh", (".json", ".xml", ".txt", ".log", ".dat"))
    assert demo is True
    names = {p.name for p in files}
    assert "lynis-report.txt" in names
    assert "osquery.json" in names


def test_maester() -> None:
    from shared.control_map import map_finding

    recs = saas_idp.parse_file(DEMO / "saas" / "maester.json")
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert any("MT.1035" in n for n in names)
    assert not any("MT.1001" in n for n in names)
    hit = next(r for r in recs if r["kind"] == "finding" and "MT.1035" in r["name"])
    mapped = map_finding(hit)
    assert mapped["include_poam"] is True
    assert "phishing-resistant" in mapped["control_name"].lower()
    assert "Graph API" in mapped["recommended_fix"] or "not a Graph" in mapped["recommended_fix"]


def test_minimal_maester_pester_json(tmp_path) -> None:
    dest = tmp_path / "maester-min.json"
    dest.write_text(
        """{
  "TenantId": "contoso.onmicrosoft.com",
  "Tests": [
    {"Id": "MT.1035", "Passed": false, "Severity": "high",
     "Description": "Privileged users should have phishing-resistant MFA"},
    {"Id": "MT.1001", "Passed": true, "Severity": "medium",
     "Description": "Security defaults documented"},
    {"Id": "MT.9999", "Result": "Skipped", "Severity": "high",
     "Description": "should not emit"}
  ]
}
""",
        encoding="utf-8",
    )
    recs = saas_idp.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "MT.1035" in findings[0]["name"]
    assert not any("MT.1001" in r["name"] or "MT.9999" in r["name"] for r in findings)


def test_empty_in_still_loads_maester(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-saas"))
    (tmp_path / "empty-saas" / "saas").mkdir(parents=True)
    files, demo = load_inputs("saas-idp", (".json", ".jsonl"))
    assert demo is True
    names = {p.name for p in files}
    assert "maester.json" in names
    assert "scuba.json" in names
    assert "okta.json" in names
    assert "scuba-wrap.json" in names


def test_graph_empty_members_does_not_invent(tmp_path) -> None:
    dest = tmp_path / "graph-empty.json"
    dest.write_text(
        """{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#directoryRoles",
  "tenant": "contoso.onmicrosoft.com",
  "directoryRoles": [{"displayName": "Global Administrator", "members": []}]
}
""",
        encoding="utf-8",
    )
    assert saas_idp.parse_file(dest) == []


def test_testssl() -> None:
    from shared.control_map import map_finding

    recs = vuln_scan.parse_file(DEMO / "vuln" / "testssl.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("heartbleed" in r["name"].lower() or "CVE-2014-0160" in str(r) for r in findings)
    assert any("TLS1" in r["name"] or "TLS 1.0" in r["description"] for r in findings)
    assert not any("secure_renego" in r["name"] for r in findings)
    hb = next(r for r in findings if "heartbleed" in r["name"].lower())
    mapped = map_finding(hb)
    assert mapped["include_poam"] is True
    assert "heartbleed" in mapped["control_name"].lower()
    assert "live probe" in mapped["recommended_fix"].lower()


def test_minimal_testssl_native_array(tmp_path) -> None:
    dest = tmp_path / "testssl-min.json"
    dest.write_text(
        """[
  {"id": "heartbleed", "severity": "HIGH", "cve": "CVE-2014-0160",
   "finding": "Heartbleed still offered on TLS", "ip": "vpn.example.com/203.0.113.9"},
  {"id": "secure_renego", "severity": "OK", "finding": "Secure Renegotiation IS supported",
   "ip": "vpn.example.com/203.0.113.9"}
]
""",
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "vpn.example.com" in findings[0]["assets"]
    from collectors import easm

    easm_recs = easm.parse_file(dest)
    easm_findings = [r for r in easm_recs if r["kind"] == "finding"]
    assert len(easm_findings) == 1
    assert easm_findings[0]["severity"] == "high"


def test_empty_in_still_loads_testssl(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-vuln"))
    (tmp_path / "empty-vuln" / "vuln").mkdir(parents=True)
    files, demo = load_inputs("vuln-scan", (".json", ".jsonl", ".sarif"))
    assert demo is True
    assert "testssl.json" in {p.name for p in files}


def test_ms_graph_directory_roles() -> None:
    recs = saas_idp.parse_file(DEMO / "saas" / "graph.json")
    assert any(r["kind"] == "finding" and "Graph" in r["name"] for r in recs)
    assert any("ga@contoso.onmicrosoft.com" in str(r.get("assets")) for r in recs)


def test_kube_bench() -> None:
    from shared.control_map import map_finding

    recs = k8s_kubescape.parse_file(DEMO / "k8s" / "kube-bench.json")
    names = [r["name"] for r in recs if r["kind"] == "finding"]
    assert any("Anonymous" in n for n in names)
    assert any("privileged" in n.lower() for n in names)
    assert not any("Token authentication" in n for n in names)
    priv = next(r for r in recs if r["kind"] == "finding" and "privileged" in r["name"].lower())
    mapped = map_finding(priv)
    assert mapped["include_poam"] is True
    assert "privileged" in mapped["control_name"].lower()
    assert "kubectl" in mapped["recommended_fix"].lower()


def test_kubescape_maps_highs() -> None:
    from shared.control_map import map_finding

    recs = k8s_kubescape.parse_file(DEMO / "k8s" / "kubescape.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert not any("Immutable" in r["name"] for r in findings)
    anon = next(r for r in findings if "Anonymous" in r["name"])
    mapped = map_finding(anon)
    assert mapped["include_poam"] is True
    assert "anonymous" in mapped["control_name"].lower()


def test_minimal_kube_bench_nested(tmp_path) -> None:
    dest = tmp_path / "kb-min.json"
    dest.write_text(
        """{
  "Controls": [{
    "id": "1",
    "tests": [{
      "results": [
        {"test_number": "1.2.1", "test_desc": "Anonymous authentication is not enabled", "status": "FAIL"},
        {"test_number": "1.2.2", "test_desc": "should stay silent", "status": "PASS"}
      ]
    }]
  }]
}
""",
        encoding="utf-8",
    )
    recs = k8s_kubescape.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "Anonymous" in findings[0]["name"]
    assert findings[0]["severity"] == "high"


def test_empty_in_still_loads_k8s(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-k8s"))
    (tmp_path / "empty-k8s" / "k8s").mkdir(parents=True)
    files, demo = load_inputs("k8s-kubescape", (".json", ".jsonl"))
    assert demo is True
    names = {p.name for p in files}
    assert "kube-bench.json" in names
    assert "kubescape.json" in names


def test_httpx_jsonl() -> None:
    from shared.control_map import map_finding

    recs = easm.parse_file(DEMO / "easm" / "httpx.jsonl")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "vpn.example.com" in assets
    assert any(r["kind"] == "finding" and "vpn.example.com" in r["assets"] for r in recs)
    vpn = next(r for r in recs if r["kind"] == "finding" and "Sensitive external" in r["name"] and "vpn.example.com" in r["assets"])
    mapped = map_finding(vpn)
    assert mapped["include_poam"] is True
    assert "perimeter" in mapped["control_name"].lower() or "hostname" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]
    admin_ui = [r for r in recs if r["kind"] == "finding" and "admin interface" in r["name"].lower()]
    assert admin_ui
    assert map_finding(admin_ui[0])["include_poam"] is True


def test_httpx_json_array_failed_silent() -> None:
    from shared.control_map import map_finding

    recs = easm.parse_file(DEMO / "easm" / "httpx.json")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "admin.example.com" in assets
    assert "vpn.example.com" not in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("admin interface" in r["name"].lower() for r in findings)
    assert not any("vpn.example.com" in (r.get("assets") or []) for r in findings)
    mapped = map_finding(next(r for r in findings if "admin" in r["name"].lower()))
    assert mapped["include_poam"] is True
    assert "CVE-" not in mapped["recommended_fix"]


def test_amass_json_array(tmp_path) -> None:
    dest = tmp_path / "amass.json"
    dest.write_text(
        """[{"name":"vpn.example.com","domain":"example.com"},
        {"name":"intranet.example.com","domain":"example.com"}]""",
        encoding="utf-8",
    )
    recs = easm.parse_file(dest)
    names = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "vpn.example.com" in names
    assert "intranet.example.com" in names


def test_empty_easm_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "empty-httpx.json"
    dest.write_text("[]", encoding="utf-8")
    assert easm.parse_file(dest) == []
    dest.write_text("""{"results":[],"hosts":[]}""", encoding="utf-8")
    assert easm.parse_file(dest) == []
    dest.write_text("""{"host":"vpn.example.com","failed":true}""", encoding="utf-8")
    assert easm.parse_file(dest) == []


def test_empty_in_still_loads_easm(tmp_path, monkeypatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-easm"))
    (tmp_path / "empty-easm" / "easm").mkdir(parents=True)
    files, demo = load_inputs("easm", (".txt", ".json", ".jsonl", ".xml"))
    assert demo is True
    names = {p.name for p in files}
    assert "httpx.jsonl" in names
    assert "httpx.json" in names
    assert "amass.jsonl" in names
    assert "ffuf.json" in names
    assert "whatweb.json" in names


def test_ffuf_json_interesting_path_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = easm.parse_file(DEMO / "easm" / "ffuf.json")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "admin.example.com" in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "/admin" in findings[0]["description"]
    assert "robots" not in findings[0]["description"].lower()
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "admin" in mapped["control_name"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_gobuster_txt_interesting_path(tmp_path) -> None:
    dest = tmp_path / "gobuster.txt"
    dest.write_text(
        "https://admin.example.com/login          (Status: 200) [Size: 1024]\n"
        "https://admin.example.com/robots.txt     (Status: 200) [Size: 40]\n"
        "https://admin.example.com/nonesuch       (Status: 404) [Size: 0]\n",
        encoding="utf-8",
    )
    recs = easm.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "/login" in findings[0]["description"]
    assert any(r["kind"] == "asset" and r["name"] == "admin.example.com" for r in recs)


def test_empty_ffuf_gobuster_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "ffuf.json"
    dest.write_text("""{"commandline":"ffuf","results":[]}""", encoding="utf-8")
    assert easm.parse_file(dest) == []
    dest = tmp_path / "gobuster.txt"
    dest.write_text("https://admin.example.com/robots.txt (Status: 200) [Size: 40]\n", encoding="utf-8")
    assert easm.parse_file(dest) == []


def test_easm_no_live_probe() -> None:
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "collectors" / "easm.py").read_text(encoding="utf-8")
    assert "import subprocess" not in src
    assert "Popen" not in src
    assert "amass enum" not in src
    assert "httpx -" not in src
    assert "subfinder -" not in src
    assert "ffuf -" not in src
    assert "gobuster dir" not in src
    assert "whatweb --" not in src
    assert "whatweb http" not in src
    assert "sslscan --" not in src
    assert "socket.socket" not in src


def test_whatweb_json_admin_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = easm.parse_file(DEMO / "easm" / "whatweb.json")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "admin.example.com" in assets
    assert "www.example.com" not in assets
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert "WhatWeb" in findings[0]["name"]
    assert findings[0]["assets"] == ["admin.example.com"]
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "admin" in mapped["control_name"].lower()
    assert "live HTTP" in mapped["recommended_fix"] or "not a live" in mapped["recommended_fix"].lower()
    assert "CVE-" not in mapped["recommended_fix"]


def test_empty_whatweb_invents_nothing(tmp_path) -> None:
    dest = tmp_path / "whatweb.json"
    dest.write_text("[]", encoding="utf-8")
    assert easm.parse_file(dest) == []
    dest.write_text(
        """[{"target":"https://www.example.com","http_status":200,
        "plugins":{"Title":{"string":["Home"]}}}]""",
        encoding="utf-8",
    )
    assert easm.parse_file(dest) == []
    dest.write_text('{"data":[]}', encoding="utf-8")
    assert easm.parse_file(dest) == []


def test_whatweb_data_wrapper(tmp_path) -> None:
    dest = tmp_path / "whatweb-wrap.json"
    dest.write_text(
        """{"data":[{"target":"https://admin.example.com/login","http_status":200,
        "plugins":{"Title":{"string":["Admin Login"]}}}]}""",
        encoding="utf-8",
    )
    recs = easm.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert findings[0]["assets"] == ["admin.example.com"]


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


def test_scuba_demo_failed_high_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = saas_idp.parse_file(DEMO / "saas" / "scuba.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    names = [r["name"] for r in findings]
    assert "Legacy authentication protocols disabled" in names
    assert "Privileged roles use PIM" in names
    assert "External sharing restricted" in names
    assert "Security defaults or CA policies" not in names
    assert all("contoso.onmicrosoft.com" in str(r.get("assets")) for r in recs)
    pim = next(r for r in findings if r["name"] == "Privileged roles use PIM")
    mapped = map_finding(pim)
    assert mapped["include_poam"] is True
    assert "global administrator" in mapped["control_name"].lower()
    assert "Graph API" in mapped["recommended_fix"] or "not a Graph" in mapped["recommended_fix"]


def test_okta_demo_admin_mfa_maps_to_poam() -> None:
    from shared.control_map import map_finding

    recs = saas_idp.parse_file(DEMO / "saas" / "okta.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert findings[0]["name"] == "Okta admin MFA gap"
    assert "example.okta.com" in findings[0]["assets"]
    assets = {r["name"] for r in recs if r["kind"] == "asset"}
    assert "example.okta.com" in assets
    assert "it-admin@example.com" in assets
    assert "jane@example.com" in assets
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "mfa" in mapped["control_name"].lower()
    assert "not a Graph or Okta API" in mapped["recommended_fix"]
    assert "CVE-" not in mapped["recommended_fix"]


def test_scuba_wrap_and_okta_data_unwrap() -> None:
    from shared.control_map import map_finding

    recs = saas_idp.parse_file(DEMO / "saas" / "scuba-wrap.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert findings[0]["name"] == "Privileged users require MFA"
    assert findings[0]["assets"] == ["contoso.onmicrosoft.com"]
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is True
    assert "mfa" in mapped["control_name"].lower()
    assert "ScubaGear" in mapped["recommended_fix"] or "Okta export" in mapped["recommended_fix"]
    assert "not a Graph or Okta API" in mapped["recommended_fix"]


def test_okta_data_wrapper(tmp_path) -> None:
    dest = tmp_path / "okta-wrap.json"
    dest.write_text(
        """{
  "data": {
    "org": "example.okta.com",
    "policies": [
      {"id": "pol-mfa", "type": "MFA_ENROLL", "name": "Admins MFA",
       "status": "INACTIVE", "description": "Okta admin MFA enrollment disabled"}
    ],
    "users": []
  }
}
""",
        encoding="utf-8",
    )
    recs = saas_idp.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert findings[0]["name"] == "Okta admin MFA gap"
    assert findings[0]["assets"] == ["example.okta.com"]


def test_empty_and_pass_only_saas_invent_nothing(tmp_path) -> None:
    empty = tmp_path / "scuba-empty.json"
    empty.write_text('{"Results": []}', encoding="utf-8")
    assert saas_idp.parse_file(empty) == []
    passed = tmp_path / "scuba-pass.json"
    passed.write_text(
        """{"Results": [{"Tenant": "contoso.onmicrosoft.com",
        "Requirement": "Security defaults", "Result": "Pass",
        "Details": "ok", "Severity": "high"}]}""",
        encoding="utf-8",
    )
    assert saas_idp.parse_file(passed) == []
    skip = tmp_path / "scuba-skip.json"
    skip.write_text(
        """{"Results": [{"Tenant": "contoso.onmicrosoft.com",
        "Requirement": "Info only", "Result": "Skip",
        "Details": "n/a", "Severity": "high"}]}""",
        encoding="utf-8",
    )
    assert saas_idp.parse_file(skip) == []
    low = tmp_path / "scuba-low.json"
    low.write_text(
        """{"Results": [{"Tenant": "contoso.onmicrosoft.com",
        "Requirement": "Low fail", "Result": "Fail",
        "Details": "noise", "Severity": "info"}]}""",
        encoding="utf-8",
    )
    assert saas_idp.parse_file(low) == []
    okta_empty = tmp_path / "okta-empty.json"
    okta_empty.write_text('{"users": [], "policies": []}', encoding="utf-8")
    assert saas_idp.parse_file(okta_empty) == []
    maester_pass = tmp_path / "maester-pass.json"
    maester_pass.write_text(
        """{"Tenant": "contoso.onmicrosoft.com",
        "TestResults": [{"Id": "MT.1", "Name": "MT.1", "Result": "Passed",
        "Severity": "high", "Description": "ok"}]}""",
        encoding="utf-8",
    )
    assert saas_idp.parse_file(maester_pass) == []


def test_scuba_jsonl_and_array(tmp_path) -> None:
    dest = tmp_path / "scuba.jsonl"
    dest.write_text(
        '{"Requirement": "Privileged users require MFA", "Result": "Fail",'
        ' "Details": "Admin MFA not enforced", "Tenant": "contoso.onmicrosoft.com",'
        ' "Severity": "high"}\n'
        '{"Requirement": "ok row", "Result": "Pass", "Tenant": "contoso.onmicrosoft.com"}\n',
        encoding="utf-8",
    )
    recs = saas_idp.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 1
    assert findings[0]["name"] == "Privileged users require MFA"
    arr = tmp_path / "scuba-array.json"
    arr.write_text(
        """[{"Requirement": "Privileged users require MFA", "Result": "Fail",
        "Details": "Admin MFA not enforced", "Tenant": "contoso.onmicrosoft.com",
        "Severity": "high"}]""",
        encoding="utf-8",
    )
    recs = saas_idp.parse_file(arr)
    assert any(r["kind"] == "finding" and r["name"] == "Privileged users require MFA" for r in recs)


def test_saas_parser_no_live() -> None:
    src = (ROOT / "collectors" / "saas_idp.py").read_text(encoding="utf-8")
    assert "import subprocess" not in src
    assert "Popen" not in src
    assert "urllib.request" not in src
    assert "requests.get" not in src
    assert "socket.socket" not in src
    assert "nessuscli scan" not in src
    assert "nessuscli --" not in src
