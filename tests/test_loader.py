from __future__ import annotations

from pathlib import Path

from collectors.grc_loader import _labels, collect_controls, dedupe_assets, dedupe_by_ref
from collectors.inventory_nmap import parse_files as parse_nmap_files
from collectors.inventory_nmap import parse_nmap_gnmap, parse_nmap_xml
from collectors.vuln_scan import parse_files as parse_vuln
from shared.io_util import load_structured
from shared.schema import (
    ASSET_TYPES,
    FINDING_STATUSES,
    asset_type_for_name,
    finding,
    is_lockfile_path,
    normalize_finding_status,
)


ROOT = Path(__file__).resolve().parents[1]


def test_labels_drop_whitespace_only() -> None:
    assert _labels({"labels": ["cloud", "  ", "", "aws", "\t"]}) == "cloud,aws"
    assert _labels({"labels": [" "]}) == ""
    assert _labels({"labels": []}) == ""
    assert _labels({}) == ""


def test_dedupe_assets_merges_same_name() -> None:
    rows = [
        {"name": "web01", "asset_type": "SP", "ref_id": "NMAP-WEB01", "labels": ["nmap"]},
        {"name": "web01", "asset_type": "SP", "ref_id": "WAZ-WEB01", "labels": ["wazuh"]},
    ]
    out = dedupe_assets(rows)
    assert len(out) == 1
    assert set(out[0]["labels"]) == {"nmap", "wazuh"}


def test_dedupe_by_ref() -> None:
    rows = [
        {"ref_id": "A", "name": "one"},
        {"ref_id": "A", "name": "dup"},
        {"ref_id": "B", "name": "two"},
    ]
    out = dedupe_by_ref(rows)
    assert [r["ref_id"] for r in out] == ["A", "B"]
    assert out[0]["name"] == "one"


def test_truncated_json_skipped() -> None:
    path = ROOT / "in" / "cloud" / "truncated.json"
    assert path.exists()
    assert load_structured(path) == []


def test_utf8_bom_cloud_json_loads() -> None:
    from collectors.cloud_prowler import parse_files

    path = ROOT / "in" / "cloud" / "bom-prowler.json"
    assert path.exists()
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), "fixture must be UTF-8 BOM JSON"
    docs = load_structured(path)
    assert docs, "BOM JSON must still load"
    assert all(isinstance(d, dict) for d in docs)
    records = parse_files([path])
    findings = [r for r in records if r.kind == "finding"]
    assert any("GUARDDUTY" in r.ref_id or "guardduty" in r.name.lower() for r in findings)


def test_normalize_finding_status_aliases() -> None:
    assert FINDING_STATUSES == frozenset({"open", "closed", "in_progress"})
    assert normalize_finding_status(None) == "open"
    assert normalize_finding_status("") == "open"
    assert normalize_finding_status("NEW") == "open"
    assert normalize_finding_status("ACTIVE") == "open"
    assert normalize_finding_status("FAIL") == "open"
    assert normalize_finding_status("RESOLVED") == "closed"
    assert normalize_finding_status("ARCHIVED") == "closed"
    assert normalize_finding_status("PASS") == "closed"
    assert normalize_finding_status("IN PROGRESS") == "in_progress"
    assert normalize_finding_status("in-progress") == "in_progress"
    assert normalize_finding_status("MANUAL") == "in_progress"
    assert normalize_finding_status("NOTIFIED") == "in_progress"
    assert normalize_finding_status("bogus-xyz") == "open"
    rec = finding(
        "CLD-",
        "X",
        "n",
        description="d",
        severity="low",
        source="t",
        status="RESOLVED",
    )
    assert rec.status == "closed"
    assert rec.to_canonical()["status"] == "closed"


def test_prowler_finding_status_lifecycle() -> None:
    from collectors.cloud_prowler import parse_files

    path = ROOT / "in" / "cloud" / "finding-status.json"
    records = parse_files([path])
    findings = {r.ref_id: r for r in records if r.kind == "finding"}
    assert findings["CLD-GUARDDUTY-NO-HIGH-SEVERITY-FINDINGS"].status == "in_progress"
    assert findings["CLD-EC2-INSTANCE-PUBLIC-IP"].status == "closed"
    assert findings["CLD-S3-BUCKET-ACL-PROHIBITED"].status == "in_progress"
    assets = {r.name for r in records if r.kind == "asset"}
    assert "i-0closed" in assets
    assert "corp-acl-bucket" in assets


def test_prowler_v4_metadata_status_nested() -> None:
    from collectors.cloud_prowler import parse_files

    path = ROOT / "fixtures" / "demo" / "cloud" / "prowler_v4.json"
    records = parse_files([path])
    findings = [r for r in records if r.kind == "finding"]
    assert findings
    assert any("IMDS" in r.name.upper() or "IMDSV1" in r.ref_id for r in findings)
    assets = [r.name for r in records if r.kind == "asset"]
    assert "i-0cafe" in assets


def test_asff_prowler_parses() -> None:
    from collectors.cloud_prowler import parse_files

    path = ROOT / "fixtures" / "demo" / "cloud" / "asff.json"
    records = parse_files([path])
    findings = [r for r in records if r.kind == "finding"]
    assert findings
    assert any("snapshot" in r.name.lower() or "ebs" in r.ref_id.lower() for r in findings)


def test_prowler_csv_check_id_status_severity() -> None:
    from collectors.cloud_prowler import csv_row_to_item, parse_files, parse_prowler_csv

    mapped = csv_row_to_item(
        {
            "CHECK_ID": "s3_bucket_object_lock_enabled",
            "STATUS": "FAIL",
            "SEVERITY": "high",
            "RESOURCE_ID": "corp-lock-bucket",
        }
    )
    assert mapped["CheckID"] == "s3_bucket_object_lock_enabled"
    assert mapped["Status"] == "FAIL"
    assert mapped["Severity"] == "high"
    path = ROOT / "fixtures" / "demo" / "cloud" / "prowler.csv"
    records = parse_prowler_csv(path)
    findings = {r.ref_id: r for r in records if r.kind == "finding"}
    assets = {r.name for r in records if r.kind == "asset"}
    assert "CLD-S3-BUCKET-OBJECT-LOCK-ENABLED" in findings
    assert findings["CLD-S3-BUCKET-OBJECT-LOCK-ENABLED"].severity == "high"
    assert "corp-lock-bucket" in assets
    assert "CLD-IAM-PASSWORD-POLICY-MINIMUM-LENGTH-14" in findings
    assert findings["CLD-IAM-PASSWORD-POLICY-MINIMUM-LENGTH-14"].severity == "medium"
    assert "password-policy" in assets
    assert "CLD-EC2-INSTANCE-MANAGED-BY-SSM" not in findings
    assert "i-0ssm" not in assets
    routed = parse_files([ROOT / "in" / "cloud" / "prowler.csv"])
    refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "CLD-S3-BUCKET-OBJECT-LOCK-ENABLED" in refs
    assert "CLD-IAM-PASSWORD-POLICY-MINIMUM-LENGTH-14" in refs
    assert "CLD-EC2-INSTANCE-MANAGED-BY-SSM" not in refs


def test_prowler_checkstatus_when_status_empty() -> None:
    from collectors.cloud_prowler import (
        _prowler_status,
        csv_row_to_item,
        parse_files,
        parse_prowler_item,
    )

    assert _prowler_status({"Status": "  ", "CheckStatus": "FAIL"}) == ("FAIL", "CheckStatus")
    assert _prowler_status({"check_status": "FAIL"}) == ("FAIL", "check_status")
    assert _prowler_status({"Status": "PASS", "CheckStatus": "FAIL"}) == ("PASS", "Status")
    mapped = csv_row_to_item(
        {
            "CHECK_ID": "kms_cmk_rotation_enabled",
            "CHECK_STATUS": "FAIL",
            "SEVERITY": "critical",
            "RESOURCE_NAME": "kms-unrotated-key",
        }
    )
    assert mapped["Status"] == "FAIL"
    recs = parse_prowler_item(
        {
            "CheckID": "s3_bucket_default_encryption_kms",
            "CheckTitle": "Ensure S3 bucket default encryption uses KMS",
            "Status": "  ",
            "CheckStatus": "FAIL",
            "Severity": "high",
            "ResourceName": "corp-audit-plain",
            "ResourceType": "AwsS3Bucket",
        }
    )
    findings = [r for r in recs if r.kind == "finding"]
    assert findings and findings[0].ref_id == "CLD-S3-BUCKET-DEFAULT-ENCRYPTION-KMS"
    assert findings[0].severity == "high"
    assert "checkstatus" in findings[0].labels
    passed = parse_prowler_item(
        {
            "CheckID": "ec2_ebs_volume_encryption",
            "CheckStatus": "PASS",
            "Severity": "medium",
            "ResourceName": "vol-0skipenc",
        }
    )
    assert not any(r.kind == "finding" for r in passed)
    routed = parse_files([ROOT / "in" / "cloud" / "prowler-checkstatus.json"])
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    names = {r.name for r in routed if r.kind == "asset"}
    assert "corp-audit-plain" in names
    assert "kms-unrotated-key" in names
    assert "CLD-S3-BUCKET-DEFAULT-ENCRYPTION-KMS" in refs
    assert refs["CLD-S3-BUCKET-DEFAULT-ENCRYPTION-KMS"].severity == "high"
    assert "checkstatus" in refs["CLD-S3-BUCKET-DEFAULT-ENCRYPTION-KMS"].labels
    assert "CLD-KMS-CMK-ROTATION-ENABLED" in refs
    assert refs["CLD-KMS-CMK-ROTATION-ENABLED"].severity == "critical"
    assert "CLD-EC2-EBS-VOLUME-ENCRYPTION" not in refs


def test_wazuh_sca_failed_checks() -> None:
    from collectors.host_wazuh import parse_files as parse_wazuh
    from collectors.host_wazuh import parse_sca
    from shared.io_util import load_structured

    path = ROOT / "fixtures" / "demo" / "wazuh" / "sca.json"
    docs = load_structured(path)
    records = parse_sca(docs[0])
    findings = [r for r in records if r.kind == "finding"]
    names = [r.name.lower() for r in findings]
    assert findings
    assert any("guest" in n for n in names)
    assert any("firewall" in n for n in names)
    assert any("anonymous" in n for n in names)
    assert all("password history" not in n for n in names)
    assert all(r.related_assets and "srv-finance" in r.related_assets for r in findings)
    routed = parse_wazuh([ROOT / "in" / "wazuh" / "sca.json"])
    assert any(r.kind == "finding" and "SCA" in r.ref_id for r in routed)


def test_wazuh_alerts_rule_level() -> None:
    from collectors.host_wazuh import (
        _rule_level_severity,
        parse_doc,
        parse_files as parse_wazuh,
    )
    from shared.io_util import load_structured

    assert _rule_level_severity(12) == "critical"
    assert _rule_level_severity("10") == "high"
    assert _rule_level_severity(7) == "medium"
    assert _rule_level_severity(2) == "info"
    path = ROOT / "fixtures" / "demo" / "wazuh" / "alerts.json"
    records = parse_doc(load_structured(path)[0])
    assets = {r.name for r in records if r.kind == "asset"}
    assert "vpn-gw" in assets
    assert "cfg-bastion" in assets
    findings = [r for r in records if r.kind == "finding"]
    by_ref = {r.ref_id: r for r in findings}
    assert "WAZ-ALERT-5712" in by_ref
    assert by_ref["WAZ-ALERT-5712"].severity == "high"
    assert by_ref["WAZ-ALERT-5712"].related_assets == ["vpn-gw"]
    assert "203.0.113.9" in by_ref["WAZ-ALERT-5712"].description
    assert "WAZ-ALERT-550" in by_ref
    assert by_ref["WAZ-ALERT-550"].severity == "critical"
    assert "WAZ-ALERT-1002" not in by_ref
    assert not any(r.ref_id.endswith("1002") for r in findings)
    routed = parse_wazuh([ROOT / "in" / "wazuh" / "alerts.json"])
    refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "WAZ-ALERT-5712" in refs
    assert "WAZ-ALERT-550" in refs
    assert "WAZ-ALERT-1002" not in refs


def test_okta_users_credentials_provider_mfa() -> None:
    from collectors.saas_idp import (
        _okta_has_mfa,
        _okta_provider_type,
        parse_files as parse_saas,
        parse_okta_users,
    )
    from shared.io_util import load_structured

    password_only = {
        "profile": {"login": "okta-appadmin@contoso.com"},
        "credentials": {"provider": {"type": "OKTA"}},
    }
    assert _okta_provider_type(password_only) == "OKTA"
    assert _okta_has_mfa(password_only) is False
    totp = {
        "profile": {"login": "okta-analyst@contoso.com"},
        "credentials": {"provider": {"type": "OKTA"}},
        "factors": [{"factorType": "token:software:totp", "status": "ACTIVE"}],
    }
    assert _okta_has_mfa(totp) is True
    federated = {
        "profile": {"login": "okta-federated@contoso.com"},
        "credentials": {"provider": {"type": "FEDERATION"}},
    }
    assert _okta_has_mfa(federated) is True
    path = ROOT / "fixtures" / "demo" / "saas" / "okta-users.json"
    records = parse_okta_users(load_structured(path))
    assets = {r.name: r for r in records if r.kind == "asset"}
    assert "okta-appadmin@contoso.com" in assets
    assert assets["okta-appadmin@contoso.com"].asset_type == "PR"
    assert "okta-contractor@contoso.com" in assets
    assert assets["okta-contractor@contoso.com"].asset_type == "SP"
    findings = {r.ref_id: r for r in records if r.kind == "finding"}
    assert "SAAS-OKTA-MFA-OKTA-APPADMIN-CONTOSO-COM" in findings
    assert findings["SAAS-OKTA-MFA-OKTA-APPADMIN-CONTOSO-COM"].severity == "critical"
    assert "SAAS-OKTA-MFA-OKTA-CONTRACTOR-CONTOSO-COM" in findings
    assert findings["SAAS-OKTA-MFA-OKTA-CONTRACTOR-CONTOSO-COM"].severity == "high"
    assert "SAAS-OKTA-MFA-OKTA-ANALYST-CONTOSO-COM" not in findings
    assert "SAAS-OKTA-MFA-OKTA-FEDERATED-CONTOSO-COM" not in findings
    routed = parse_saas([ROOT / "in" / "saas" / "okta-users.json"])
    refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "SAAS-OKTA-MFA-OKTA-APPADMIN-CONTOSO-COM" in refs
    assert "SAAS-OKTA-MFA-OKTA-CONTRACTOR-CONTOSO-COM" in refs
    assert "SAAS-OKTA-MFA-OKTA-ANALYST-CONTOSO-COM" not in refs


def test_graph_user_registration_details_mfa() -> None:
    from collectors.saas_idp import (
        _graph_mfa_registered,
        _is_graph_registration,
        parse_files as parse_saas,
        parse_graph_registration,
    )
    from shared.io_util import load_structured

    gap = {
        "userPrincipalName": "ga-breakglass@litware.onmicrosoft.com",
        "isAdmin": True,
        "isMfaRegistered": False,
        "methodsRegistered": [],
    }
    assert _is_graph_registration(gap) is True
    assert _graph_mfa_registered(gap) is False
    enrolled = {
        "userPrincipalName": "analyst@litware.onmicrosoft.com",
        "isAdmin": False,
        "isMfaRegistered": True,
        "methodsRegistered": ["microsoftAuthenticatorPush"],
    }
    assert _graph_mfa_registered(enrolled) is True
    methods_only = {
        "userPrincipalName": "hello@litware.onmicrosoft.com",
        "methodsRegistered": ["windowsHelloForBusiness"],
    }
    assert _is_graph_registration(methods_only) is True
    assert _graph_mfa_registered(methods_only) is True
    docs = load_structured(ROOT / "fixtures" / "demo" / "saas" / "graph-registration.json")
    users = docs[0].get("value") if docs and isinstance(docs[0], dict) else []
    records = parse_graph_registration(users)
    assets = {r.name: r for r in records if r.kind == "asset"}
    assert "litware.onmicrosoft.com" in assets
    assert assets["litware.onmicrosoft.com"].asset_type == "PR"
    assert "ga-breakglass@litware.onmicrosoft.com" in assets
    assert assets["ga-breakglass@litware.onmicrosoft.com"].asset_type == "PR"
    assert "vendor@litware.onmicrosoft.com" in assets
    assert assets["vendor@litware.onmicrosoft.com"].asset_type == "SP"
    assert "analyst@litware.onmicrosoft.com" in assets
    assert "helpdesk@litware.onmicrosoft.com" in assets
    assert not any("guest.user_ext" in n for n in assets)
    findings = {r.ref_id: r for r in records if r.kind == "finding"}
    assert "SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM" in findings
    assert findings["SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM"].severity == "critical"
    assert "SAAS-GRAPH-MFA-VENDOR-LITWARE-ONMICROSOFT-COM" in findings
    assert findings["SAAS-GRAPH-MFA-VENDOR-LITWARE-ONMICROSOFT-COM"].severity == "high"
    assert "SAAS-GRAPH-MFA-ANALYST-LITWARE-ONMICROSOFT-COM" not in findings
    assert "SAAS-GRAPH-MFA-HELPDESK-LITWARE-ONMICROSOFT-COM" not in findings
    assert not any("GUEST" in rid for rid in findings)
    routed = parse_saas([ROOT / "in" / "saas" / "graph-registration.json"])
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    names = {r.name for r in routed if r.kind == "asset"}
    assert "litware.onmicrosoft.com" in names
    assert "SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM" in refs
    assert refs["SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM"].severity == "critical"
    assert "graph" in refs["SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM"].labels
    assert "SAAS-GRAPH-MFA-VENDOR-LITWARE-ONMICROSOFT-COM" in refs
    assert "SAAS-GRAPH-MFA-ANALYST-LITWARE-ONMICROSOFT-COM" not in refs
    assert "SAAS-GRAPH-MFA-HELPDESK-LITWARE-ONMICROSOFT-COM" not in refs
    assert not any("GUEST" in rid for rid in refs)


def test_wazuh_disconnected_capital_d() -> None:
    from collectors.host_wazuh import _agent_status, parse_doc, parse_files as parse_wazuh
    from shared.io_util import load_structured

    assert _agent_status({"status": "Disconnected"}) == "disconnected"
    assert _agent_status({"status": "Never connected"}) == "never_connected"
    assert _agent_status({"connection_status": "Disconnected"}) == "disconnected"
    path = ROOT / "in" / "wazuh" / "agents_disconnected.json"
    raw = path.read_text(encoding="utf-8")
    assert '"Disconnected"' in raw
    docs = load_structured(path)
    records = parse_doc(docs[0])
    assets = [r for r in records if r.kind == "asset"]
    findings = [r for r in records if r.kind == "finding"]
    assert any(r.name == "jump-legacy" for r in assets)
    disc = [r for r in findings if r.ref_id == "WAZ-DISC-JUMP-LEGACY"]
    assert disc and disc[0].severity == "high"
    assert "disconnected" in disc[0].labels
    jump = next(r for r in assets if r.name == "jump-legacy")
    assert jump.extra.get("status") == "disconnected"
    routed = parse_wazuh([path])
    assert any(r.kind == "finding" and r.ref_id == "WAZ-DISC-JUMP-LEGACY" for r in routed)


def test_osquery_listening_port() -> None:
    from collectors.host_wazuh import parse_osquery
    from shared.io_util import load_structured

    path = ROOT / "fixtures" / "demo" / "wazuh" / "osquery.json"
    docs = load_structured(path)
    records = parse_osquery(docs[0])
    assert any(r.kind == "finding" and "telnet" in r.name.lower() for r in records)


def test_osquery_list_wrapper_rows() -> None:
    from collectors.host_wazuh import _is_osquery, parse_files as parse_wazuh, parse_osquery
    from shared.io_util import load_structured

    wrapped = {
        "osquery": [
            {
                "hostIdentifier": "nas-legacy.corp.local",
                "name": "listening_ports",
                "columns": {"port": "445", "address": "0.0.0.0"},
            }
        ]
    }
    assert _is_osquery(wrapped) is True
    recs = parse_osquery(wrapped)
    assert any(r.kind == "finding" and r.ref_id == "WAZ-OSQ-NAS-LEGACY-CORP-LOCAL-445" for r in recs)
    raw = [
        {"hostIdentifier": "modem-legacy.corp.local", "port": "23", "address": "0.0.0.0", "name": "telnetd"},
        {"hostIdentifier": "helper-ssh.corp.local", "port": "22", "address": "0.0.0.0", "name": "sshd"},
    ]
    assert _is_osquery(raw) is True
    listed = parse_osquery(raw)
    refs = {r.ref_id: r for r in listed if r.kind == "finding"}
    assert "WAZ-OSQ-MODEM-LEGACY-CORP-LOCAL-23" in refs
    assert refs["WAZ-OSQ-MODEM-LEGACY-CORP-LOCAL-23"].severity == "high"
    assert not any("HELPER-SSH" in r.ref_id for r in listed if r.kind == "finding")
    path = ROOT / "in" / "wazuh" / "osquery_list.json"
    routed = parse_wazuh([path])
    names = {r.name for r in routed if r.kind == "asset"}
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    assert "nas-legacy.corp.local" in names
    assert "modem-legacy.corp.local" in names
    assert "helper-ssh.corp.local" in names
    assert refs["WAZ-OSQ-NAS-LEGACY-CORP-LOCAL-445"].severity == "high"
    assert refs["WAZ-OSQ-MODEM-LEGACY-CORP-LOCAL-23"].severity == "high"
    assert "WAZ-OSQ-HELPER-SSH-CORP-LOCAL-22" not in refs
    docs = load_structured(ROOT / "fixtures" / "demo" / "wazuh" / "osquery_list.json")
    assert _is_osquery(docs[0]) is True


def test_osquery_listening_ports_nested_columns() -> None:
    from collectors.host_wazuh import parse_files as parse_wazuh
    from collectors.host_wazuh import parse_osquery
    from shared.io_util import load_structured

    path = ROOT / "fixtures" / "demo" / "wazuh" / "osquery_columns.jsonl"
    docs = load_structured(path)
    assert docs and all(isinstance(d.get("columns"), dict) for d in docs)
    records: list = []
    for doc in docs:
        records.extend(parse_osquery(doc))
    assets = {r.name for r in records if r.kind == "asset"}
    assert "smb-legacy.corp.local" in assets
    assert "jump-rdp.corp.local" in assets
    smb = [r for r in records if r.kind == "finding" and r.ref_id == "WAZ-OSQ-SMB-LEGACY-CORP-LOCAL-445"]
    assert smb and smb[0].severity == "high"
    rdp = [r for r in records if r.kind == "finding" and "3389" in r.ref_id]
    assert rdp and rdp[0].severity == "medium"
    packed = parse_osquery(
        {
            "name": "listening_ports",
            "rows": [
                {
                    "host_identifier": "nested-row.corp.local",
                    "columns": {"port": "23", "name": "telnetd", "address": "0.0.0.0"},
                }
            ],
        }
    )
    assert any(r.kind == "finding" and r.severity == "high" and "nested-row.corp.local" in r.related_assets for r in packed)
    routed = parse_wazuh([ROOT / "in" / "wazuh" / "osquery_columns.jsonl"])
    assert any(r.kind == "finding" and r.ref_id == "WAZ-OSQ-SMB-LEGACY-CORP-LOCAL-445" for r in routed)


def test_amass_json_names_array() -> None:
    from collectors.easm import _amass_name_lists, parse_amass_name_lists, parse_files as parse_easm

    blob = {
        "names": ["vpn.backup.example-corp.com", "intranet.example-corp.com", ""],
        "domains": [{"fqdn": "staging-old.example-corp.com"}],
    }
    assert _amass_name_lists(blob) is True
    recs = parse_amass_name_lists(blob)
    names = {r.name for r in recs if r.kind == "asset"}
    assert "vpn.backup.example-corp.com" in names
    assert "intranet.example-corp.com" in names
    assert "staging-old.example-corp.com" in names
    findings = [r for r in recs if r.kind == "finding"]
    assert any(r.ref_id == "EASM-AMASS-VPN-BACKUP-EXAMPLE-CORP-COM" for r in findings)
    assert all("exposed" not in r.labels for r in findings)
    assert all("enum" in r.labels for r in findings)
    routed = parse_easm([ROOT / "in" / "easm" / "amass-names.json"])
    names = {r.name for r in routed if r.kind == "asset"}
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    assert "vpn.backup.example-corp.com" in names
    assert "admin-portal.example-corp.com" in names
    assert "intranet.example-corp.com" in names
    assert "www.example-corp.com" in names
    assert "EASM-AMASS-VPN-BACKUP-EXAMPLE-CORP-COM" in refs
    assert refs["EASM-AMASS-VPN-BACKUP-EXAMPLE-CORP-COM"].severity == "medium"
    assert "EASM-AMASS-ADMIN-PORTAL-EXAMPLE-CORP-COM" in refs
    assert "exposed" not in refs["EASM-AMASS-VPN-BACKUP-EXAMPLE-CORP-COM"].labels
    assert not any("INTRANET" in rid for rid in refs)


def test_amass_json_name_fqdn_objects() -> None:
    from collectors.easm import parse_amass_json_item, parse_files as parse_easm
    from shared.io_util import load_structured

    recs = parse_amass_json_item(
        {"name": "sharepoint-old.example-corp.com", "domain": "example-corp.com", "tag": "cert"}
    )
    assert any(r.kind == "asset" and r.name == "sharepoint-old.example-corp.com" for r in recs)
    assert not any(r.kind == "finding" for r in recs)
    fqdn = parse_amass_json_item({"fqdn": "remote.example-corp.com", "domain": "example-corp.com"})
    assert any(r.kind == "asset" and r.name == "remote.example-corp.com" for r in fqdn)
    vpn = parse_amass_json_item(
        {"name": "admin-vpn.example-corp.com", "addresses": [{"ip": "203.0.113.10"}]}
    )
    findings = [r for r in vpn if r.kind == "finding"]
    assert findings and all("amass" in r.labels and "enum" in r.labels for r in findings)
    assert all("exposed" not in r.labels for r in findings)
    path = ROOT / "in" / "easm" / "amass.jsonl"
    docs = load_structured(path)
    assert docs and any("name" in d or "fqdn" in d for d in docs)
    routed = parse_easm([path])
    names = {r.name for r in routed if r.kind == "asset"}
    assert "sharepoint-old.example-corp.com" in names
    assert "remote.example-corp.com" in names
    assert "admin-vpn.example-corp.com" in names
    assert not any(r.kind == "finding" and "exposed" in r.labels for r in routed)


def test_subfinder_string_list() -> None:
    from collectors.easm import parse_files

    path = ROOT / "fixtures" / "demo" / "easm" / "subfinder.json"
    records = parse_files([path])
    names = [r.name for r in records if r.kind == "asset"]
    assert "files-old.example-corp.com" in names


def test_subfinder_jsonl_host_objects() -> None:
    from collectors.easm import parse_files as parse_easm

    path = ROOT / "in" / "easm" / "subfinder.jsonl"
    records = parse_easm([path])
    names = {r.name for r in records if r.kind == "asset"}
    assert "git.example-corp.com" in names
    assert "admin-sso.example-corp.com" in names
    assert "citrix.example-corp.com" in names
    findings = [r for r in records if r.kind == "finding"]
    sso = [
        r
        for r in findings
        if "admin-sso.example-corp.com" in (r.related_assets or [])
    ]
    assert sso
    assert all("subfinder" in r.labels for r in sso)
    assert all("exposed" not in r.labels for r in sso)
    assert all(r.severity == "medium" for r in sso)
    assert not any(r.kind == "finding" and "git.example-corp.com" in (r.related_assets or []) for r in records)


def test_easm_httpx_input_when_host_empty() -> None:
    from collectors.easm import _httpx_raw_target, normalize_host, parse_files, parse_httpx_item

    empty_host = {
        "host": "",
        "input": "https://admin-confluence.example-corp.com:443/login",
        "status_code": 200,
        "title": "Confluence",
    }
    assert not empty_host.get("host")
    assert _httpx_raw_target(empty_host) == "https://admin-confluence.example-corp.com:443/login"
    assert normalize_host(_httpx_raw_target(empty_host)) == "admin-confluence.example-corp.com"
    recs = parse_httpx_item(empty_host)
    assets = [r for r in recs if r.kind == "asset"]
    findings = [r for r in recs if r.kind == "finding"]
    assert assets and assets[0].name == "admin-confluence.example-corp.com"
    assert "httpx-input" in assets[0].labels
    assert not assets[0].name.lower().startswith("http")
    assert findings and findings[0].severity == "high"
    assert findings[0].related_assets == ["admin-confluence.example-corp.com"]
    assert "httpx-input" in findings[0].labels
    spaced = parse_httpx_item(
        {"host": "   ", "input": "https://owa-legacy.example-corp.com", "status_code": 401, "title": "OWA"}
    )
    assert [r.name for r in spaced if r.kind == "asset"] == ["owa-legacy.example-corp.com"]
    listed = parse_httpx_item({"host": [], "input": ["https://fileshare.example-corp.com/dav"], "status_code": 200})
    assert [r.name for r in listed if r.kind == "asset"] == ["fileshare.example-corp.com"]
    blank = parse_httpx_item({"host": "", "input": "", "url": "", "status_code": 200})
    assert blank == []
    path = ROOT / "in" / "easm" / "httpx-input.jsonl"
    routed = parse_files([path])
    names = {r.name for r in routed if r.kind == "asset"}
    assert "admin-confluence.example-corp.com" in names
    assert "owa-legacy.example-corp.com" in names
    assert "fileshare.example-corp.com" in names
    assert "unknown-host" not in names
    assert not any(str(n).lower().startswith(("http://", "https://")) for n in names)
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    assert "EASM-ADMIN-CONFLUENCE-EXAMPLE-CORP-COM" in refs
    assert refs["EASM-ADMIN-CONFLUENCE-EXAMPLE-CORP-COM"].severity == "high"
    assert "exposed" in refs["EASM-ADMIN-CONFLUENCE-EXAMPLE-CORP-COM"].labels


def test_easm_httpx_url_only_strings() -> None:
    from collectors.easm import normalize_host, parse_files, parse_httpx_item

    assert normalize_host("https://test.example-corp.com:8443/healthz") == "test.example-corp.com"
    assert normalize_host("https://portal-legacy.example-corp.com/login") == "portal-legacy.example-corp.com"
    assert normalize_host("https://alice:secret@vpn.example-corp.com/x") == "vpn.example-corp.com"

    recs = parse_httpx_item("https://test.example-corp.com:8443/healthz")
    assets = [r for r in recs if r.kind == "asset"]
    findings = [r for r in recs if r.kind == "finding"]
    assert assets and assets[0].name == "test.example-corp.com"
    assert assets[0].asset_type == "SP"
    assert findings and findings[0].severity == "medium"
    assert "exposed" in findings[0].labels
    assert findings[0].related_assets == ["test.example-corp.com"]
    blob = " ".join(f"{r.name} {r.description}" for r in recs)
    assert "https://" not in blob
    assert "secret" not in blob

    recs2 = parse_httpx_item({"url": "https://portal-legacy.example-corp.com/login"})
    assert [r.name for r in recs2 if r.kind == "asset"] == ["portal-legacy.example-corp.com"]
    assert not any(r.kind == "finding" for r in recs2)

    path = ROOT / "in" / "easm" / "httpx-urls.txt"
    routed = parse_files([path])
    names = {r.name for r in routed if r.kind == "asset"}
    assert "test.example-corp.com" in names
    assert "portal-legacy.example-corp.com" in names
    assert not any(str(n).lower().startswith(("http://", "https://")) for n in names)
    exposed = [
        r
        for r in routed
        if r.kind == "finding" and "test.example-corp.com" in (r.related_assets or [])
    ]
    assert len(exposed) == 1
    assert "exposed" in exposed[0].labels


def test_easm_dedupe_findings_by_hostname_kind() -> None:
    from collectors.easm import parse_files as parse_easm

    files = [
        ROOT / "in" / "easm" / "amass.txt",
        ROOT / "in" / "easm" / "httpx.jsonl",
        ROOT / "in" / "easm" / "subfinder.json",
    ]
    records = parse_easm(files)
    findings = [r for r in records if r.kind == "finding"]
    keys: list[tuple[str, str]] = []
    for rec in findings:
        host = str((rec.related_assets or [rec.name])[0]).lower().rstrip(".")
        kind = "exposed" if "exposed" in rec.labels else "enum"
        keys.append((host, kind))
    assert len(keys) == len(set(keys)), f"duplicate easm findings: {keys}"
    assert keys.count(("vpn.example-corp.com", "enum")) == 1
    assert keys.count(("vpn.example-corp.com", "exposed")) == 1
    vpn_enum = next(r for r in findings if "vpn.example-corp.com" in (r.related_assets or []) and "exposed" not in r.labels)
    assert "enum" in vpn_enum.labels
    assert "subfinder" in vpn_enum.labels


def test_scuba_fail_results() -> None:
    from collectors.identity_ad import parse_files

    path = ROOT / "fixtures" / "demo" / "identity" / "scubagear.json"
    records = parse_files([path])
    findings = [r for r in records if r.kind == "finding"]
    assert findings
    assert any("pim" in r.name.lower() for r in findings)


def test_scuba_relativepath_requirement_id_fallback() -> None:
    from collectors.identity_ad import (
        _scuba_id_from_relative_path,
        _scuba_requirement_id,
        parse_files as parse_identity,
        parse_scuba,
    )
    from shared.io_util import load_structured

    assert (
        _scuba_id_from_relative_path("baselines/teams.md#ms.teams.2.1v1")
        == "ms.teams.2.1v1"
    )
    assert (
        _scuba_id_from_relative_path(r"baselines\defender.md#MS.DEFENDER.1.4v1")
        == "MS.DEFENDER.1.4v1"
    )
    rid, from_rel = _scuba_requirement_id(
        {"CheckID": "", "RelativePath": "baselines/teams.md#ms.teams.2.1v1", "Requirement": "chat"}
    )
    assert rid == "ms.teams.2.1v1"
    assert from_rel is True
    check_first, from_rel_check = _scuba_requirement_id(
        {"CheckID": "MS.AAD.7.4v1", "RelativePath": "baselines/aad.md#ms.aad.1.1v1"}
    )
    assert check_first == "MS.AAD.7.4v1"
    assert from_rel_check is False
    path = ROOT / "fixtures" / "demo" / "identity" / "scubagear_relativepath.json"
    records = parse_scuba(load_structured(path)[0])
    refs = {r.ref_id: r for r in records if r.kind == "finding"}
    assert "ID-SCUBA-MS-TEAMS-2-1V1" in refs
    teams = refs["ID-SCUBA-MS-TEAMS-2-1V1"]
    assert teams.severity == "high"
    assert "relativepath" in teams.labels
    assert "ID-SCUBA-MS-DEFENDER-1-4V1" in refs
    assert refs["ID-SCUBA-MS-DEFENDER-1-4V1"].severity == "high"
    assert "ID-SCUBA-MS-SHAREPOINT-1-1V1" not in refs
    assets = {r.name for r in records if r.kind == "asset"}
    assert any("fabrikam.onmicrosoft.com" in n for n in assets)
    routed = parse_identity([ROOT / "in" / "identity" / "scubagear_relativepath.json"])
    routed_refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "ID-SCUBA-MS-TEAMS-2-1V1" in routed_refs
    assert "ID-SCUBA-MS-DEFENDER-1-4V1" in routed_refs
    assert "ID-SCUBA-MS-SHAREPOINT-1-1V1" not in routed_refs


def test_scuba_failed_array_not_only_results() -> None:
    from collectors.identity_ad import parse_files as parse_identity
    from collectors.identity_ad import parse_scuba
    from shared.io_util import load_structured

    path = ROOT / "fixtures" / "demo" / "identity" / "scubagear_failed.json"
    docs = load_structured(path)
    records = parse_scuba(docs[0])
    findings = [r for r in records if r.kind == "finding"]
    refs = {r.ref_id for r in findings}
    assert "ID-SCUBA-MS-EXO-4-1V1" in refs
    exo = next(r for r in findings if r.ref_id == "ID-SCUBA-MS-EXO-4-1V1")
    assert exo.severity == "high"
    assert "failed-list" in exo.labels
    assert not any("MS.EXO.1.1v1" in r.ref_id for r in findings)
    assets = {r.name for r in records if r.kind == "asset"}
    assert any("EXO" in n for n in assets)
    routed = parse_identity([ROOT / "in" / "identity" / "scubagear_failed.json"])
    assert any(r.kind == "finding" and r.ref_id == "ID-SCUBA-MS-EXO-4-1V1" for r in routed)


def test_gitleaks_fingerprint_rule_when_ruleid_empty() -> None:
    from collectors.code_secrets import _gitleaks_rule, parse_files as parse_code, parse_gitleaks

    assert (
        _gitleaks_rule({"Fingerprint": "ops/pager.env:slack-bot-token:8", "File": "ops/pager.env"})
        == "slack-bot-token"
    )
    assert _gitleaks_rule({"RuleID": "", "DetectorName": "private-key"}) == "private-key"
    assert (
        _gitleaks_rule(
            {"RuleID": "github-pat", "Fingerprint": "ci/token.env:generic-api-key:2"}
        )
        == "github-pat"
    )
    win = _gitleaks_rule({"Fingerprint": r"C:\repo\file.env:generic-api-key:12"})
    assert win == "generic-api-key"
    recs = parse_gitleaks(
        [
            {
                "File": "ops/pager.env",
                "Fingerprint": "ops/pager.env:slack-bot-token:8",
                "Description": "Slack bot token",
                "Secret": "xoxb-exampleExampleExample",
            }
        ]
    )
    findings = [r for r in recs if r.kind == "finding"]
    assert findings and findings[0].ref_id == "CODE-SLACK-BOT-TOKEN-OPS-PAGER-ENV"
    assert findings[0].severity == "high"
    assert "secret" not in findings[0].ref_id.lower() or "slack" in findings[0].ref_id.lower()
    path = ROOT / "in" / "code" / "gitleaks-fingerprint.json"
    routed = parse_code([path])
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    assert "CODE-SLACK-BOT-TOKEN-OPS-PAGER-ENV" in refs
    assert refs["CODE-SLACK-BOT-TOKEN-OPS-PAGER-ENV"].severity == "high"
    assert "CODE-PRIVATE-KEY-CERTS-LEGACY-PEM" in refs
    assert "CODE-SECRET-OPS-PAGER-ENV" not in refs
    blob = " ".join(f"{r.description} {r.extra}" for r in routed)
    assert "xoxb-exampleExampleExample" not in blob
    assert "BEGIN RSA PRIVATE KEY" not in blob


def test_gitleaks_empty_file_uses_source() -> None:
    from collectors.code_secrets import _gitleaks_path, parse_files as parse_code, parse_gitleaks

    assert _gitleaks_path({"File": "  ", "Source": "terraform/prod.tfvars"}) == (
        "terraform/prod.tfvars",
        True,
    )
    assert _gitleaks_path({"Source": "mobile/config.json"}) == ("mobile/config.json", True)
    assert _gitleaks_path({"File": "deploy/.env", "Source": "other"}) == ("deploy/.env", False)
    recs = parse_gitleaks(
        [
            {
                "RuleID": "hashicorp-tf-password",
                "File": "  ",
                "Source": "terraform/prod.tfvars",
                "Description": "tf password",
                "Secret": "tf-demo-password-not-real",
            }
        ]
    )
    findings = [r for r in recs if r.kind == "finding"]
    assert findings and findings[0].ref_id == "CODE-HASHICORP-TF-PASSWORD-TERRAFORM-PROD-TFVARS"
    assert findings[0].severity == "high"
    assert "gitleaks-source" in findings[0].labels
    assert "unknown" not in findings[0].ref_id.lower()
    routed = parse_code([ROOT / "in" / "code" / "gitleaks-source.json"])
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    assert "CODE-HASHICORP-TF-PASSWORD-TERRAFORM-PROD-TFVARS" in refs
    assert refs["CODE-HASHICORP-TF-PASSWORD-TERRAFORM-PROD-TFVARS"].severity == "high"
    assert "gitleaks-source" in refs["CODE-HASHICORP-TF-PASSWORD-TERRAFORM-PROD-TFVARS"].labels
    assert "CODE-JWT-MOBILE-CONFIG-JSON" in refs
    assert "gitleaks-source" in refs["CODE-JWT-MOBILE-CONFIG-JSON"].labels
    assert "CODE-HASHICORP-TF-PASSWORD-UNKNOWN" not in refs
    assert "CODE-JWT-UNKNOWN" not in refs
    blob = " ".join(f"{r.description} {r.extra}" for r in routed)
    assert "tf-demo-password-not-real" not in blob
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo" not in blob


def test_gitleaks_secret_not_persisted() -> None:
    import json

    from collectors.code_secrets import parse_gitleaks
    from shared.io_util import load_structured, redact_obj, redact_text

    path = ROOT / "fixtures" / "demo" / "code" / "gitleaks.json"
    items = load_structured(path)
    assert any(i.get("Secret") for i in items if isinstance(i, dict))
    records = parse_gitleaks(items)
    blob = json.dumps([r.to_canonical() for r in records])
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "ghp_exampleExampleExampleExampleExamp" not in blob
    for rec in records:
        extra = rec.extra or {}
        if "Secret" in extra:
            assert extra["Secret"] == "[REDACTED]"
    stuffed = redact_obj({"Secret": "AKIAIOSFODNN7EXAMPLE", "File": "deploy/.env"})
    assert stuffed["Secret"] == "[REDACTED]"
    assert stuffed["File"] == "deploy/.env"
    raw = redact_text('{"Secret": "ghp_exampleExampleExampleExampleExamp"}')
    assert "[REDACTED]" in raw
    assert "ghp_example" not in raw


def test_gitleaks_sarif_ruleid_not_semgrep() -> None:
    import json

    from collectors.code_secrets import (
        _is_gitleaks_sarif,
        parse_files as parse_code,
        parse_gitleaks_sarif,
    )
    from shared.io_util import load_structured

    path = ROOT / "fixtures" / "demo" / "code" / "gitleaks.sarif"
    docs = load_structured(path)
    assert docs
    assert _is_gitleaks_sarif(docs[0], path) is True
    records = parse_gitleaks_sarif(docs[0])
    findings = [r for r in records if r.kind == "finding"]
    assert findings
    hit = next(r for r in findings if r.ref_id == "CODE-SLACK-BOT-TOKEN-CI-SECRETS-ENV")
    assert hit.severity == "high"
    assert "gitleaks" in hit.labels
    assert "sarif" in hit.labels
    assert "semgrep" not in hit.labels
    blob = json.dumps([r.to_canonical() for r in records])
    assert "ghp_sarifSnippetMustNotLeakAAAA" not in blob
    assert "snippet" not in blob.lower() or "ghp_" not in blob
    routed = parse_code([ROOT / "in" / "code" / "gitleaks.sarif"])
    refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "CODE-SLACK-BOT-TOKEN-CI-SECRETS-ENV" in refs
    assert not any(str(ref).startswith("CODE-SG-") for ref in refs)


def test_trivy_secrets_redacted() -> None:
    import json

    from collectors.code_secrets import parse_files as parse_code

    path = ROOT / "fixtures" / "demo" / "code" / "trivy-secrets.json"
    records = parse_code([path])
    findings = [r for r in records if r.kind == "finding"]
    assert any("aws" in r.name.lower() or "aws-access-key" in "".join(r.labels) for r in findings)
    assert any("github" in r.name.lower() or "github-pat" in "".join(r.labels) for r in findings)
    blob = json.dumps([r.to_canonical() for r in records])
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "[REDACTED]" in blob
    assert all("Match" not in (r.extra or {}) for r in findings)
    assert all(r.extra.get("Match") is None for r in findings)
    routed = parse_code([ROOT / "in" / "code" / "trivy-secrets.json"])
    assert any(r.kind == "finding" and "TS-" in r.ref_id for r in routed)


def test_trivy_misconfig_fail_not_pass() -> None:
    from collectors.code_secrets import (
        _trivy_misconfig_failed,
        parse_files as parse_code,
        parse_trivy,
    )
    from shared.io_util import load_structured

    assert _trivy_misconfig_failed({"Status": "FAIL"}) is True
    assert _trivy_misconfig_failed({"Status": "PASS"}) is False
    assert _trivy_misconfig_failed({"status": "Passed"}) is False
    assert _trivy_misconfig_failed({"Status": "EXCEPTION"}) is False
    assert _trivy_misconfig_failed({}) is True
    path = ROOT / "fixtures" / "demo" / "code" / "trivy-misconfig.json"
    docs = load_structured(path)
    records = parse_trivy(docs[0])
    assets = {r.name for r in records if r.kind == "asset"}
    assert "deploy/api.Dockerfile" in assets
    assert "k8s/privileged-pod.yaml" in assets
    findings = [r for r in records if r.kind == "finding"]
    by_ref = {r.ref_id: r for r in findings}
    assert "CODE-DS002" in by_ref
    assert by_ref["CODE-DS002"].severity == "high"
    assert by_ref["CODE-DS002"].related_assets == ["deploy/api.Dockerfile"]
    assert "CODE-KSV017" in by_ref
    assert by_ref["CODE-KSV017"].severity == "critical"
    assert "CODE-DS005" not in by_ref
    routed = parse_code([ROOT / "in" / "code" / "trivy-misconfig.json"])
    refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "CODE-DS002" in refs
    assert "CODE-KSV017" in refs
    assert "CODE-DS005" not in refs


def test_semgrep_results() -> None:
    from collectors.code_secrets import parse_files

    path = ROOT / "fixtures" / "demo" / "code" / "semgrep.json"
    records = parse_files([path])
    assert any(r.kind == "finding" and "semgrep" in r.name.lower() for r in records)


def test_semgrep_sarif_ruleid_level() -> None:
    from collectors.code_secrets import parse_files as parse_code
    from collectors.code_secrets import parse_semgrep
    from shared.io_util import load_structured

    path = ROOT / "fixtures" / "demo" / "code" / "semgrep.sarif"
    docs = load_structured(path)
    assert docs and "runs" in docs[0]
    records = parse_semgrep(docs[0])
    findings = [r for r in records if r.kind == "finding"]
    by_ref = {r.ref_id: r for r in findings}
    sql = by_ref.get("CODE-SG-PYTHON-DJANGO-SQL-EXTRA-USED")
    assert sql is not None
    assert sql.severity == "high"
    assert "sarif" in sql.labels
    assert "python.django.sql.extra-used" in sql.labels
    assert "app/views.py" in sql.description
    weak = by_ref.get("CODE-SG-PYTHON-LANG-SECURITY-INSECURE-HASH")
    assert weak is not None
    assert weak.severity == "medium"
    assert "app/tokens.py" in weak.description
    routed = parse_code([ROOT / "in" / "code" / "semgrep.sarif"])
    assert any(
        r.kind == "finding" and r.ref_id == "CODE-SG-PYTHON-DJANGO-SQL-EXTRA-USED" and r.severity == "high"
        for r in routed
    )


def test_openvas_nocve_uses_ref_cve() -> None:
    import xml.etree.ElementTree as ET

    from collectors.vuln_scan import _openvas_cve, parse_files, parse_openvas_xml

    nvt = ET.fromstring(
        '<nvt><cve>NOCVE</cve><refs><ref type="cve" id="CVE-2017-5638"/></refs></nvt>'
    )
    assert _openvas_cve(nvt) == "CVE-2017-5638"
    nested = ET.fromstring("<nvt><cves><cve>CVE-2020-1938</cve></cves></nvt>")
    assert _openvas_cve(nested) == "CVE-2020-1938"
    junk = ET.fromstring("<nvt><cve>NOCVE</cve></nvt>")
    assert _openvas_cve(junk) == ""
    path = ROOT / "fixtures" / "demo" / "vuln" / "openvas-nocve.xml"
    records = parse_openvas_xml(path)
    refs = {r.ref_id: r for r in records if r.kind == "finding"}
    names = {r.name for r in records if r.kind == "asset"}
    assert "struts-legacy.corp.local" in names
    assert "tomcat-legacy.corp.local" in names
    assert "VULN-CVE-2017-5638" in refs
    assert refs["VULN-CVE-2017-5638"].severity == "critical"
    assert refs["VULN-CVE-2017-5638"].related_assets == ["struts-legacy.corp.local"]
    assert "VULN-CVE-2020-1938" in refs
    assert refs["VULN-CVE-2020-1938"].severity == "high"
    assert "VULN-NOCVE" not in refs
    routed = parse_files([ROOT / "in" / "vuln" / "openvas-nocve.xml"])
    routed_refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "VULN-CVE-2017-5638" in routed_refs
    assert "VULN-CVE-2020-1938" in routed_refs
    assert "VULN-NOCVE" not in routed_refs


def test_nessus_xml_report_item() -> None:
    import xml.etree.ElementTree as ET

    from collectors.vuln_scan import (
        _nessus_host,
        _nessus_severity,
        _nessus_skip,
        parse_files,
        parse_nessus_xml,
    )

    fqdn = ET.fromstring(
        '<ReportHost name="10.0.88.12">'
        "<HostProperties>"
        '<tag name="host-ip">10.0.88.12</tag>'
        '<tag name="host-fqdn">dc-legacy.corp.local</tag>'
        "</HostProperties>"
        "</ReportHost>"
    )
    assert _nessus_host(fqdn) == "dc-legacy.corp.local"
    empty_fqdn = ET.fromstring(
        '<ReportHost name="print-legacy.corp.local">'
        "<HostProperties>"
        '<tag name="host-ip">10.0.88.19</tag>'
        '<tag name="host-fqdn">  </tag>'
        "</HostProperties>"
        "</ReportHost>"
    )
    assert _nessus_host(empty_fqdn) == "print-legacy.corp.local"
    attr4 = ET.fromstring(
        '<ReportItem severity="4" pluginID="1" pluginName="x"><risk_factor>Critical</risk_factor></ReportItem>'
    )
    assert _nessus_severity(attr4) == "critical"
    info = ET.fromstring(
        '<ReportItem severity="0" pluginID="19506" pluginName="Nessus Scan Information">'
        "<risk_factor>None</risk_factor></ReportItem>"
    )
    assert _nessus_skip(info, _nessus_severity(info))
    path = ROOT / "fixtures" / "demo" / "vuln" / "nessus.xml"
    records = parse_nessus_xml(path)
    refs = {r.ref_id: r for r in records if r.kind == "finding"}
    names = {r.name for r in records if r.kind == "asset"}
    assert "dc-legacy.corp.local" in names
    assert "print-legacy.corp.local" in names
    assert "10.0.88.12" not in names
    assert "VULN-CVE-2020-1472" in refs
    assert refs["VULN-CVE-2020-1472"].severity == "critical"
    assert refs["VULN-CVE-2020-1472"].related_assets == ["dc-legacy.corp.local"]
    assert "VULN-CVE-2021-34527" in refs
    assert refs["VULN-CVE-2021-34527"].severity == "high"
    assert refs["VULN-CVE-2021-34527"].related_assets == ["print-legacy.corp.local"]
    assert "VULN-19506" not in refs
    routed = parse_files([ROOT / "in" / "vuln" / "nessus.xml"])
    routed_refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "VULN-CVE-2020-1472" in routed_refs
    assert "VULN-CVE-2021-34527" in routed_refs
    assert "VULN-19506" not in routed_refs
    nessus_suffix = ROOT / "fixtures" / "demo" / "vuln" / "nessus.xml"
    assert parse_files([nessus_suffix])


def test_openvas_xml_emits_cve() -> None:
    from collectors.vuln_scan import parse_openvas_xml

    path = ROOT / "fixtures" / "demo" / "vuln" / "openvas.xml"
    records = parse_openvas_xml(path)
    findings = [r for r in records if r.kind == "finding"]
    assert findings
    assert any("CVE-2021-44228" in (r.extra.get("cve") or r.ref_id) for r in findings)


def test_openvas_numeric_cvss_is_critical() -> None:
    from collectors.vuln_scan import _cvss_or_level, parse_files, parse_openvas_xml

    assert _cvss_or_level("9.8") == "critical"
    assert _cvss_or_level("10") == "critical"
    path = ROOT / "fixtures" / "demo" / "vuln" / "openvas.xml"
    records = parse_openvas_xml(path)
    heart = [r for r in records if r.kind == "finding" and "CVE-2014-0160" in r.ref_id]
    assert heart
    assert all(r.severity == "critical" for r in heart)
    assert all(r.severity != "info" for r in heart)
    assets = {r.name for r in records if r.kind == "asset"}
    assert "legacy-ssl.corp.local" in assets
    routed = parse_files([ROOT / "in" / "vuln" / "openvas.xml"])
    assert any(
        r.kind == "finding" and r.ref_id == "VULN-CVE-2014-0160" and r.severity == "critical"
        for r in routed
    )


def test_openvas_empty_host_text_uses_ip_attr() -> None:
    import xml.etree.ElementTree as ET

    from collectors.vuln_scan import _openvas_host, parse_files, parse_openvas_xml

    empty = ET.fromstring('<result><host ip="10.0.0.66"></host></result>')
    assert _openvas_host(empty) == "10.0.0.66"
    self_close = ET.fromstring('<result><host ip="10.0.0.66"/></result>')
    assert _openvas_host(self_close) == "10.0.0.66"
    upper = ET.fromstring('<result><host IP="10.0.0.66"/></result>')
    assert _openvas_host(upper) == "10.0.0.66"
    whitespace = ET.fromstring(
        '<result><host ip="10.0.0.66">\n  <asset asset_id="x"/>\n</host></result>'
    )
    assert _openvas_host(whitespace) == "10.0.0.66"
    child_ip = ET.fromstring("<result><host><ip>10.0.0.66</ip></host></result>")
    assert _openvas_host(child_ip) == "10.0.0.66"
    named = ET.fromstring(
        '<result><host ip="10.0.0.199">gvm-named.corp.local</host></result>'
    )
    assert _openvas_host(named) == "gvm-named.corp.local"
    path = ROOT / "fixtures" / "demo" / "vuln" / "openvas-host-ip.xml"
    records = parse_openvas_xml(path)
    assets = {r.name for r in records if r.kind == "asset"}
    assert "10.0.0.66" in assets
    assert "gvm-named.corp.local" in assets
    assert "10.0.0.199" not in assets
    assert "unknown-host" not in assets
    findings = [r for r in records if r.kind == "finding"]
    drupal = next(r for r in findings if "CVE-2018-7600" in r.ref_id)
    assert drupal.related_assets == ["10.0.0.66"]
    assert drupal.severity == "critical"
    php = next(r for r in findings if "CVE-2012-1823" in r.ref_id)
    assert php.related_assets == ["gvm-named.corp.local"]
    assert php.severity == "high"
    routed = parse_files([ROOT / "in" / "vuln" / "openvas-host-ip.xml"])
    names = {r.name for r in routed if r.kind == "asset"}
    assert "10.0.0.66" in names
    assert "gvm-named.corp.local" in names
    assert "10.0.0.199" not in names
    assert any(
        r.kind == "finding" and r.ref_id == "VULN-CVE-2018-7600" and r.severity == "critical"
        for r in routed
    )
    assert any(
        r.kind == "finding" and r.ref_id == "VULN-CVE-2012-1823" and r.severity == "high"
        for r in routed
    )


def test_nuclei_classification_cve_id() -> None:
    from collectors.vuln_scan import (
        _nuclei_cves,
        _nuclei_finding_key,
        parse_files as parse_vuln,
        parse_nuclei_item,
    )

    item = {
        "template-id": "log4j-rce",
        "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "classification": {"cve-id": "CVE-2021-45046"},
        },
        "host": "log4j-legacy.corp.local",
    }
    assert _nuclei_cves(item, item["info"]) == ["CVE-2021-45046"]
    assert _nuclei_finding_key("log4j-rce", ["CVE-2021-45046"]) == "CVE-2021-45046"
    assert _nuclei_finding_key("CVE-2021-44228", ["CVE-2021-45046"]) == "CVE-2021-44228"
    recs = parse_nuclei_item(item)
    findings = [r for r in recs if r.kind == "finding"]
    assert findings and findings[0].ref_id == "VULN-CVE-2021-45046"
    assert findings[0].severity == "critical"
    assert findings[0].related_assets == ["log4j-legacy.corp.local"]
    assert "cve-id" in findings[0].labels
    listed = parse_nuclei_item(
        {
            "template-id": "spring-cloud-function",
            "info": {
                "name": "SpEL",
                "severity": "high",
                "classification": {"cve_id": ["CVE-2022-22963"]},
            },
            "host": "func-legacy.corp.local",
        }
    )
    assert any(r.kind == "finding" and r.ref_id == "VULN-CVE-2022-22963" for r in listed)
    path = ROOT / "in" / "vuln" / "nuclei-cve-id.jsonl"
    routed = parse_vuln([path])
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    names = {r.name for r in routed if r.kind == "asset"}
    assert "log4j-legacy.corp.local" in names
    assert "func-legacy.corp.local" in names
    assert "VULN-CVE-2021-45046" in refs
    assert refs["VULN-CVE-2021-45046"].severity == "critical"
    assert "VULN-CVE-2022-22963" in refs
    assert "VULN-LOG4J-RCE" not in refs
    assert "VULN-SPRING-CLOUD-FUNCTION" not in refs


def test_nuclei_empty_template_id_uses_path() -> None:
    from collectors.vuln_scan import (
        _nuclei_template_from_path,
        _nuclei_template_id,
        parse_files as parse_vuln,
        parse_nuclei_item,
    )

    item = {
        "template": "http/cves/2020/CVE-2020-14882.yaml",
        "template-id": "  ",
        "info": {"name": "Oracle WebLogic Console RCE", "severity": "critical"},
        "host": "weblogic-legacy.corp.local",
    }
    assert _nuclei_template_id(item) == "CVE-2020-14882"
    assert _nuclei_template_from_path(item) == "CVE-2020-14882"
    recs = parse_nuclei_item(item)
    findings = [r for r in recs if r.kind == "finding"]
    assert findings and findings[0].ref_id == "VULN-CVE-2020-14882"
    assert findings[0].severity == "critical"
    assert "template-path" in findings[0].labels
    assert findings[0].related_assets == ["weblogic-legacy.corp.local"]
    path_only = {
        "template-path": r"C:\templates\http\cves\2021\CVE-2021-21972.yaml",
        "info": {"name": "VMware vSphere Client RCE", "severity": "critical"},
        "host": "vsphere-legacy.corp.local",
    }
    assert "template-id" not in path_only
    assert _nuclei_template_id(path_only) == "CVE-2021-21972"
    listed = parse_nuclei_item(path_only)
    assert any(r.kind == "finding" and r.ref_id == "VULN-CVE-2021-21972" for r in listed)
    bare = parse_nuclei_item(
        {
            "template": "http/misconfig/exposed-kibana.yaml",
            "template-id": "",
            "info": {"name": "Kibana login exposed", "severity": "medium"},
            "host": "kibana-template.corp.local",
        }
    )
    refs = {r.ref_id for r in bare if r.kind == "finding"}
    assert "VULN-EXPOSED-KIBANA" in refs
    assert "VULN-KIBANA-LOGIN-EXPOSED" not in refs
    routed = parse_vuln([ROOT / "in" / "vuln" / "nuclei-template.jsonl"])
    routed_refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    names = {r.name for r in routed if r.kind == "asset"}
    assert "weblogic-legacy.corp.local" in names
    assert "vsphere-legacy.corp.local" in names
    assert "VULN-CVE-2020-14882" in routed_refs
    assert routed_refs["VULN-CVE-2020-14882"].severity == "critical"
    assert "template-path" in routed_refs["VULN-CVE-2020-14882"].labels
    assert "VULN-CVE-2021-21972" in routed_refs
    assert "VULN-EXPOSED-KIBANA" in routed_refs
    assert "VULN-ORACLE-WEBLOGIC-CONSOLE-RCE" not in routed_refs
    assert "VULN-VMWARE-VSPHERE-CLIENT-RCE" not in routed_refs


def test_nuclei_ip_only_no_host_matched_at() -> None:
    from collectors.vuln_scan import _nuclei_host, parse_files as parse_vuln, parse_nuclei_item

    item = {
        "template-id": "CVE-2018-13379",
        "info": {"name": "FortiOS", "severity": "critical", "description": "path traversal"},
        "ip": "10.0.0.55",
    }
    assert "host" not in item
    assert "matched-at" not in item
    assert _nuclei_host(item) == "10.0.0.55"
    listed = dict(item)
    listed["ip"] = ["10.0.0.55"]
    assert _nuclei_host(listed) == "10.0.0.55"
    recs = parse_nuclei_item(item)
    assets = [r for r in recs if r.kind == "asset"]
    assert assets and assets[0].name == "10.0.0.55"
    assert "ip-only" in assets[0].labels
    findings = [r for r in recs if r.kind == "finding"]
    assert findings and findings[0].related_assets == ["10.0.0.55"]
    assert findings[0].ref_id == "VULN-CVE-2018-13379"
    assert findings[0].severity == "critical"
    path = ROOT / "in" / "vuln" / "nuclei-ip-only.jsonl"
    routed = parse_vuln([path])
    names = {r.name for r in routed if r.kind == "asset"}
    assert "10.0.0.55" in names
    assert "unknown-host" not in names
    assert any(r.kind == "finding" and r.ref_id == "VULN-CVE-2018-13379" for r in routed)


def test_nuclei_matched_at_url_normalizes_host() -> None:
    from collectors.vuln_scan import _nuclei_host, parse_files as parse_vuln, parse_nuclei_item

    item = {
        "template-id": "CVE-2019-11510",
        "info": {"name": "Pulse", "severity": "critical", "description": "file read"},
        "matched-at": "https://pulse-legacy.corp.local:443/dana-na/",
    }
    assert "host" not in item
    assert _nuclei_host(item) == "pulse-legacy.corp.local"
    recs = parse_nuclei_item(item)
    assets = [r for r in recs if r.kind == "asset"]
    assert assets and assets[0].name == "pulse-legacy.corp.local"
    assert not assets[0].name.lower().startswith("http")
    findings = [r for r in recs if r.kind == "finding"]
    assert findings and findings[0].related_assets == ["pulse-legacy.corp.local"]
    assert findings[0].extra.get("matched_at") == "pulse-legacy.corp.local"
    blob = " ".join(f"{r.name} {r.description}" for r in recs)
    assert "https://" not in blob
    path = ROOT / "in" / "vuln" / "nuclei-matched-at.jsonl"
    routed = parse_vuln([path])
    names = {r.name for r in routed if r.kind == "asset"}
    assert "pulse-legacy.corp.local" in names
    assert not any(str(n).lower().startswith(("http://", "https://")) for n in names)
    assert any(r.kind == "finding" and r.ref_id == "VULN-CVE-2019-11510" for r in routed)


def test_nuclei_sarif_parses() -> None:
    from collectors.vuln_scan import parse_files as parse_vuln_files
    from collectors.vuln_scan import parse_nuclei_sarif
    from shared.io_util import load_structured

    path = ROOT / "fixtures" / "demo" / "vuln" / "nuclei.sarif"
    docs = load_structured(path)
    assert docs
    records = parse_nuclei_sarif(docs[0])
    findings = [r for r in records if r.kind == "finding"]
    assets = {r.name for r in records if r.kind == "asset"}
    assert any("CVE-2024-21762" in r.ref_id for r in findings)
    assert any(r.severity == "critical" for r in findings)
    assert "vpn.example-corp.com" in assets
    assert "citrix.corp.local" in assets
    routed = parse_vuln_files([ROOT / "in" / "vuln" / "nuclei.sarif"])
    assert any(r.kind == "finding" and "CVE-2024-21762" in r.ref_id for r in routed)


def test_blank_nuclei_line_skipped() -> None:
    path = ROOT / "in" / "vuln" / "nuclei-hostile.ndjson"
    records = parse_vuln([path])
    names = [r.name for r in records if r.kind == "finding"]
    assert "OpenSSH version disclosure" in names
    assert all(r.kind in {"asset", "finding", "evidence", "incident"} for r in records)


def test_nmap_gnmap_parses_hosts() -> None:
    from collectors.inventory_nmap import parse_nmap_gnmap

    path = ROOT / "fixtures" / "demo" / "nmap" / "scan.gnmap"
    records = parse_nmap_gnmap(path)
    assets = [r.name for r in records if r.kind == "asset"]
    assert "legacy-ftp.corp.local" in assets
    assert "10.0.0.88" in assets
    findings = [r for r in records if r.kind == "finding"]
    assert any("FTP" in r.name or "445" in r.name or "SMB" in r.name for r in findings)


def test_nmap_xml_openssh5_is_finding(tmp_path) -> None:
    from collectors.inventory_nmap import parse_nmap_xml

    path = tmp_path / "honeypot.xml"
    path.write_text(
        """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="lab">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="2222">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="5.3p1 Debian-3ubuntu7"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )
    records = parse_nmap_xml(path)
    findings = [r for r in records if r.kind == "finding"]
    assert any("OpenSSH 5" in r.name for r in findings)


def test_nmap_xml_prefers_user_hostname_over_ptr() -> None:
    from collectors.inventory_nmap import parse_files as parse_nmap_files
    from collectors.inventory_nmap import parse_nmap_xml

    path = ROOT / "in" / "nmap" / "user-vs-ptr.xml"
    records = parse_nmap_xml(path)
    assets = [r for r in records if r.kind == "asset"]
    names = {r.name for r in assets}
    assert "bastion-prod.corp.local" in names
    assert "ip-10-0-0-77.ec2.internal" not in names
    bastion = next(r for r in assets if r.name == "bastion-prod.corp.local")
    assert bastion.extra.get("hostname_type") == "user"
    assert "hostname-user" in bastion.labels
    findings = [r for r in records if r.kind == "finding"]
    assert findings
    assert all("bastion-prod.corp.local" in (r.related_assets or []) for r in findings)
    assert all("ip-10-0-0-77.ec2.internal" not in (r.related_assets or []) for r in findings)
    routed = parse_nmap_files([path])
    assert any(r.kind == "asset" and r.name == "bastion-prod.corp.local" for r in routed)


def test_nmap_without_hostname_uses_ip() -> None:
    path = ROOT / "in" / "nmap" / "no-hostname.xml"
    records = parse_nmap_xml(path)
    assets = [r for r in records if r.kind == "asset"]
    assert assets
    assert assets[0].name == "10.0.0.9"
    assert "ip-only" in assets[0].labels


def test_nmap_ipv6_without_hostname_uses_address() -> None:
    from collectors.inventory_nmap import parse_files as parse_nmap_files

    path = ROOT / "in" / "nmap" / "ipv6-no-hostname.xml"
    records = parse_nmap_xml(path)
    assets = [r for r in records if r.kind == "asset"]
    assert assets
    assert assets[0].name == "2001:db8::9"
    assert "ip-only" in assets[0].labels
    assert "ipv6" in assets[0].labels
    assert assets[0].extra.get("ip") == "2001:db8::9"
    findings = [r for r in records if r.kind == "finding"]
    assert any("445" in r.ref_id or "SMB" in r.name for r in findings)
    routed = parse_nmap_files([path])
    assert any(r.kind == "asset" and r.name == "2001:db8::9" for r in routed)


def test_nmap_xml_skips_status_down_hosts() -> None:
    import xml.etree.ElementTree as ET

    from collectors.inventory_nmap import _host_is_up, parse_files as parse_nmap_files
    from collectors.inventory_nmap import parse_nmap_xml

    down = ET.fromstring('<host><status state="down"/></host>')
    assert _host_is_up(down) is False
    mixed = ET.fromstring('<host><status state="Down" reason="no-response"/></host>')
    assert _host_is_up(mixed) is False
    up = ET.fromstring('<host><status state="up"/></host>')
    assert _host_is_up(up) is True
    missing = ET.fromstring("<host><address addr=\"10.0.0.1\"/></host>")
    assert _host_is_up(missing) is True
    path = ROOT / "fixtures" / "demo" / "nmap" / "host-down.xml"
    records = parse_nmap_xml(path)
    names = {r.name for r in records if r.kind == "asset"}
    assert "up-xml.corp.local" in names
    assert "down-xml.corp.local" not in names
    assert "xml-down-mixed.corp.local" not in names
    assert "10.0.0.43" not in names
    assert "10.0.0.45" not in names
    findings = [r for r in records if r.kind == "finding"]
    assert not any("445" in r.ref_id or "SMB" in r.name for r in findings)
    assert not any("telnet" in r.name.lower() or "23" in r.ref_id for r in findings)
    routed = parse_nmap_files([ROOT / "in" / "nmap" / "host-down.xml"])
    routed_names = {r.name for r in routed if r.kind == "asset"}
    assert "up-xml.corp.local" in routed_names
    assert "down-xml.corp.local" not in routed_names
    assert "xml-down-mixed.corp.local" not in routed_names


def test_nmap_gnmap_host_lines() -> None:
    path = ROOT / "fixtures" / "demo" / "nmap" / "scan.gnmap"
    records = parse_nmap_gnmap(path)
    assets = [r for r in records if r.kind == "asset"]
    names = {r.name for r in assets}
    assert "legacy-telnet.corp.local" in names
    assert "10.0.0.41" in names
    assert "down-host.corp.local" not in names
    ip_only = next(r for r in assets if r.name == "10.0.0.41")
    assert "ip-only" in ip_only.labels
    findings = [r for r in records if r.kind == "finding"]
    assert any("telnet" in r.name.lower() for r in findings)
    assert any("rdp" in r.name.lower() or "3389" in r.ref_id for r in findings)
    assert not any("10.0.0.41" in r.ref_id and "445" in r.ref_id for r in findings)


def test_nmap_parse_files_routes_gnmap() -> None:
    path = ROOT / "in" / "nmap" / "scan.gnmap"
    records = parse_nmap_files([path])
    names = {r.name for r in records if r.kind == "asset"}
    assert "legacy-telnet.corp.local" in names
    assert path.read_text(encoding="utf-8").splitlines()[0].startswith("# Nmap")


def test_bloodhound_ce_data_list_nodes() -> None:
    from collectors.identity_ad import _is_bloodhound_ce, parse_bloodhound_ce
    from collectors.identity_ad import parse_files as parse_identity
    from shared.io_util import load_structured

    doc = load_structured(ROOT / "fixtures" / "demo" / "identity" / "bloodhound_data_list.json")[0]
    assert isinstance(doc.get("data"), list)
    assert _is_bloodhound_ce(doc) is True
    records = parse_bloodhound_ce(doc)
    names = {r.name for r in records if r.kind == "asset"}
    assert "AW.LOCAL" in names
    assert "SVC-SQL@AW.LOCAL" in names
    assert "JDOE@AW.LOCAL" in names
    assert "ANALYST@AW.LOCAL" in names
    refs = {r.ref_id: r for r in records if r.kind == "finding"}
    assert "ID-BHCE-SPN-SVC-SQL-AW-LOCAL" in refs
    assert refs["ID-BHCE-SPN-SVC-SQL-AW-LOCAL"].severity == "high"
    assert "ID-BHCE-ASREP-JDOE-AW-LOCAL" in refs
    assert refs["ID-BHCE-ASREP-JDOE-AW-LOCAL"].severity == "high"
    assert "ID-BHCE-GENERICALL-CONTRACTOR-AW-LOCAL-DC02-AW-LOCAL" in refs
    assert refs["ID-BHCE-GENERICALL-CONTRACTOR-AW-LOCAL-DC02-AW-LOCAL"].severity == "critical"
    assert not any("ANALYST" in rid for rid in refs)
    routed = parse_identity([ROOT / "in" / "identity" / "bloodhound_data_list.json"])
    routed_refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "ID-BHCE-SPN-SVC-SQL-AW-LOCAL" in routed_refs
    assert "ID-BHCE-ASREP-JDOE-AW-LOCAL" in routed_refs


def test_bloodhound_ce_data_nodes_edges() -> None:
    from collectors.identity_ad import parse_bloodhound_ce
    from collectors.identity_ad import parse_files as parse_identity
    from shared.io_util import load_structured

    path = ROOT / "fixtures" / "demo" / "identity" / "bloodhound_ce.json"
    docs = load_structured(path)
    records = parse_bloodhound_ce(docs[0])
    names = {r.name for r in records if r.kind == "asset"}
    assert "HELPDESK@CORP.LOCAL" in names
    assert "INTERN@CORP.LOCAL" in names
    findings = [r for r in records if r.kind == "finding"]
    blob = " ".join(f"{r.ref_id} {r.name}" for r in findings).upper()
    assert "GENERICALL" in blob
    assert "DOMAIN ADMINS" in blob or "MEMBEROF" in blob
    assert any("as-rep" in r.name.lower() or "ASREP" in r.ref_id for r in findings)
    assert any("hasspn" in r.description.lower() or "roastable" in r.name.lower() for r in findings)
    routed = parse_identity([ROOT / "in" / "identity" / "bloodhound_ce.json"])
    assert any(r.kind == "finding" and "BHCE" in r.ref_id for r in routed)


def test_pingcastle_healthcheckrisk_json_without_xml() -> None:
    from collectors.identity_ad import parse_files as parse_identity
    from collectors.identity_ad import parse_pingcastle_json
    from shared.io_util import load_structured

    path = ROOT / "in" / "identity" / "pingcastle_healthcheckrisk.json"
    docs = load_structured(path)
    assert docs and "HealthcheckRisk" in docs[0]
    records = parse_pingcastle_json(docs[0])
    assets = {r.name for r in records if r.kind == "asset"}
    assert "fabrikam.local" in assets
    findings = {r.ref_id: r for r in records if r.kind == "finding"}
    trusted = findings.get("ID-PCHCR-P-TRUSTEDCREDS")
    assert trusted is not None
    assert trusted.severity == "high"
    nulls = findings.get("ID-PCHCR-A-NULLSESSION")
    assert nulls is not None
    assert nulls.severity == "medium"
    routed = parse_identity([path])
    assert any(r.kind == "finding" and r.ref_id == "ID-PCHCR-P-TRUSTEDCREDS" for r in routed)
    assert not any(r.kind == "finding" and "PCXML" in r.ref_id for r in routed)


def test_pingcastle_xml_domainfqdn_when_host_empty() -> None:
    import xml.etree.ElementTree as ET

    from collectors.identity_ad import _pingcastle_domain, parse_files as parse_identity
    from collectors.identity_ad import parse_pingcastle_xml

    empty_host = ET.fromstring(
        '<HealthcheckData DomainFQDN="ad.tailspintoys.local">'
        "<Host></Host><DomainFQDN></DomainFQDN>"
        "<ForestFQDN>tailspintoys.local</ForestFQDN></HealthcheckData>"
    )
    assert _pingcastle_domain(empty_host) == "ad.tailspintoys.local"
    forest_only = ET.fromstring(
        "<HealthcheckData><Host/><DomainFQDN/>"
        "<ForestFQDN>forest.example.local</ForestFQDN></HealthcheckData>"
    )
    assert _pingcastle_domain(forest_only) == "forest.example.local"
    path = ROOT / "fixtures" / "demo" / "identity" / "pingcastle-domainfqdn.xml"
    records = parse_pingcastle_xml(path)
    assets = {r.name for r in records if r.kind == "asset"}
    assert "ad.tailspintoys.local" in assets
    assert "corp.local" not in assets
    assert "unknown-domain" not in assets
    findings = {r.ref_id: r for r in records if r.kind == "finding"}
    hit = findings.get("ID-PCXML-P-ADMINPWDTOOOLD")
    assert hit is not None
    assert hit.severity == "high"
    assert hit.related_assets == ["ad.tailspintoys.local"]
    routed = parse_identity([ROOT / "in" / "identity" / "pingcastle-domainfqdn.xml"])
    names = {r.name for r in routed if r.kind == "asset"}
    assert "ad.tailspintoys.local" in names
    assert any(r.kind == "finding" and r.ref_id == "ID-PCXML-P-ADMINPWDTOOOLD" for r in routed)


def test_pingcastle_xml_risk_rules() -> None:
    from collectors.identity_ad import parse_files as parse_identity
    from collectors.identity_ad import parse_pingcastle_xml

    path = ROOT / "fixtures" / "demo" / "identity" / "pingcastle.xml"
    records = parse_pingcastle_xml(path)
    assets = [r for r in records if r.kind == "asset"]
    findings = [r for r in records if r.kind == "finding"]
    assert any(r.name.lower() == "corp.local" for r in assets)
    assert any("LAPS" in r.ref_id or "LAPS" in r.name for r in findings)
    assert any("P-Delegated" in r.ref_id or "Delegated" in r.name for r in findings)
    assert any(r.severity == "high" for r in findings)
    routed = parse_identity([ROOT / "in" / "identity" / "pingcastle.xml"])
    assert any(r.kind == "finding" and "PCXML" in r.ref_id for r in routed)


def test_kube_bench_fail_case_insensitive() -> None:
    from collectors.k8s_kubescape import (
        _kube_bench_severity,
        parse_files as parse_k8s,
        parse_kube_bench,
    )
    from shared.io_util import load_structured

    assert _kube_bench_severity("Fail", "RBAC") == "medium"
    assert _kube_bench_severity("fail", "anonymous auth") == "high"
    assert _kube_bench_severity("Failed", "NodeRestriction") == "medium"
    assert _kube_bench_severity("FAILED", "profiling") == "medium"
    path = ROOT / "in" / "k8s" / "kube-bench.json"
    docs = load_structured(path)
    records = parse_kube_bench(docs[0])
    refs = {r.ref_id for r in records if r.kind == "finding"}
    assert "K8S-KB-1-2-7" in refs
    assert "K8S-KB-1-2-8" in refs
    fail_mixed = [r for r in records if r.ref_id == "K8S-KB-1-2-7"]
    assert fail_mixed and fail_mixed[0].severity == "medium"
    assert "fail" in fail_mixed[0].labels
    failed = [r for r in records if r.ref_id == "K8S-KB-1-2-8"]
    assert failed and failed[0].severity == "medium"
    routed = parse_k8s([path])
    assert any(r.kind == "finding" and r.ref_id == "K8S-KB-1-2-7" for r in routed)


def test_kube_bench_hyphenated_keys() -> None:
    from collectors.k8s_kubescape import (
        _kb_get,
        _kube_bench_status,
        parse_files as parse_k8s,
        parse_kube_bench,
    )
    from shared.io_util import load_structured

    row = {"test-number": "4.2.1", "test-desc": "anon", "test-result": "FAIL"}
    assert _kb_get(row, "test_number", "test-number") == "4.2.1"
    assert _kb_get(row, "test_desc", "test-desc") == "anon"
    assert _kube_bench_status(row) == "FAIL"
    path = ROOT / "fixtures" / "demo" / "k8s" / "kube-bench-hyphen.json"
    records = parse_kube_bench(load_structured(path)[0])
    refs = {r.ref_id: r for r in records if r.kind == "finding"}
    assert "K8S-KB-4-2-1" in refs
    assert refs["K8S-KB-4-2-1"].severity == "high"
    assert "hyphen" in refs["K8S-KB-4-2-1"].labels
    assert "K8S-KB-4-2-4" in refs
    assert refs["K8S-KB-4-2-4"].severity == "medium"
    assert "K8S-KB-4-2-6" in refs
    assert refs["K8S-KB-4-2-6"].severity == "medium"
    assert "K8S-KB-4-2-13" not in refs
    routed = parse_k8s([ROOT / "in" / "k8s" / "kube-bench-hyphen.json"])
    routed_refs = {r.ref_id for r in routed if r.kind == "finding"}
    assert "K8S-KB-4-2-1" in routed_refs
    assert "K8S-KB-4-2-4" in routed_refs
    assert "K8S-KB-4-2-13" not in routed_refs


def test_kube_bench_top_level_tests() -> None:
    from collectors.k8s_kubescape import (
        _kb_controls,
        parse_files as parse_k8s,
        parse_kube_bench,
    )

    doc = {
        "id": "4",
        "text": "Worker Node Security Configuration",
        "node_type": "node",
        "tests": [
            {
                "section": "4.1",
                "desc": "Worker Node Configuration Files",
                "results": [
                    {
                        "test_number": "4.1.1",
                        "test_desc": "kubelet service file permissions",
                        "status": "FAIL",
                    },
                    {
                        "test_number": "4.1.2",
                        "test_desc": "kubelet service file ownership",
                        "status": "FAIL",
                    },
                    {"test_number": "4.1.9", "test_desc": "event-qps", "status": "WARN"},
                    {"test_number": "4.1.10", "test_desc": "tls cert", "status": "PASS"},
                ],
            }
        ],
    }
    assert "Controls" not in doc and "controls" not in doc
    assert len(_kb_controls(doc)) == 1
    records = parse_kube_bench(doc)
    refs = {r.ref_id: r for r in records if r.kind == "finding"}
    assert "K8S-KB-4-1-1" in refs
    assert refs["K8S-KB-4-1-1"].severity == "medium"
    assert "root-tests" in refs["K8S-KB-4-1-1"].labels
    assert "K8S-KB-4-1-2" in refs
    assert refs["K8S-KB-4-1-2"].severity == "medium"
    assert "K8S-KB-4-1-9" in refs
    assert refs["K8S-KB-4-1-9"].severity == "medium"
    assert "K8S-KB-4-1-10" not in refs
    bare = parse_kube_bench(
        {
            "Tests": [
                {
                    "test_number": "4.1.1",
                    "test_desc": "kubelet service file permissions",
                    "status": "FAIL",
                }
            ]
        }
    )
    assert any(r.ref_id == "K8S-KB-4-1-1" for r in bare if r.kind == "finding")
    routed = parse_k8s([ROOT / "in" / "k8s" / "kube-bench-tests.json"])
    routed_refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    assert "K8S-KB-4-1-1" in routed_refs
    assert routed_refs["K8S-KB-4-1-1"].severity == "medium"
    assert "root-tests" in routed_refs["K8S-KB-4-1-1"].labels
    assert "K8S-KB-4-1-2" in routed_refs
    assert "K8S-KB-4-1-9" in routed_refs
    assert routed_refs["K8S-KB-4-1-9"].severity == "medium"
    assert "K8S-KB-4-1-10" not in routed_refs


def test_kube_bench_warn_is_medium() -> None:
    from collectors.k8s_kubescape import parse_files as parse_k8s
    from collectors.k8s_kubescape import parse_kube_bench
    from shared.io_util import load_structured

    path = ROOT / "in" / "k8s" / "kube-bench.json"
    docs = load_structured(path)
    records = parse_kube_bench(docs[0])
    findings = [r for r in records if r.kind == "finding"]
    warn = [r for r in findings if "KB-1-2-6" in r.ref_id]
    assert warn
    assert all(r.severity == "medium" for r in warn)
    assert all("warn" in r.labels for r in warn)
    assert not any("KB-1-2-20" in r.ref_id for r in findings)
    routed = parse_k8s([path])
    assert any(r.kind == "finding" and "KB-1-2-6" in r.ref_id and r.severity == "medium" for r in routed)


def test_kubescape_summary_details() -> None:
    from collectors.k8s_kubescape import parse_files as parse_k8s

    path = ROOT / "fixtures" / "demo" / "k8s" / "kubescape_summary.json"
    records = parse_k8s([path])
    findings = [r for r in records if r.kind == "finding"]
    assets = {r.name for r in records if r.kind == "asset"}
    assert "prod-aks" in assets
    assert any("C-0002" in r.ref_id or "exec" in r.name.lower() for r in findings)
    assert any("RES-SEV" in r.ref_id or "resourcesseverity" in r.labels for r in findings)
    assert any(r.severity == "critical" for r in findings)
    routed = parse_k8s([ROOT / "in" / "k8s" / "kubescape_summary.json"])
    assert any(r.kind == "finding" and "C-0057" in r.ref_id for r in routed)


def test_kubescape_failed_controls_no_resources() -> None:
    from collectors.k8s_kubescape import parse_files as parse_k8s
    from collectors.k8s_kubescape import parse_kubescape

    doc = {
        "clusterName": "inline-gke",
        "failedControls": [
            {
                "controlID": "C-0016",
                "name": "Allow privilege escalation",
                "severity": "high",
            },
            {"controlID": "C-0048", "name": "HostPath mount", "scoreFactor": 8},
            {"controlID": "C-0005", "name": "insecure port", "status": "passed", "severity": "high"},
            "C-0013",
        ],
    }
    assert "resources" not in doc
    assert "results" not in doc
    records = parse_kubescape(doc)
    assets = {r.name for r in records if r.kind == "asset"}
    assert "inline-gke" in assets
    findings = {r.ref_id: r for r in records if r.kind == "finding"}
    assert "K8S-C-0016" in findings
    assert findings["K8S-C-0016"].severity == "high"
    assert "failedcontrols" in findings["K8S-C-0016"].labels
    assert findings["K8S-C-0016"].related_assets[0] == "inline-gke"
    assert "K8S-C-0048" in findings
    assert findings["K8S-C-0048"].severity == "high"
    assert "K8S-C-0013" in findings
    assert findings["K8S-C-0013"].severity == "medium"
    assert "K8S-C-0005" not in findings
    nested = parse_kubescape(
        {
            "cluster": "summary-gke",
            "summaryDetails": {
                "failed_controls": {
                    "C-0030": {
                        "controlId": "C-0030",
                        "name": "Ingress and Egress blocked",
                        "severity": "medium",
                    }
                }
            },
        }
    )
    nested_findings = {r.ref_id: r for r in nested if r.kind == "finding"}
    assert "K8S-C-0030" in nested_findings
    assert nested_findings["K8S-C-0030"].severity == "medium"
    path = ROOT / "fixtures" / "demo" / "k8s" / "kubescape_failedcontrols.json"
    routed = parse_k8s([path])
    names = {r.name for r in routed if r.kind == "asset"}
    refs = {r.ref_id: r for r in routed if r.kind == "finding"}
    assert "staging-gke" in names
    assert "K8S-C-0016" in refs and refs["K8S-C-0016"].severity == "high"
    assert "K8S-C-0048" in refs and refs["K8S-C-0048"].severity == "high"
    assert "K8S-C-0005" not in refs
    in_routed = parse_k8s([ROOT / "in" / "k8s" / "kubescape_failedcontrols.json"])
    assert any(r.kind == "finding" and r.ref_id == "K8S-C-0016" for r in in_routed)
    assert any(r.kind == "asset" and r.name == "staging-gke" for r in in_routed)


def test_package_lock_json_path_is_sp_only() -> None:
    from collectors.code_secrets import parse_files as parse_code

    assert is_lockfile_path("package-lock.json")
    assert is_lockfile_path("apps/web/package-lock.json")
    assert is_lockfile_path(r"apps\web\package-lock.json")
    assert asset_type_for_name("apps/web/package-lock.json", "PR") == "SP"
    assert not is_lockfile_path("package.json")
    path = ROOT / "in" / "code" / "trivy-package-lock.json"
    records = parse_code([path])
    assets = [r for r in records if r.kind == "asset"]
    assert any(r.name == "apps/web/package-lock.json" for r in assets)
    assert all(r.asset_type == "SP" for r in assets if "package-lock.json" in r.name.replace("\\", "/"))
    findings = [r for r in records if r.kind == "finding"]
    assert any(r.ref_id == "CODE-CVE-2024-21538" and r.severity == "high" for r in findings)
    forced = dedupe_assets(
        [{"name": "apps/web/package-lock.json", "asset_type": "PR", "ref_id": "X", "labels": []}]
    )
    assert len(forced) == 1
    assert forced[0]["asset_type"] == "SP"


def test_asset_types_only_pr_sp() -> None:
    assert ASSET_TYPES == frozenset({"PR", "SP"})


def test_collect_controls_ensures_respond_recover() -> None:
    rows = collect_controls([])
    funcs = {c["csf_function"] for c in rows}
    assert "respond" in funcs
    assert "recover" in funcs
    assert "govern" in funcs
    already = collect_controls(
        [
            {
                "extra": {
                    "control": {
                        "ref_id": "CTL-FIM",
                        "name": "FIM",
                        "csf_function": "respond",
                    }
                }
            },
            {
                "extra": {
                    "control": {
                        "ref_id": "CTL-BACKUP-RESTORE",
                        "name": "Backup",
                        "csf_function": "recover",
                    }
                }
            },
        ]
    )
    refs = [c["ref_id"] for c in already]
    assert refs.count("CTL-FIM") == 1
    assert refs.count("CTL-BACKUP-RESTORE") == 1
    assert "CTL-IR-RESPOND" not in refs


def test_backup_operators_control_is_recover() -> None:
    from collectors.identity_ad import parse_files as parse_identity

    path = ROOT / "fixtures" / "demo" / "identity" / "bloodhound_pingcastle.json"
    records = parse_identity([path])
    findings = [r for r in records if r.kind == "finding" and "BACKUP" in r.ref_id.upper()]
    assert findings
    ctl = (findings[0].extra or {}).get("control") or {}
    assert ctl.get("csf_function") == "recover"
    assert ctl.get("ref_id") == "CTL-BACKUP-RESTORE"


def test_wazuh_fim_control_is_respond() -> None:
    from collectors.host_wazuh import parse_files as parse_wazuh

    records = parse_wazuh([ROOT / "in" / "wazuh" / "agents.json"])
    fim = [
        r
        for r in records
        if r.kind == "finding"
        and ((r.extra or {}).get("control") or {}).get("ref_id") == "CTL-FIM"
    ]
    assert fim
    assert all(((r.extra or {}).get("control") or {}).get("csf_function") == "respond" for r in fim)
