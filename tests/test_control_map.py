"""Finding → CPG/CSF map and POA&M rows. No invented CVEs or due dates."""

from __future__ import annotations

from pathlib import Path

from shared.control_map import extra_labels, map_finding
from shared.schema import make_record


def test_smb_445_maps_to_hardening_not_cve() -> None:
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-filesrv-445",
        name="SMB 445 exposed",
        description="filesrv.corp.local has open TCP/445 (microsoft-ds).",
        severity="high",
        category="exposure",
        assets=["filesrv.corp.local"],
        labels=["nmap", "port-445"],
        extra={"port": "445", "service": "microsoft-ds"},
    )
    mapped = map_finding(rec)
    assert mapped["include_poam"] is True
    assert "cpg_2_W" in mapped["cpg"]
    assert "csf_PR" in mapped["csf"]
    assert "CVE-" not in mapped["recommended_fix"]
    assert "445" in mapped["recommended_fix"]
    assert "SMBv1" in mapped["recommended_fix"]
    assert "not a dialect" in mapped["recommended_fix"].lower() or "not a dialect or CVE" in mapped["recommended_fix"]
    assert ":" not in mapped["framework_refs"]


def test_rdp_medium_is_key_poam() -> None:
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-dc-3389",
        name="RDP exposed",
        description="dc.corp.local has open TCP/3389 (ms-wbt-server).",
        severity="medium",
        category="exposure",
        assets=["dc.corp.local"],
        extra={"port": "3389", "service": "ms-wbt-server"},
    )
    assert map_finding(rec)["include_poam"] is True


def test_low_ssh_not_forced_onto_poam() -> None:
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-box-22",
        name="SSH exposed",
        description="box has open TCP/22 (ssh).",
        severity="low",
        category="exposure",
        assets=["box"],
        extra={"port": "22", "service": "ssh"},
    )
    assert map_finding(rec)["include_poam"] is False


def test_tls_posture_is_key_poam() -> None:
    rec = make_record(
        kind="finding",
        source="easm",
        ref_id="EASM-vpn-tls",
        name="TLS expired on vpn.example.com",
        description="https listener presents an expired certificate.",
        severity="medium",
        category="exposure",
        assets=["vpn.example.com"],
        extra={"port": "443", "service": "https"},
    )
    mapped = map_finding(rec)
    assert mapped["include_poam"] is True
    assert "TLS" in mapped["control_name"]
    assert "CVE-" not in mapped["recommended_fix"]
    assert ":" not in mapped["framework_refs"]


def test_admin_share_is_key_poam() -> None:
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-dc-admin$",
        name="ADMIN$ share reachable",
        description="dc.corp.local exposes the ADMIN$ administrative share.",
        severity="medium",
        category="exposure",
        assets=["dc.corp.local"],
        extra={"port": "445", "service": "microsoft-ds"},
    )
    mapped = map_finding(rec)
    assert mapped["include_poam"] is True
    assert "admin share" in mapped["control_name"].lower() or "C$" in mapped["recommended_fix"]
    # Description-only (no 445 extra) still maps the share narrative:
    share = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-admin-share",
        name="C$ admin share open",
        description="filesrv.corp.local C$ administrative share is reachable.",
        severity="medium",
        category="exposure",
        assets=["filesrv.corp.local"],
    )
    mapped = map_finding(share)
    assert mapped["include_poam"] is True
    assert "admin share" in mapped["control_name"].lower() or "C$" in mapped["recommended_fix"]
    assert "CVE-" not in mapped["recommended_fix"]


def test_cloud_high_findings_map_to_poam_not_cve() -> None:
    cases = [
        (
            "S3 bucket allows public access",
            "Bucket demo-asff-open AllUsers public-access.",
            {"check_id": "s3_bucket_public_access", "service": "s3", "arn": "arn:aws:s3:::demo-asff-open"},
            "public",
        ),
        (
            "IAM user does not have AdministratorAccess",
            "User has AdministratorAccess attached directly.",
            {"check_id": "iam_user_administrator_access", "service": "iam"},
            "administrator",
        ),
        (
            "Root account MFA enabled",
            "Root user has no MFA device.",
            {"check_id": "iam_root_mfa_enabled", "service": "iam"},
            "mfa",
        ),
        (
            "Default security group restricts all traffic",
            "Default SG allows 0.0.0.0/0 on all ports.",
            {"check_id": "ec2_securitygroup_allow_ingress_from_internet_to_any_port", "service": "ec2"},
            "security-group",
        ),
        (
            "RDS instance not publicly accessible",
            "RDS instance PubliclyAccessible=true.",
            {"check_id": "rds_instance_no_public_access", "service": "rds"},
            "rds",
        ),
        (
            "S3 bucket server-side encryption",
            "ASFF export: encryption not enforced on demo-logs.",
            {"check_id": "s3_bucket_default_encryption", "service": "s3"},
            "encryption",
        ),
    ]
    for name, desc, extra, needle in cases:
        rec = make_record(
            kind="finding",
            source="cloud-prowler",
            ref_id="CLD-cloud-map",
            name=name,
            description=desc,
            severity="high",
            category="cloud-misconfiguration",
            assets=["demo-cloud"],
            extra=extra,
        )
        mapped = map_finding(rec)
        assert mapped["include_poam"] is True, name
        assert needle in mapped["control_name"].lower(), (name, mapped["control_name"])
        assert "CVE-" not in mapped["recommended_fix"]


def test_k8s_highs_map_to_poam() -> None:
    cases = [
        (
            "Minimize the admission of privileged containers",
            "privileged containers must not be admitted",
            {"control": "5.2.1"},
            "privileged",
        ),
        (
            "Anonymous Kubernetes API access",
            "anonymous-auth=true on kube-apiserver",
            {"control": "C-0013"},
            "anonymous",
        ),
        (
            "Allow privilege escalation",
            "allowPrivilegeEscalation not set false",
            {"control": "C-0034"},
            "privilege escalation",
        ),
        (
            "HostNetwork access",
            "DaemonSet uses hostNetwork",
            {"control": "C-0041"},
            "hostnetwork",
        ),
    ]
    for name, desc, extra, needle in cases:
        rec = make_record(
            kind="finding",
            source="k8s-kubescape",
            ref_id="K8S-map",
            name=name,
            description=desc,
            severity="high",
            category="cloud-misconfiguration",
            assets=["prod-cluster"],
            extra=extra,
        )
        mapped = map_finding(rec)
        assert mapped["include_poam"] is True, name
        assert needle in mapped["control_name"].lower(), (name, mapped["control_name"])
        assert "kubectl" in mapped["recommended_fix"].lower() or "live cluster" in mapped["recommended_fix"].lower()


def test_testssl_and_maester_map_to_poam() -> None:
    hb = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-hb",
        name="heartbleed",
        description="Heartbleed still offered on TLS",
        severity="high",
        category="vulnerability",
        assets=["dev-api.example.com"],
        extra={"cve": "CVE-2014-0160", "id": "heartbleed"},
    )
    mapped = map_finding(hb)
    assert mapped["include_poam"] is True
    assert "heartbleed" in mapped["control_name"].lower()
    assert "live probe" in mapped["recommended_fix"].lower()
    tls1 = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-tls1",
        name="TLS1",
        description="TLS 1.0 offered",
        severity="high",
        category="vulnerability",
        assets=["dev-api.example.com"],
        extra={"id": "TLS1"},
    )
    mapped = map_finding(tls1)
    assert mapped["include_poam"] is True
    assert "tls 1.0" in mapped["control_name"].lower()
    mt = make_record(
        kind="finding",
        source="saas-idp",
        ref_id="SAAS-mt",
        name="Maester MT.1035",
        description="Privileged users should have phishing-resistant MFA",
        severity="high",
        category="cloud-misconfiguration",
        assets=["contoso.onmicrosoft.com"],
        extra={"id": "MT.1035"},
    )
    mapped = map_finding(mt)
    assert mapped["include_poam"] is True
    assert "phishing-resistant" in mapped["control_name"].lower()
    assert "Graph API" in mapped["recommended_fix"] or "not a Graph" in mapped["recommended_fix"]


def test_hk_and_lynis_high_map_to_poam_not_cve() -> None:
    cases = [
        (
            "HardeningKitty Enforce password history",
            "Enforce password history result=failed recommended=24 actual=[REDACTED]",
            {"id": "1.1", "name": "Enforce password history"},
            "password history",
        ),
        (
            "HardeningKitty Disable LM hash storage",
            "Disable LM hash storage result=failed recommended=Enabled actual=[REDACTED]",
            {"id": "18.9", "name": "Disable LM hash storage"},
            "lm hash",
        ),
        (
            "Lynis FIRE-4590: No firewall software installed",
            "No firewall software installed",
            {"check_id": "FIRE-4590"},
            "firewall",
        ),
        (
            "Lynis SSH-7408: SSH PermitRootLogin is enabled",
            "SSH PermitRootLogin is enabled",
            {"check_id": "SSH-7408"},
            "root login",
        ),
    ]
    for name, desc, extra, needle in cases:
        rec = make_record(
            kind="finding",
            source="host-wazuh",
            ref_id="WAZ-map",
            name=name,
            description=desc,
            severity="high",
            category="host-posture",
            assets=["jump-unmanaged"],
            extra=extra,
        )
        mapped = map_finding(rec)
        assert mapped["include_poam"] is True, name
        assert needle in mapped["control_name"].lower(), (name, mapped["control_name"])
        assert "CVE-" not in mapped["recommended_fix"]


def test_sarif_sql_injection_maps_to_poam() -> None:
    rec = make_record(
        kind="finding",
        source="code-secrets",
        ref_id="CODE-sql",
        name="Possible SQL injection via string format",
        description="python.lang.security.audit.sql-injection",
        severity="high",
        category="sast",
        assets=["services/payments/query.py"],
        extra={"rule": "python.lang.security.audit.sql-injection"},
    )
    mapped = map_finding(rec)
    assert mapped["include_poam"] is True
    assert "SQL injection" in mapped["control_name"]
    assert "CVE-" not in mapped["recommended_fix"]
    assert "SARIF" in mapped["recommended_fix"]


def test_extra_labels_wizard_safe_no_colon() -> None:
    stamps = extra_labels()
    assert "cpg_2_W" in stamps
    assert "csf_PR" in stamps
    assert all(":" not in s for s in stamps)
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-x-445",
        name="SMB 445 exposed",
        severity="high",
        category="exposure",
        extra={"port": "445", "service": "microsoft-ds"},
    )
    mapped = extra_labels(rec)
    assert "cpg_2_W" in mapped and "csf_PR" in mapped
    assert all(":" not in s for s in mapped)


def test_loader_writes_poam_with_blank_owner_due(tmp_path: Path, monkeypatch) -> None:
    import csv

    from collectors.grc_loader import load
    from shared.io_util import out_dir, write_canonical

    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-filesrv-445",
        name="SMB 445 exposed",
        description="filesrv.corp.local has open TCP/445 (microsoft-ds).",
        severity="high",
        category="exposure",
        assets=["filesrv.corp.local"],
        labels=["nmap", "port-445"],
        extra={"port": "445", "service": "microsoft-ds"},
    )
    write_canonical("inventory-nmap", [rec])
    summary = load()
    assert summary.get("poam", 0) >= 1
    poam = out_dir() / "poam" / "poam.csv"
    with poam.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    assert any("SMB" in (r.get("weakness") or "") for r in rows)
    for row in rows:
        assert row.get("owner") == ""
        assert row.get("due") == ""
        assert row.get("status") == "open"
        assert ":" not in (row.get("framework_refs") or "")
    md = (out_dir() / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "Pentera" in md and "Evergreen maps" in md
    assert "blank" in md.lower()
