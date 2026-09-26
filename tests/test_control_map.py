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
    assert "cpg_3_S" in mapped["cpg"]
    assert mapped["csf_subcategory"] == "PR.IR-01"
    assert "csf_PR_IR_01" in mapped["csf"]
    assert "csf_PR" in mapped["csf"]  # function stamp from PR #128 stays
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


def test_low_ssh_is_on_full_poam() -> None:
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
    assert map_finding(rec)["include_poam"] is True


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


def test_saas_mfa_and_admin_highs_map_to_poam() -> None:
    okta = make_record(
        kind="finding",
        source="saas-idp",
        ref_id="SAAS-okta-mfa",
        name="Okta admin MFA gap",
        description="Okta admin MFA enrollment disabled",
        severity="critical",
        category="identity-gap",
        assets=["example.okta.com"],
        extra={"policy": "pol-mfa-admins"},
    )
    mapped = map_finding(okta)
    assert mapped["include_poam"] is True
    assert "mfa" in mapped["control_name"].lower()
    assert "not a Graph or Okta API" in mapped["recommended_fix"]
    assert "CVE-" not in mapped["recommended_fix"]
    scuba_mfa = make_record(
        kind="finding",
        source="saas-idp",
        ref_id="SAAS-scuba-mfa",
        name="Privileged users require MFA",
        description="Admin MFA not enforced for Global Administrator",
        severity="high",
        category="cloud-misconfiguration",
        assets=["contoso.onmicrosoft.com"],
    )
    mapped = map_finding(scuba_mfa)
    assert mapped["include_poam"] is True
    assert "mfa" in mapped["control_name"].lower()
    assert "not a Graph or Okta API" in mapped["recommended_fix"]
    ga = make_record(
        kind="finding",
        source="saas-idp",
        ref_id="SAAS-ga",
        name="Entra Global Administrator via Graph",
        description="ga@contoso.onmicrosoft.com holds Global Administrator (Microsoft Graph export)",
        severity="critical",
        category="identity-gap",
        assets=["ga@contoso.onmicrosoft.com", "contoso.onmicrosoft.com"],
        extra={"role": "Global Administrator"},
    )
    mapped = map_finding(ga)
    assert mapped["include_poam"] is True
    assert "global administrator" in mapped["control_name"].lower()
    assert "not a Graph API" in mapped["recommended_fix"]


def test_idp_mdm_inventory_highs_map_to_poam() -> None:
    cases = [
        (
            "MFA not registered",
            "Export lists bob@contoso.onmicrosoft.com without MFA registered. assessment finding",
            "mfa",
        ),
        (
            "Privileged MFA gap",
            "Export lists it-admin@example.com without MFA registered while holding SUPER_ADMIN.",
            "mfa",
        ),
        (
            "Standing Global Administrator",
            "Export lists a standing Global Administrator assignment for ga@contoso.onmicrosoft.com (not PIM-eligible).",
            "global administrator",
        ),
        (
            "Stale guest account",
            "Export lists guest vendor with a stale last-sign-in.",
            "guest",
        ),
        (
            "intune encryption compliance 33.3%",
            "Export shows 1/3 measured devices encrypted (33.3% compliance).",
            "disk encryption",
        ),
        (
            "Missing EDR on jump-unmanaged",
            "jump-unmanaged export lists endpoint detection / antivirus as missing.",
            "endpoint detection",
        ),
    ]
    for name, desc, needle in cases:
        rec = make_record(
            kind="finding",
            source="saas-idp" if "guest" in name.lower() or "mfa" in name.lower() or "administrator" in name.lower() else "host-wazuh",
            ref_id="INV-map",
            name=name,
            description=desc,
            severity="high",
            category="identity-gap",
            assets=["demo"],
        )
        mapped = map_finding(rec)
        assert mapped["include_poam"] is True, name
        assert needle in mapped["control_name"].lower(), (name, mapped["control_name"])
        assert "CVE-" not in mapped["recommended_fix"]


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


def test_checkov_public_acl_maps_to_poam() -> None:
    rec = make_record(
        kind="finding",
        source="code-secrets",
        ref_id="CODE-ckv",
        name="S3 Bucket has an ACL defined which allows public READ access.",
        description="CKV_AWS_20 S3 Bucket has an ACL defined which allows public READ access. resource=aws_s3_bucket.demo",
        severity="high",
        category="iac",
        assets=["infra/terraform.tfvars"],
        extra={"check_id": "CKV_AWS_20", "resource": "aws_s3_bucket.demo"},
    )
    mapped = map_finding(rec)
    assert mapped["include_poam"] is True
    assert "public" in mapped["control_name"].lower()
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


def test_honeypot_stage_hit_is_not_compromise_poam() -> None:
    rec = make_record(
        kind="finding",
        source="honeypot",
        ref_id="HPOT-ssh-canary-s2",
        name="Deception-sensor stage-2 hit on ssh-canary-01",
        description=(
            "This is deception-sensor evidence / an agent-behavior signal. "
            "A honeypot stage hit is not a full control failure and does not mean "
            "the network is compromised."
        ),
        severity="medium",
        category="deception-sensor",
        assets=["ssh-canary-01"],
        extra={"honesty": "deception-sensor", "stage": 2, "trap_id": "ssh-canary-01"},
    )
    mapped = map_finding(rec)
    assert mapped["include_poam"] is False
    assert "deception-sensor" in mapped["control_name"].lower() or "deception-sensor" in mapped["recommended_fix"]
    assert "not a full control failure" in mapped["recommended_fix"]
    assert "CVE-" not in mapped["recommended_fix"]
    assert mapped["csf_function"] == "detect"


def test_extra_labels_wizard_safe_no_colon() -> None:
    stamps = extra_labels()
    assert "cpg_2_W" in stamps or "cpg_3_S" in stamps
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
    assert "cpg_3_S" in mapped and "csf_PR" in mapped
    assert "csf_PR_IR_01" in mapped
    assert all(":" not in s for s in mapped)


def test_loader_writes_poam_with_blank_owner_due(tmp_path: Path, monkeypatch) -> None:
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
    from shared.ciso_shape import csv_rows

    poam = out_dir() / "poam" / "poam.csv"
    rows = csv_rows(poam)
    assert rows
    assert any("SMB" in (r.get("weakness") or "") for r in rows)
    for row in rows:
        assert row.get("owner") == ""
        assert row.get("due") == ""
        assert row.get("status") == "open"
        assert ":" not in (row.get("framework_refs") or "")
    md = (out_dir() / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "Pentera" not in md
    assert "blank" in md.lower()


def _finding(*, ref: str, name: str, description: str, severity: str, extra: dict | None = None, **kwargs):
    return make_record(
        kind="finding",
        source=kwargs.get("source", "inventory-nmap"),
        ref_id=ref,
        name=name,
        description=description,
        severity=severity,
        category=kwargs.get("category", "exposure"),
        assets=kwargs.get("assets", ["host-a"]),
        extra=extra or {},
    )


def test_csf_stamp_follows_control_not_severity() -> None:
    """Same severity + different controls → different CSF; same control + different sevs → same CSF."""
    tls_high = map_finding(
        _finding(
            ref="NMAP-tls-high",
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            severity="high",
            extra={"port": "443", "service": "https"},
        )
    )
    smb_high = map_finding(
        _finding(
            ref="NMAP-smb-high",
            name="SMB 445 exposed",
            description="filesrv has open TCP/445 (microsoft-ds).",
            severity="high",
            extra={"port": "445", "service": "microsoft-ds"},
        )
    )
    honeypot_high = map_finding(
        _finding(
            ref="HPOT-high",
            name="Deception-sensor stage-2 hit",
            description="deception-sensor evidence / an agent-behavior signal.",
            severity="high",
            category="deception-sensor",
            source="honeypot",
            extra={"honesty": "deception-sensor", "stage": 2},
        )
    )
    time_high = map_finding(
        _finding(
            ref="WAZ-time-high",
            name="chrony is not enabled",
            description="Enable chrony so audit timestamps stay trustworthy.",
            severity="high",
            category="hardening",
            source="host-wazuh",
            extra={"control_key": "time_sync"},
        )
    )
    perimeter_high = map_finding(
        _finding(
            ref="EASM-vpn-high",
            name="Sensitive external hostname on the public perimeter",
            description="vpn.example.com is published on the public perimeter.",
            severity="high",
            category="exposure",
            source="easm",
        )
    )
    assert tls_high["csf_function"] == "protect"
    assert smb_high["csf_function"] == "protect"
    assert honeypot_high["csf_function"] == "detect"
    assert time_high["csf_function"] == "detect"
    assert perimeter_high["csf_function"] == "identify"
    assert tls_high["csf_function"] != honeypot_high["csf_function"]
    assert tls_high["csf_function"] != perimeter_high["csf_function"]
    assert time_high["csf_function"] != smb_high["csf_function"]

    tls_low = map_finding(
        _finding(
            ref="NMAP-tls-low",
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            severity="low",
            extra={"port": "443", "service": "https"},
        )
    )
    tls_crit = map_finding(
        _finding(
            ref="NMAP-tls-crit",
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            severity="critical",
            extra={"port": "443", "service": "https"},
        )
    )
    assert tls_low["csf_function"] == tls_high["csf_function"] == tls_crit["csf_function"] == "protect"
    assert "csf_PR" in tls_crit["csf"]
    assert "csf_RS" not in tls_crit["csf"]  # critical is not Respond
    assert "csf_ID" not in tls_low["csf"] or tls_low["csf_function"] == "protect"

    honeypot_low = map_finding(
        _finding(
            ref="HPOT-low",
            name="Deception-sensor stage-1 hit",
            description="deception-sensor evidence / an agent-behavior signal.",
            severity="low",
            category="deception-sensor",
            source="honeypot",
            extra={"honesty": "deception-sensor", "stage": 1},
        )
    )
    assert honeypot_low["csf_function"] == honeypot_high["csf_function"] == "detect"


def test_csf_unmapped_fallback_is_deterministic_not_severity() -> None:
    unk_low = map_finding(
        _finding(
            ref="UNK-low",
            name="Obscure widget misaligned",
            description="A one-off finding with no control family.",
            severity="low",
            category="other",
        )
    )
    unk_crit = map_finding(
        _finding(
            ref="UNK-crit",
            name="Obscure widget misaligned",
            description="A one-off finding with no control family.",
            severity="critical",
            category="other",
        )
    )
    assert unk_low["control_name"].startswith("Review and remediate per control")
    assert unk_low["csf_function"] == unk_crit["csf_function"]
    assert unk_low["csf_function"] == "identify"
    assert "csf_unmapped" in unk_low["csf"]
    assert "csf_unmapped" in unk_crit["csf"]
    assert unk_crit["csf_function"] != "respond"
    assert unk_low["csf_subcategory"] == "unmapped"
    assert "csf_PR" not in (unk_low.get("framework_refs") or "")
    assert "cpg_unmapped" in (unk_low.get("framework_refs") or "")


def test_loader_csf_column_matches_control_not_severity(tmp_path: Path, monkeypatch) -> None:
    from collectors.grc_loader import load
    from shared.io_util import out_dir, write_canonical

    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    recs = [
        _finding(
            ref="NMAP-tls-a",
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            severity="critical",
            extra={"port": "443", "service": "https"},
        ),
        _finding(
            ref="NMAP-tls-b",
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            severity="low",
            extra={"port": "443", "service": "https"},
        ),
        _finding(
            ref="WAZ-time",
            name="chrony is not enabled",
            description="Enable chrony so audit timestamps stay trustworthy.",
            severity="critical",
            category="hardening",
            source="host-wazuh",
            extra={"control_key": "time_sync"},
        ),
        _finding(
            ref="HPOT-1",
            name="Deception-sensor stage-2 hit",
            description="deception-sensor evidence / an agent-behavior signal.",
            severity="critical",
            category="deception-sensor",
            source="honeypot",
            extra={"honesty": "deception-sensor"},
        ),
    ]
    write_canonical("inventory-nmap", recs)
    load()
    from shared.ciso_shape import csv_rows

    rows = csv_rows(out_dir() / "ciso-assistant" / "applied_controls.csv")
    by_ref = {r["ref_id"]: r for r in rows}
    # Same weakness + same asset merge; keep the critical row's control.
    assert "CTL-nmap-tls-a" in by_ref
    assert "CTL-nmap-tls-b" not in by_ref
    assert by_ref["CTL-nmap-tls-a"]["csf_function"] == "protect"
    assert by_ref["CTL-waz-time"]["csf_function"] == "detect"
    assert by_ref["CTL-hpot-1"]["csf_function"] == "detect"
    assert by_ref["CTL-nmap-tls-a"]["csf_function"] != by_ref["CTL-waz-time"]["csf_function"]
