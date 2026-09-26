"""CSF 2.0 subcategory + CISA CPG 2.0 per weakness class.

Official IDs only. No csf_PR catch-all. poam.csv and poam_fedramp.csv
carry the same CSF/CPG tags per EGP- ID.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from shared.control_map import extra_labels, map_finding
from shared.framework_class_map import (
    BLANKET_REGISTER_STAMPS,
    CPG20_GOALS,
    CSF20_FUNCTION_OF,
    CSF20_SUBCATEGORIES,
    UNMAPPED,
    WEAKNESS_CLASS_MAP,
    apply_class_mapping,
    classify_weakness_class,
    cpg_stamp,
    csf_cpg_tag_set,
    csf_stamp,
    is_internet_facing,
    resolve_class_tags,
)
from shared.schema import make_record


def _finding(**kwargs):
    return make_record(
        kind="finding",
        source=kwargs.pop("source", "inventory-nmap"),
        ref_id=kwargs.pop("ref", "X-1"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", "desc"),
        severity=kwargs.pop("severity", "high"),
        category=kwargs.pop("category", "exposure"),
        assets=kwargs.pop("assets", ["host-a"]),
        extra=kwargs.pop("extra", {}),
        **kwargs,
    )


def test_every_mapped_csf_id_is_official_csf20() -> None:
    for cls, row in WEAKNESS_CLASS_MAP.items():
        if cls == UNMAPPED:
            assert row["by_function"] == {}
            continue
        for fn, sid in (row.get("by_function") or {}).items():
            assert sid in CSF20_SUBCATEGORIES, (cls, sid)
            assert CSF20_FUNCTION_OF[sid] == fn, (cls, sid, fn)


def test_every_mapped_cpg_id_is_official_cpg20() -> None:
    for cls, row in WEAKNESS_CLASS_MAP.items():
        cid = row["cpg"]
        if cid == UNMAPPED:
            continue
        assert cid in CPG20_GOALS, (cls, cid)
        assert row["source_note"], cls


def test_unmapped_never_emits_csf_pr() -> None:
    tags = resolve_class_tags(UNMAPPED, "identify")
    assert tags["csf_stamp"] == "csf_unmapped"
    assert tags["cpg_stamp"] == "cpg_unmapped"
    assert "csf_PR" not in tags["csf_stamp"]
    rec = _finding(
        ref="UNK-1",
        name="Obscure widget misaligned",
        description="A one-off finding with no control family.",
        category="other",
    )
    mapped = map_finding(rec)
    assert mapped["csf_subcategory"] == UNMAPPED
    refs = mapped["framework_refs"]
    assert "csf_unmapped" in refs
    assert "cpg_unmapped" in refs
    assert "csf_PR" not in refs.split(",")
    assert "csf_protect" not in refs


def test_subcategory_sits_under_stamped_function() -> None:
    tls = map_finding(
        _finding(
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            extra={"port": "443", "service": "https"},
        )
    )
    assert tls["csf_function"] == "protect"
    assert tls["csf_subcategory"] == "PR.DS-02"
    assert CSF20_FUNCTION_OF[tls["csf_subcategory"]] == tls["csf_function"]
    assert "csf_PR_DS_02" in tls["framework_refs"]
    assert "cpg_3_K" in tls["framework_refs"]

    smb = map_finding(
        _finding(
            name="SMB 445 exposed",
            description="filesrv has open TCP/445 (microsoft-ds).",
            extra={"port": "445", "service": "microsoft-ds"},
        )
    )
    assert smb["csf_function"] == "protect"
    assert smb["csf_subcategory"] == "PR.IR-01"
    assert "csf_PR" not in smb["framework_refs"].split(",")
    assert "cpg_3_I" in smb["cpg"]
    assert "cpg_3_S" not in smb["cpg"]

    honeypot = map_finding(
        _finding(
            name="Deception-sensor stage-2 hit",
            description="deception-sensor evidence / an agent-behavior signal.",
            category="deception-sensor",
            source="honeypot",
            extra={"honesty": "deception-sensor", "stage": 2},
        )
    )
    assert honeypot["csf_function"] == "detect"
    assert honeypot["csf_subcategory"] == "DE.CM-01"
    assert CSF20_FUNCTION_OF[honeypot["csf_subcategory"]] == "detect"

    perimeter = map_finding(
        _finding(
            name="Sensitive external hostname on the public perimeter",
            description="vpn.example.com is published on the public perimeter.",
            source="easm",
        )
    )
    assert perimeter["csf_function"] == "protect"
    assert perimeter["csf_subcategory"] == "PR.IR-01"
    assert "cpg_3_S" in perimeter["cpg"]


def test_vuln_reconciles_id_ra_or_pr_ps() -> None:
    log4j = map_finding(
        _finding(
            ref="VULN-log4j",
            name="Apache Log4j RCE",
            description="Log4Shell JNDI lookup CVE-2021-44228",
            category="vulnerability",
            source="vuln-scan",
            extra={"cve": "CVE-2021-44228"},
        )
    )
    assert log4j["weakness_class"] == "vuln_patch"
    assert log4j["csf_function"] in {"identify", "protect"}
    assert log4j["csf_subcategory"] in {"ID.RA-01", "PR.PS-02"}
    assert CSF20_FUNCTION_OF[log4j["csf_subcategory"]] == log4j["csf_function"]
    assert "cpg_2_B" in log4j["cpg"]


def test_identity_and_config_classes() -> None:
    mfa = map_finding(
        _finding(
            name="Root account has no MFA",
            description="Root user has no MFA device.",
            extra={"check_id": "iam_root_mfa_enabled"},
        )
    )
    assert mfa["csf_subcategory"] == "PR.AA-03"
    assert "cpg_3_F" in mfa["cpg"]
    dcsync = map_finding(
        _finding(
            name="BloodHound DCSync",
            description="SVC-SQL@CORP.LOCAL|CORP.LOCAL DCSync",
            source="identity-ad",
            extra={"edge": "DCSync"},
        )
    )
    assert dcsync["csf_subcategory"] == "PR.AA-05"
    assert "cpg_3_H" in dcsync["cpg"]
    patch = map_finding(
        _finding(
            name="Install outstanding security patches",
            description="security patch missing",
            category="hardening",
            source="host-wazuh",
            extra={"control_key": "patching"},
        )
    )
    assert patch["weakness_class"] == "vuln_patch"
    assert patch["csf_subcategory"] in {"ID.RA-01", "PR.PS-02"}


def test_wizard_safe_stamps_have_no_colon() -> None:
    assert ":" not in csf_stamp("PR.IR-01")
    assert csf_stamp("PR.IR-01") == "csf_PR_IR_01"
    assert cpg_stamp("3.S") == "cpg_3_S"
    assert ":" not in cpg_stamp("2.B")


def test_loader_poam_and_fedramp_tags_match_per_egp(
    tmp_path: Path, monkeypatch
) -> None:
    from collectors.grc_loader import load
    from shared.io_util import out_dir, write_canonical

    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    (tmp_path / "in").mkdir()
    recs = [
        _finding(
            ref="NMAP-smb",
            name="SMB 445 exposed",
            description="filesrv has open TCP/445 (microsoft-ds).",
            extra={"port": "445", "service": "microsoft-ds"},
        ),
        _finding(
            ref="NMAP-tls",
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            extra={"port": "443", "service": "https"},
        ),
        _finding(
            ref="ID-mfa",
            name="Root account has no MFA",
            description="Root user has no MFA device.",
            extra={"check_id": "iam_root_mfa_enabled"},
        ),
        _finding(
            ref="VULN-xz",
            name="xz-utils supply chain backdoor",
            description="Malicious code in xz-utils liblzma CVE-2024-3094",
            category="vulnerability",
            source="vuln-scan",
            extra={"cve": "CVE-2024-3094", "pkg": "xz-utils"},
        ),
        _finding(
            ref="WAZ-time",
            name="chrony is not enabled",
            description="Enable chrony so audit timestamps stay trustworthy.",
            category="hardening",
            source="host-wazuh",
            extra={"control_key": "time_sync"},
        ),
    ]
    write_canonical("inventory-nmap", recs)
    load()
    poam_path = out_dir() / "poam" / "poam.csv"
    fed_path = out_dir() / "poam" / "poam_fedramp.csv"
    ledger = json.loads((out_dir() / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    with poam_path.open(encoding="utf-8", newline="") as fh:
        poam = list(csv.DictReader(fh))
    with fed_path.open(encoding="utf-8", newline="") as fh:
        fed = list(csv.DictReader(fh))
    assert "Framework Tags" in (fed[0] if fed else {})
    by_ref_item = {
        str(item.get("ref_id") or ""): item for item in (ledger.get("items") or {}).values()
    }
    poam_by_ref = {r.get("finding_ref_id") or "": r for r in poam}
    fed_by_id = {r.get("POAM ID") or "": r for r in fed}
    matched = 0
    for ref, prow in poam_by_ref.items():
        item = by_ref_item.get(ref)
        if not item:
            continue
        egp = str(item.get("poam_id") or "")
        assert egp.startswith("EGP-")
        frow = fed_by_id[egp]
        assert csf_cpg_tag_set(prow.get("framework_refs") or "") == csf_cpg_tag_set(
            frow.get("Framework Tags") or ""
        )
        matched += 1
    assert matched >= 4
    csf_counts: Counter[str] = Counter()
    cpg_goals: set[str] = set()
    for row in poam:
        csf, cpg = csf_cpg_tag_set(row.get("framework_refs") or "")
        csf_counts.update(csf)
        cpg_goals.update(t for t in cpg if t != "cpg_unmapped")
    n = len(poam)
    assert n >= 4
    top = max(csf_counts.values()) / n
    assert top <= 0.40, csf_counts
    assert len(cpg_goals) >= 5, cpg_goals


def test_classify_unknown_is_unmapped() -> None:
    mapped = {"control_name": "Review and remediate per control widget", "finding_type": ""}
    assert classify_weakness_class(mapped, {}) == UNMAPPED
    tagged = apply_class_mapping(
        {
            "control_name": "Review and remediate per control widget",
            "csf_function": "identify",
            "csf": ["csf_ID", "csf_identify", "csf_unmapped"],
            "nist_800_53": [],
            "cis": [],
        }
    )
    assert tagged["csf_subcategory"] == UNMAPPED
    assert "csf_PR" not in tagged["framework_refs"]


def test_cpg_3_i_is_official() -> None:
    assert CPG20_GOALS["3.I"] == "Implement Logical/Physical Network Segmentation"
    assert cpg_stamp("3.I") == "cpg_3_I"


def test_internet_facing_requires_evidence() -> None:
    internal = _finding(
        name="SMB 445 exposed",
        description="dc.corp.local has open TCP/445 (microsoft-ds).",
        assets=["dc.corp.local"],
        extra={"port": "445", "service": "microsoft-ds", "ip": "10.0.0.10"},
    )
    assert is_internet_facing(internal) is False
    public_ip = _finding(
        name="SMB 445 exposed",
        assets=["edge.example.net"],
        extra={"port": "445", "ip": "203.0.113.10"},
    )
    # 203.0.113.0/24 is documentation — ipaddress treats it as not global.
    assert is_internet_facing(public_ip) is False
    real_public = _finding(
        name="HTTPS exposed",
        assets=["203.0.113.1"],
        extra={"ip": "8.8.8.8"},
    )
    assert is_internet_facing(real_public) is True
    easm = _finding(
        name="Sensitive external hostname vpn.example.com",
        source="easm",
        assets=["vpn.example.com"],
    )
    assert is_internet_facing(easm) is True
    rds = _finding(
        source="cloud-prowler",
        name="RDS instance is publicly accessible",
        extra={"check_id": "rds_instance_no_public_access"},
    )
    assert is_internet_facing(rds, {"finding_type": "rds_public"}) is True
    empty = _finding(name="mystery", description="no plane", assets=["unknown-host"])
    assert is_internet_facing(empty) is False


# Reviewer cold-review #4 §D4 21-row sample. OK stay; wrong get the
# corrected tags; weak/arguable are the justified choices in this brick.
_REVIEWER_21 = (
    # OK (8)
    (
        "ok_rds_public",
        dict(
            source="cloud-prowler",
            name="RDS instance is publicly accessible",
            description="RDS instance PubliclyAccessible=true.",
            extra={"check_id": "rds_instance_no_public_access"},
        ),
        {"cpg": "cpg_3_S"},
    ),
    (
        "ok_s3_public",
        dict(
            source="cloud-prowler",
            name="S3 bucket allows public access",
            description="Bucket ACL AllUsers.",
            extra={"check_id": "s3_bucket_public_access"},
        ),
        {"cpg": "cpg_3_S"},
    ),
    (
        "ok_spf",
        dict(
            source="dns-email",
            name="SPF missing",
            description="No SPF TXT for example.com.",
            category="email",
        ),
        {"cpg": "cpg_3_L", "csf": "csf_PR_DS_02"},
    ),
    (
        "ok_dmarc",
        dict(
            source="dns-email",
            name="DMARC missing",
            description="No _dmarc TXT for example.com.",
            category="email",
        ),
        {"cpg": "cpg_3_L", "csf": "csf_PR_DS_02"},
    ),
    (
        "ok_heartbleed",
        dict(
            source="vuln-scan",
            name="OpenSSL Heartbleed",
            description="Heartbleed CVE-2014-0160 on the TLS stack.",
            category="vulnerability",
            extra={"cve": "CVE-2014-0160"},
        ),
        {"cpg": "cpg_2_B", "csf": "csf_PR_PS_02"},
    ),
    (
        "ok_api_key",
        dict(
            source="code-secrets",
            name="Generic API Key",
            description="Generic API key in services/payments/config.py.",
            category="secrets",
        ),
        {"cpg": "cpg_3_C", "csf": "csf_PR_AA_01"},
    ),
    (
        "ok_domain_admins",
        dict(
            source="identity-ad",
            name="Domain Admins standing members",
            description="Domain Admins has standing members.",
            extra={"edge": "Domain Admins"},
        ),
        {"cpg": "cpg_3_H"},
    ),
    (
        "ok_cloudtrail",
        dict(
            source="cloud-prowler",
            name="CloudTrail multi-region trail is missing",
            description="No multi-region CloudTrail trail.",
            extra={"check_id": "cloudtrail_multi_region_enabled"},
        ),
        {"cpg": "cpg_3_Q"},
    ),
    # Arguable (3) — justified choices
    (
        "arg_roastable_spn",
        dict(
            source="identity-ad",
            name="Roastable SPN",
            description="SVC-SQL@CORP.LOCAL has an SPN and is kerberoastable.",
            extra={"edge": "kerberoast"},
        ),
        # Offline crack of the TGS (service account password) → 3.B, same as AS-REP.
        {"cpg": "cpg_3_B", "csf": "csf_PR_AA_01"},
    ),
    (
        "arg_mdm_enrollment",
        dict(
            source="host-wazuh",
            name="Endpoint not enrolled in MDM",
            description="fleet-laptop-07 MDM enrollment off.",
        ),
        # Stay 3.N / PR.PS-01: MDM enrollment is configuration management.
        {"cpg": "cpg_3_N", "csf": "csf_PR_PS_01"},
    ),
    (
        "arg_k8s_anonymous",
        dict(
            source="k8s-kubescape",
            name="Anonymous Kubernetes API access",
            description="anonymous-auth=true on kube-apiserver.",
            extra={"check_id": "1_2_1"},
            assets=["prod-cluster"],
        ),
        # No internet-facing evidence on prod-cluster → 3.I, not 3.S.
        {"cpg": "cpg_3_I", "csf": "csf_PR_AA_05"},
    ),
    # Weak (3) — better honest fit
    (
        "weak_host_firewall",
        dict(
            source="host-wazuh",
            name="Host firewall is disabled",
            description="No firewall software installed.",
            extra={"control_key": "host_firewall"},
        ),
        {"cpg": "cpg_3_I", "csf": "csf_PR_PS_01"},
    ),
    (
        "weak_sensitive_hostname",
        dict(
            source="easm",
            name="Sensitive external hostname vpn.example.com",
            description="vpn.example.com is published on the public perimeter.",
            assets=["vpn.example.com"],
        ),
        # EASM source is internet-facing evidence; lock down the listener → 3.S / PR.IR-01.
        {"cpg": "cpg_3_S", "csf": "csf_PR_IR_01"},
    ),
    (
        "weak_falco_binary_dir",
        dict(
            source="k8s-kubescape",
            name="Falco WriteBelowBinaryDir",
            description="Workload can write below binary directory.",
            extra={"check_id": "write_below_binary_dir"},
            labels=["falco"],
        ),
        # Runtime integrity / malicious-code detection, not change-management 3.N.
        {"cpg": "cpg_4_A", "csf": "csf_DE_CM_09"},
    ),
    # Wrong (7) — corrected tags
    (
        "wrong_internal_telnet",
        dict(
            source="inventory-nmap",
            name="Telnet exposed",
            description="telnet-legacy.corp.local has open TCP/23.",
            category="exposure",
            extra={"port": "23", "service": "telnet"},
            assets=["telnet-legacy.corp.local"],
        ),
        {"cpg": "cpg_3_I", "not_cpg": "cpg_3_S", "csf": "csf_PR_IR_01"},
    ),
    (
        "wrong_smb_dc",
        dict(
            source="inventory-nmap",
            name="SMB 445 exposed",
            description="dc.corp.local has open TCP/445 (microsoft-ds).",
            category="exposure",
            extra={"port": "445", "service": "microsoft-ds", "ip": "10.0.0.20"},
            assets=["dc.corp.local"],
        ),
        {"cpg": "cpg_3_I", "not_cpg": "cpg_3_S", "csf": "csf_PR_IR_01"},
    ),
    (
        "wrong_msrpc_135",
        dict(
            source="inventory-nmap",
            name="msrpc 135 exposed",
            description="dc.corp.local has open TCP/135 (msrpc).",
            category="exposure",
            extra={"port": "135", "service": "msrpc"},
            assets=["dc.corp.local"],
        ),
        {"cpg": "cpg_3_I", "not_cpg": "cpg_3_S"},
    ),
    (
        "wrong_admin_share",
        dict(
            source="inventory-nmap",
            name="Administrative share exposed on dc.corp.local (C$/ADMIN$)",
            description="C$/ADMIN$ reachable off the admin network.",
            category="exposure",
            extra={"port": "445", "service": "microsoft-ds"},
            assets=["dc.corp.local"],
        ),
        {"cpg": "cpg_3_I", "not_cpg": "cpg_3_S", "csf": "csf_PR_AA_05"},
    ),
    (
        "wrong_legacy_auth",
        dict(
            source="saas-idp",
            name="Legacy authentication protocols are enabled",
            description="M365 legacy auth (IMAP/SMTP basic) still enabled.",
        ),
        {"cpg": "cpg_3_F", "not_cpg": "cpg_3_E", "csf": "csf_PR_AA_03"},
    ),
    (
        "wrong_asrep",
        dict(
            source="identity-ad",
            name="AS-REP roastable account",
            description="SVC-KRBTGT-ROAST does not require Kerberos preauth.",
            extra={"edge": "asrep"},
        ),
        {"cpg": "cpg_3_B", "not_cpg": "cpg_3_E", "csf": "csf_PR_AA_01"},
    ),
    (
        "wrong_redis",
        dict(
            source="vuln-scan",
            name="Redis without auth",
            description="Unauthenticated Redis on a LAB host.",
            category="vulnerability",
            extra={"template_id": "exposed-redis", "rule": "exposed-redis"},
            assets=["https://redis-a.lab.internal"],
        ),
        {
            "cpg": "cpg_3_I",
            "not_cpg": "cpg_2_B",
            "csf": "csf_PR_AA_05",
            "not_csf": "csf_PR_PS_02",
            "control": "Require authentication on Redis",
            "not_n53": ("SI-2", "RA-5"),
        },
    ),
)


def test_reviewer_21_row_sample_expectations() -> None:
    assert len(_REVIEWER_21) == 21
    for key, kwargs, expect in _REVIEWER_21:
        rec = _finding(**kwargs)
        mapped = map_finding(rec)
        refs = mapped.get("framework_refs") or ""
        cpg = mapped.get("cpg") or []
        if want := expect.get("cpg"):
            assert want in cpg or want in refs, (key, cpg, refs)
        if not_cpg := expect.get("not_cpg"):
            assert not_cpg not in cpg and not_cpg not in refs.split(","), (key, cpg, refs)
        if want_csf := expect.get("csf"):
            assert want_csf in refs or want_csf in (mapped.get("csf") or []), (key, refs)
        if not_csf := expect.get("not_csf"):
            assert not_csf not in refs.split(","), (key, refs)
        if control := expect.get("control"):
            assert mapped.get("control_name") == control, (key, mapped.get("control_name"))
        if not_n53 := expect.get("not_n53"):
            n53 = set(mapped.get("nist_800_53") or [])
            assert not (set(not_n53) & n53), (key, n53)
            assert mapped.get("control_name") != "Apply vulnerability remediation"


def test_register_never_blanket_csf_pr(tmp_path: Path, monkeypatch) -> None:
    from collectors.grc_loader import load
    from shared.io_util import out_dir, write_canonical

    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    (tmp_path / "in").mkdir()
    recs = [
        _finding(
            ref="NMAP-smb",
            name="SMB 445 exposed",
            description="filesrv has open TCP/445 (microsoft-ds).",
            extra={"port": "445", "service": "microsoft-ds"},
            assets=["filesrv.corp.local"],
        ),
        make_record(
            kind="asset",
            source="inventory-nmap",
            ref_id="AST-filesrv",
            name="filesrv.corp.local",
            description="internal file server",
            assets=["filesrv.corp.local"],
        ),
    ]
    write_canonical("inventory-nmap", recs)
    load()
    findings = list(
        csv.DictReader((out_dir() / "ciso-assistant" / "findings.csv").open(encoding="utf-8"))
    )
    assets = list(
        csv.DictReader((out_dir() / "ciso-assistant" / "assets.csv").open(encoding="utf-8"))
    )
    assert findings
    for row in findings:
        labels = {t.strip() for t in (row.get("filtering_labels") or "").split(",") if t.strip()}
        assert not (labels & BLANKET_REGISTER_STAMPS), (row.get("name"), labels)
        assert "csf_PR_IR_01" in labels or "csf_PR_AA_05" in labels
    for row in assets:
        labels = {t.strip() for t in (row.get("filtering_labels") or "").split(",") if t.strip()}
        assert "cpg_2_W" not in labels
        assert "cpg_1_E" not in labels
        assert "csf_PR" not in labels
        assert "csf_protect" not in labels
    # extra_labels vocabulary and finding path also stay clean.
    assert not (set(extra_labels()) & BLANKET_REGISTER_STAMPS)
    assert "csf_PR" not in extra_labels(recs[0])
