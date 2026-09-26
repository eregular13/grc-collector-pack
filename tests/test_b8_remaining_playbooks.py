"""Cold-review-4 §B8 leftovers: remediation text only (no type/n53 churn).

Pins nuclei Redis-without-auth, leftover PingCastle RiskIds, testssl
wildcard/CAA wording, Nikto header-by-message + LFI, Trivy/SARIF package
CVEs, and the #164 NTP/RCE/dSHeuristics nits.
SAMPLE/DEMO != client KEEP. No POST /api/risks.
"""

from __future__ import annotations

from pathlib import Path

from collectors import vuln_scan
from shared.control_map import map_finding
from shared.finding_types import finding_type
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
DEMO = ROOT / "fixtures" / "demo"
LAB = ROOT / "fixtures" / "lab-drop"


def _rec(**kwargs):
    extra = dict(kwargs.pop("extra", {}) or {})
    labels = list(kwargs.pop("labels", []) or [])
    return make_record(
        kind="finding",
        source=kwargs.pop("source", "vuln-scan"),
        ref_id=kwargs.pop("ref_id", "B8-1"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", ""),
        severity=kwargs.pop("severity", "high"),
        category=kwargs.pop("category", "vulnerability"),
        assets=kwargs.pop("assets", ["example.local"]),
        labels=labels,
        extra=extra,
    )


def test_nuclei_exposed_redis_uses_redis_auth_playbook() -> None:
    path = LAB / "vuln" / "nuclei-multi-host.jsonl"
    if not path.exists():
        path = DEMO / "vuln" / "nuclei-multi-host.jsonl"
    recs = [r for r in vuln_scan.parse_file(path) if r["kind"] == "finding"]
    redis_rows = [
        r
        for r in recs
        if str(r.get("extra", {}).get("template_id") or r.get("extra", {}).get("rule") or "")
        == "exposed-redis"
    ]
    assert redis_rows, "lab/demo nuclei-multi-host must emit exposed-redis"
    for row in redis_rows:
        assert finding_type(row) == ""
        mapped = map_finding(row)
        assert mapped["control_name"] == "Require authentication on Redis"
        assert mapped.get("generic") is False
        n53 = set(mapped.get("nist_800_53") or [])
        assert {"IA-2", "AC-3"} <= n53
        assert not {"SI-2", "RA-5"} <= n53
        fix = mapped["recommended_fix"].lower()
        assert "requirepass" in fix
        assert "protected-mode" in fix
        assert "-@dangerous" in fix or "acl" in fix
        assert "rename-command" not in fix or "instead of rename" in fix
        assert "generic fallback" not in fix


def test_leftover_pingcastle_risk_ids_get_named_ad_playbooks() -> None:
    cases = (
        (
            "S-PwdNeverExpires",
            "Disable password-never-expires on accounts",
            ("never expires", "gmsa"),
        ),
        (
            "A-LAPS-Not-Installed",
            "Deploy LAPS for local administrator passwords",
            ("laps",),
        ),
        (
            "A-LAPS-Joined-Computers",
            "Deploy LAPS for local administrator passwords",
            ("laps", "joined"),
        ),
        (
            "P-DNSAdmin",
            "Restrict DnsAdmins membership",
            ("cve-2021-40469", "2.10.1"),
        ),
        (
            "S-SIDHistory",
            "Remove SID History from trusted accounts",
            ("sid history",),
        ),
        (
            "T-SIDHistoryDangerous",
            "Remove SID History from trusted accounts",
            ("sid history",),
        ),
        (
            "T-SIDFiltering",
            "Enable SID filtering on trusts",
            ("quarantine:yes", "enablesidhistory:no", "forest"),
        ),
    )
    for rid, control, tokens in cases:
        rec = _rec(
            source="identity-ad",
            name=f"PingCastle {rid}",
            description=f"{rid} healthcheck rationale",
            category="identity-gap",
            labels=["pingcastle"],
            extra={"risk_id": rid},
        )
        assert finding_type(rec) == ""
        mapped = map_finding(rec)
        assert mapped.get("generic") is False, rid
        assert mapped["control_name"] == control, (rid, mapped["control_name"])
        assert "generic fallback" not in mapped["recommended_fix"].lower()
        blob = mapped["recommended_fix"].lower()
        assert all(tok in blob for tok in tokens), (rid, blob)
    dead = _rec(
        source="identity-ad",
        name="PingCastle T-SIDHistory",
        category="identity-gap",
        extra={"risk_id": "T-SIDHistory"},
    )
    assert map_finding(dead)["control_name"].startswith("Remediate PingCastle")


def test_unmapped_pingcastle_risk_id_does_not_stamp_privilege_controls() -> None:
    rec = _rec(
        source="identity-ad",
        name="PingCastle A-DC-Spooler",
        description="Print spooler on a DC",
        category="identity-gap",
        extra={"risk_id": "A-DC-Spooler"},
    )
    mapped = map_finding(rec)
    assert mapped.get("generic") is False
    assert mapped["control_name"] == "Remediate PingCastle A-DC-Spooler"
    n53 = set(mapped.get("nist_800_53") or [])
    assert n53 == set()
    assert "generic fallback" not in mapped["recommended_fix"].lower()


def test_highvalue_identity_paraphrases_without_stealing_group_controls() -> None:
    schema = _rec(
        source="identity-ad",
        name="High-value identity",
        description="SCHEMA ADMINS@CORP.LOCAL is marked high-value.",
        category="identity-gap",
        assets=["SCHEMA ADMINS@CORP.LOCAL"],
        labels=["bloodhound"],
        extra={"kind": "Group"},
    )
    enterprise = _rec(
        source="identity-ad",
        name="High-value identity",
        description="ENTERPRISE ADMINS@CORP.LOCAL is marked high-value.",
        category="identity-gap",
        assets=["ENTERPRISE ADMINS@CORP.LOCAL"],
        extra={"kind": "Group"},
    )
    smap = map_finding(schema)
    emap = map_finding(enterprise)
    assert smap["control_name"] == "Review high-value directory group membership"
    assert emap["control_name"] == "Review high-value directory group membership"
    assert "schema update" in smap["recommended_fix"].lower()
    assert "enterprise admin" in emap["recommended_fix"].lower()
    assert not smap.get("nist_800_53")
    assert smap.get("generic") is False


def test_testssl_wildcard_and_caa_keep_prior_controls() -> None:
    wildcard = _rec(
        name="Wildcard certificate trust is too broad",
        description="certificate trust includes a wildcard SAN",
        labels=["testssl"],
        extra={"id": "cert_trust_wildcard"},
    )
    caa = _rec(
        name="CAA DNS record is missing or invalid",
        description="DNS CAA record is missing",
        labels=["testssl"],
        extra={"id": "DNS_CAArecord"},
    )
    assert finding_type(wildcard) == ""
    assert finding_type(caa) == ""
    wmap = map_finding(wildcard)
    cmap = map_finding(caa)
    assert wmap["control_name"] == "Harden TLS on the exposed service"
    assert cmap["control_name"] == "Apply vulnerability remediation"
    assert "wildcard" in wmap["recommended_fix"].lower()
    assert "hostname" in wmap["recommended_fix"].lower()
    assert "caa" in cmap["recommended_fix"].lower()
    assert set(wmap.get("nist_800_53") or []) == {"SC-8", "SC-8(1)", "SC-13"}
    assert set(cmap.get("nist_800_53") or []) == {"SI-2", "RA-5"}


def test_nikto_header_matches_message_not_plugin_id() -> None:
    hsts = _rec(
        name="Nikto: The site uses SSL and the Strict-Transport-Security HTTP header is not defined.",
        description="The site uses SSL and the Strict-Transport-Security HTTP header is not defined. url=/",
        labels=["nikto"],
        extra={"id": "999970", "url": "/"},
        category="exposure",
    )
    xfo = _rec(
        name="Nikto: The anti-clickjacking X-Frame-Options header is not present.",
        description="The anti-clickjacking X-Frame-Options header is not present. url=/",
        labels=["nikto"],
        extra={"id": "999976", "url": "/"},
        category="exposure",
    )
    incapsula = _rec(
        name="Nikto: Incapsula WAF is in use",
        description="Incapsula WAF is in use url=/",
        labels=["nikto"],
        extra={"id": "999976", "url": "/"},
        category="exposure",
    )
    assert finding_type(hsts) == ""
    assert finding_type(xfo) == ""
    assert finding_type(incapsula) == ""
    hmap = map_finding(hsts)
    xmap = map_finding(xfo)
    imap = map_finding(incapsula)
    assert "header" in hmap["recommended_fix"].lower()
    assert "header" in xmap["recommended_fix"].lower()
    assert "header" not in imap["recommended_fix"].lower()
    assert "waf" in f"{imap['control_name']} {imap['recommended_fix']}".lower() or imap[
        "control_name"
    ].startswith("Reduce unnecessary network exposure")
    assert hmap["control_name"] == "Harden TLS on the exposed service"
    assert xmap["control_name"].startswith("Reduce unnecessary network exposure")
    recs = [r for r in vuln_scan.parse_file(SAMPLES / "nikto" / "juice-shop-trim.json") if r["kind"] == "finding"]
    lfi = next(r for r in recs if r["extra"].get("id") == "006737")
    assert finding_type(lfi) == "web_lfi"
    lmap = map_finding(lfi)
    assert lmap["control_name"] == "Stop web-app local file inclusion"
    assert "harden tls" not in lmap["recommended_fix"].lower()


def test_trivy_sarif_package_cve_is_patch_not_tls() -> None:
    recs = [r for r in vuln_scan.parse_file(SAMPLES / "sarif" / "trivy-critical.sarif") if r["kind"] == "finding"]
    crit = next(r for r in recs if str(r.get("extra", {}).get("rule") or r.get("extra", {}).get("cve") or "") == "CVE-2023-0001")
    mapped = map_finding(crit)
    assert mapped["control_name"] == "Patch libssl1.1 for CVE-2023-0001"
    assert mapped["control_name"] != "Harden TLS on the exposed service"
    assert mapped.get("generic") is False
    fix = mapped["recommended_fix"].lower()
    assert "libssl1.1" in fix
    assert "cve-2023-0001" in fix
    assert {"SI-2", "RA-5"} <= set(mapped.get("nist_800_53") or [])


def test_firefox_printpreview_is_not_ntp_and_safari_is_not_nuclei_rce() -> None:
    firefox = _rec(
        name="Mozilla Firefox < 50.1 Multiple Vulnerabilities",
        description="printpreview use-after-free in the Firefox runtime.",
        labels=["nessus"],
        extra={"cve": "CVE-2016-9893", "plugin_id": "95916"},
    )
    safari = _rec(
        name="Apple Safari < 10.0.2 Multiple Vulnerabilities",
        description="Safari may allow remote code execution via a crafted web page.",
        labels=["nessus"],
        extra={"cve": "CVE-2016-7650", "plugin_id": "95917"},
    )
    ntp = _rec(
        source="host-wazuh",
        name="Enable NTP daemon",
        description="OpenSCAP: ntpd is not enabled so time synchronization fails.",
        category="host-hardening",
        extra={"control_key": "time_sync"},
    )
    fmap = map_finding(firefox)
    smap = map_finding(safari)
    nmap = map_finding(ntp)
    assert fmap["control_name"] != "Enable time synchronization"
    assert "chrony" not in fmap["recommended_fix"].lower()
    assert "ntpd" not in fmap["recommended_fix"].lower()
    assert smap["control_name"] != "Stop remote code execution"
    assert "nuclei flagged" not in smap["recommended_fix"].lower()
    assert nmap["control_name"] == "Enable time synchronization"
    assert "ntp" in nmap["recommended_fix"].lower() or "chrony" in nmap["recommended_fix"].lower()


def test_dsheuristics_cites_kb5008383_chars_28_29() -> None:
    rec = _rec(
        source="identity-ad",
        name="PingCastle A-DsHeuristicsLDAPSecurity",
        description="LDAP security flags are unset",
        extra={"risk_id": "A-DsHeuristicsLDAPSecurity"},
    )
    fix = map_finding(rec)["recommended_fix"].lower()
    assert "cve-2021-42291" in fix
    assert "kb5008383" in fix
    assert "3044" in fix and "3056" in fix
    assert "character 28" in fix or "characters 28" in fix
    assert "create computer objects" not in fix
