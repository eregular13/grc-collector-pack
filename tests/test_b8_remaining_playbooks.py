"""Cold-review-4 §B8 leftovers: specific playbooks, not generic upgrade/TLS.

Pins nuclei Redis-without-auth, leftover PingCastle RiskIds, testssl
wildcard/CAA, Nikto missing-header + LFI, and Trivy/SARIF package CVEs.
SAMPLE/DEMO != client KEEP. No POST /api/risks.
"""

from __future__ import annotations

from pathlib import Path

from collectors import vuln_scan
from shared.control_map import map_finding
from shared.finding_types import finding_type, type_remediation
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
        assert finding_type(row) == "redis_noauth"
        mapped = map_finding(row)
        assert mapped["control_name"] == "Require authentication on Redis"
        assert mapped.get("generic") is False
        n53 = set(mapped.get("nist_800_53") or [])
        assert {"IA-2", "AC-3"} <= n53
        assert not {"SI-2", "RA-5"} <= n53
        fix = mapped["recommended_fix"].lower()
        assert "requirepass" in fix
        assert "protected-mode" in fix
        assert "generic fallback" not in fix
        assert "apply vulnerability remediation" not in mapped["control_name"].lower()


def test_leftover_pingcastle_risk_ids_get_named_ad_playbooks() -> None:
    cases = (
        (
            "S-PwdNeverExpires",
            "Disable password-never-expires on accounts",
            ("never expires", "password"),
        ),
        (
            "A-LAPS-Not-Installed",
            "Deploy LAPS for local administrator passwords",
            ("laps",),
        ),
        (
            "P-DNSAdmin",
            "Restrict DnsAdmins membership",
            ("dnsadmin",),
        ),
        (
            "T-SIDHistory",
            "Remove SID History from trusted accounts",
            ("sid history",),
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
        assert mapped.get("nist_800_53"), rid
        assert "generic fallback" not in mapped["recommended_fix"].lower()
        blob = mapped["recommended_fix"].lower()
        assert any(tok in blob for tok in tokens), (rid, blob)


def test_unmapped_pingcastle_risk_id_has_ad_controls_not_empty() -> None:
    rec = _rec(
        source="identity-ad",
        name="PingCastle X-UnknownBrick",
        description="Unmapped leftover RiskId",
        category="identity-gap",
        extra={"risk_id": "X-UnknownBrick"},
    )
    mapped = map_finding(rec)
    assert mapped.get("generic") is False
    assert mapped["control_name"] == "Remediate PingCastle X-UnknownBrick"
    n53 = set(mapped.get("nist_800_53") or [])
    assert {"AC-2", "AC-6", "IA-5"} <= n53
    assert "generic fallback" not in mapped["recommended_fix"].lower()


def test_highvalue_identity_routes_by_group_name() -> None:
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
    other = _rec(
        source="identity-ad",
        name="High-value identity",
        description="HV-CUSTOM@CORP.LOCAL is marked high-value.",
        category="identity-gap",
        assets=["HV-CUSTOM@CORP.LOCAL"],
        extra={"kind": "Group"},
    )
    smap = map_finding(schema)
    emap = map_finding(enterprise)
    omap = map_finding(other)
    assert smap["control_name"] == "Restrict Schema Admins membership"
    assert "schema update" in smap["recommended_fix"].lower()
    assert emap["control_name"] == "Restrict Enterprise Admins membership"
    assert omap["control_name"] == "Review high-value directory group membership"
    for mapped in (smap, emap, omap):
        assert mapped.get("generic") is False
        assert mapped.get("nist_800_53")
        assert "generic fallback" not in mapped["recommended_fix"].lower()


def test_testssl_wildcard_and_caa_are_not_generic_upgrade() -> None:
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
    assert finding_type(wildcard) == "tls_wildcard"
    assert finding_type(caa) == "tls_caa"
    wmap = map_finding(wildcard)
    cmap = map_finding(caa)
    assert wmap["control_name"] == "Stop trusting wildcard certificates too broadly"
    assert cmap["control_name"] == "Publish a CAA DNS record"
    assert "wildcard" in wmap["recommended_fix"].lower()
    assert "caa" in cmap["recommended_fix"].lower()
    for mapped in (wmap, cmap):
        assert mapped.get("generic") is False
        assert mapped["control_name"] != "Harden TLS on the exposed service"
        assert mapped["control_name"] != "Apply vulnerability remediation"
        assert "generic fallback" not in mapped["recommended_fix"].lower()
        assert type_remediation(wildcard if mapped is wmap else caa)["source"] == "testssl"


def test_nikto_missing_header_is_not_tls_and_lfi_stays_web() -> None:
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
    assert finding_type(hsts) == "web_missing_header"
    assert finding_type(xfo) == "web_missing_header"
    for row in (hsts, xfo):
        mapped = map_finding(row)
        play = f"{mapped['control_name']} {mapped['recommended_fix']}".lower()
        assert mapped["control_name"] == "Set the missing web security header"
        assert "header" in play
        assert "harden tls" not in play
        assert "tls 1.2" not in play
        assert mapped.get("generic") is False
        assert type_remediation(row)["source"] == "nikto"

    recs = [r for r in vuln_scan.parse_file(SAMPLES / "nikto" / "juice-shop-trim.json") if r["kind"] == "finding"]
    lfi = next(r for r in recs if r["extra"].get("id") == "006737")
    assert finding_type(lfi) == "web_lfi"
    lmap = map_finding(lfi)
    assert lmap["control_name"] == "Stop web-app local file inclusion"
    lplay = f"{lmap['control_name']} {lmap['recommended_fix']}".lower()
    assert "file inclusion" in lplay or "path traversal" in lplay
    assert "harden tls" not in lplay
    assert "tls 1.2" not in lplay


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
    assert "tls 1.2" not in fix
    n53 = set(mapped.get("nist_800_53") or [])
    assert {"SI-2", "RA-5"} <= n53
