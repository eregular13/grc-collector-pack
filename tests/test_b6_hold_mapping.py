"""Metis HOLD: remediation mapping vs real scanner ids and no substring hits.

Keyed rows must fire on exact testssl id / PingCastle RiskId / Nikto
message-then-id. NextGEN LFI must not steal TLS via 'https' or RDP via
'wordpress'. Playbook text is paraphrase-only.
"""

from __future__ import annotations

from pathlib import Path

from collectors import identity_ad, vuln_scan
from shared.control_map import map_finding
from shared.finding_types import TYPE_REMEDIATIONS, finding_type, type_remediation
from shared.schema import make_record
from shared.testssl import human_title

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"


def _rec(**kwargs):
    extra = dict(kwargs.pop("extra", {}) or {})
    labels = list(kwargs.pop("labels", []) or [])
    return make_record(
        kind="finding",
        source=kwargs.pop("source", "vuln-scan"),
        ref_id=kwargs.pop("ref_id", "HOLD-1"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", ""),
        severity=kwargs.pop("severity", "medium"),
        category=kwargs.pop("category", "vulnerability"),
        assets=kwargs.pop("assets", ["example.local"]),
        labels=labels,
        extra=extra,
    )


def test_sslv2_matches_testssl_exact_id_not_ssl2() -> None:
    sslv2 = _rec(
        name="SSLv2 is offered",
        description="SSLv2 is offered",
        labels=["testssl"],
        extra={"id": "SSLv2"},
    )
    ssl2 = _rec(
        name="SSL2 placeholder",
        description="invented SSL2 id",
        labels=["testssl"],
        extra={"id": "SSL2"},
    )
    assert finding_type(sslv2) == "tls_sslv2"
    assert type_remediation(sslv2)["source"] == "testssl"
    assert finding_type(ssl2) != "tls_sslv2"
    assert human_title("SSLv2") == "SSLv2 is offered"
    assert "SSLv2" in human_title("SSLv2")


def test_pingcastle_p_delegated_is_protected_users_not_unconstrained() -> None:
    delegated = _rec(
        source="identity-ad",
        name="PingCastle P-Delegated",
        description="Privileged accounts are not marked sensitive",
        labels=["pingcastle"],
        extra={"risk_id": "P-Delegated"},
    )
    unconstrained = _rec(
        source="identity-ad",
        name="PingCastle P-UnconstrainedDelegation",
        description="Account has unconstrained Kerberos delegation",
        labels=["pingcastle"],
        extra={"risk_id": "P-UnconstrainedDelegation"},
    )
    assert finding_type(delegated) == "pc_delegated"
    assert finding_type(unconstrained) == "ad_unconstrained_delegation"
    mapped_d = map_finding(delegated)
    mapped_u = map_finding(unconstrained)
    dfix = mapped_d["recommended_fix"].lower()
    ufix = mapped_u["recommended_fix"].lower()
    assert "protected users" in dfix or "cannot be delegated" in dfix
    assert mapped_d["control_name"] != mapped_u["control_name"]
    assert "unconstrained" in ufix
    assert "protected users" not in ufix
    assert type_remediation(delegated)["source"] == "pingcastle"


def test_pingcastle_asrep_uses_s_nopreauth_ids() -> None:
    pre = _rec(
        source="identity-ad",
        name="PingCastle S-NoPreAuth",
        description="Account does not require Kerberos preauthentication",
        extra={"risk_id": "S-NoPreAuth"},
    )
    admin = _rec(
        source="identity-ad",
        name="PingCastle S-NoPreAuthAdmin",
        description="Admin account does not require Kerberos preauthentication",
        extra={"risk_id": "S-NoPreAuthAdmin"},
    )
    fake = _rec(
        source="identity-ad",
        name="invented a_preauth",
        extra={"risk_id": "a_preauth"},
    )
    assert finding_type(pre) == "ad_asrep"
    assert finding_type(admin) == "ad_asrep"
    assert finding_type(fake) != "ad_asrep"
    assert "preauthentication" in map_finding(pre)["recommended_fix"].lower()


def test_web_http_methods_put_id_and_not_output_delete() -> None:
    put_261 = _rec(
        name="Nikto: The PUT method is allowed on this server",
        description="HTTP method PUT could allow clients to save files url=/",
        labels=["nikto"],
        extra={"id": "999995", "url": "/"},
    )
    recs = [r for r in vuln_scan.parse_file(SAMPLES / "nikto" / "nikto-output-trim.xml") if r["kind"] == "finding"]
    put_215 = next(r for r in recs if r["extra"].get("id") == "999978")
    output_delete = _rec(
        name="Nikto: script output deleted after render",
        description="The script output deleted a temp file url=/app",
        labels=["nikto"],
        extra={"id": "123456", "url": "/app"},
    )
    assert finding_type(put_261) == "web_http_methods"
    assert finding_type(put_215) == "web_http_methods"
    assert finding_type(output_delete) != "web_http_methods"
    assert "put" in map_finding(put_261)["recommended_fix"].lower()
    assert type_remediation(put_261)["source"] == "nikto"


def test_nextgen_lfi_is_not_tls_or_rdp_via_substring() -> None:
    recs = [r for r in vuln_scan.parse_file(SAMPLES / "nikto" / "juice-shop-trim.json") if r["kind"] == "finding"]
    lfi = next(r for r in recs if r["extra"].get("id") == "006737")
    blob = f"{lfi.get('name')} {lfi.get('description')}".lower()
    assert "https://" in blob
    wp = _rec(
        name="Nikto: NextGEN Gallery LFI on wordpress path",
        description=(
            "NextGEN Gallery LFI, see https://example.test/advisory "
            "url=/wordpress/wp-content/plugins/nextgen-gallery/"
        ),
        labels=["nikto"],
        extra={"id": "006737", "url": "/wordpress/wp-content/plugins/nextgen-gallery/"},
    )
    assert "rdp" in f"{wp['name']} {wp['description']}".lower()
    for row in (lfi, wp):
        ftype = finding_type(row)
        assert ftype == "web_lfi"
        assert not ftype.startswith("tls_")
        mapped = map_finding(row)
        play = f"{mapped['control_name']} {mapped['recommended_fix']}".lower()
        assert "tls 1.2" not in play
        assert "rdp" not in play
        assert "3389" not in play
        assert "harden tls" not in play
        assert "innerhtml" not in play


def test_nikto_xss_is_web_app_encoding_not_sast() -> None:
    recs = [r for r in vuln_scan.parse_file(SAMPLES / "nikto" / "nikto-output-trim.xml") if r["kind"] == "finding"]
    xss = next(r for r in recs if "xss" in f"{r.get('name')} {r.get('description')}".lower())
    assert finding_type(xss) == "web_xss"
    fix = map_finding(xss)["recommended_fix"].lower()
    assert "encode" in fix
    assert "content-security-policy" in fix or "csp" in fix
    assert "innerhtml" not in fix
    assert "sast" not in fix
    assert "sarif" not in fix
    assert type_remediation(xss)["source"] == "nikto"


def test_dsheuristics_cites_cve_2021_42291_not_placeholder() -> None:
    rec = _rec(
        source="identity-ad",
        name="PingCastle A-DsHeuristicsLDAPSecurity",
        description="LDAP security flags are unset",
        extra={"risk_id": "A-DsHeuristicsLDAPSecurity"},
    )
    assert finding_type(rec) == "pc_dsheuristics"
    fix = map_finding(rec)["recommended_fix"].lower()
    assert "cve-2021-42291" in fix
    assert "kb5008383" in fix
    assert "cve-2019-12345" not in fix


def test_cheap_accuracy_titles_and_playbooks() -> None:
    assert "ocsp" not in human_title("cert_caIssuers").lower()
    assert "ca issuer" in human_title("cert_caIssuers").lower()
    heart = _rec(name="heartbleed", labels=["testssl"], extra={"id": "heartbleed"})
    hfix = map_finding(heart)["recommended_fix"].lower()
    assert "key" in hfix and "certif" in hfix
    assert "ta14-098a" in hfix
    minpwd = next(
        r
        for r in identity_ad.parse_file(SAMPLES / "pingcastle" / "one.xml")
        if r["kind"] == "finding" and r["extra"].get("risk_id") == "A-MinPwdLen"
    )
    mfix = map_finding(minpwd)["recommended_fix"].lower()
    assert "800-63" in mfix
    krb = _rec(
        source="identity-ad",
        name="PingCastle A-Krbtgt",
        extra={"risk_id": "A-Krbtgt"},
    )
    assert "10 hour" in map_finding(krb)["recommended_fix"].lower()
    breach = next(
        r
        for r in vuln_scan.parse_file(SAMPLES / "testssl" / "synthetic_pretty_sections.json")
        if r["kind"] == "finding" and r["extra"].get("id") == "BREACH"
    )
    lucky = next(
        r
        for r in vuln_scan.parse_file(SAMPLES / "testssl" / "synthetic_pretty_sections.json")
        if r["kind"] == "finding" and r["extra"].get("id") == "LUCKY13"
    )
    assert finding_type(breach) == "tls_breach"
    assert finding_type(lucky) == "tls_lucky13"
    assert "brotli" in map_finding(breach)["recommended_fix"].lower()
    assert "encrypt-then-mac" in map_finding(lucky)["recommended_fix"].lower()


def test_b6_classes_have_short_source_field() -> None:
    for ftype, meta in TYPE_REMEDIATIONS.items():
        if ftype.startswith("tls_"):
            assert meta.get("source") == "testssl", ftype
        elif ftype.startswith("web_"):
            assert meta.get("source") == "nikto", ftype
        elif ftype.startswith("pc_"):
            assert meta.get("source") == "pingcastle", ftype
