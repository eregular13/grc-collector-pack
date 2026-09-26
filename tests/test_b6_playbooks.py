"""Argus cold-review-3 B6: per-type playbooks + human testssl titles.

Nikto web-app rows, TLS side-channels (BREACH/LUCKY13), PingCastle RiskIds,
and testssl ids (not raw cert_expirationStatus) get distinct remediations.
SAMPLE/DEMO != client KEEP. No POST /api/risks.
"""

from __future__ import annotations

from pathlib import Path

from collectors import identity_ad, vuln_scan
from shared.control_map import map_finding, weakness_name_for
from shared.finding_types import finding_type
from shared.schema import make_record
from shared.testssl import human_title

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
DEMO = ROOT / "fixtures" / "demo"


def test_human_title_never_returns_raw_cert_id() -> None:
    assert human_title("cert_expirationStatus") == "TLS certificate is expired or expiring"
    assert human_title("BREACH") == "HTTPS response compression enables BREACH"
    assert human_title("LUCKY13") == "TLS CBC ciphers enable LUCKY13"
    assert "cert_expirationStatus" not in human_title("cert_expirationStatus")


def test_testssl_side_channels_are_not_generic_cve_patches() -> None:
    breach = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-breach",
        name="BREACH",
        description="BREACH potentially: gzip/deflate HTTP compression",
        severity="medium",
        category="vulnerability",
        assets=["vpn.example.com"],
        labels=["testssl"],
        extra={"id": "BREACH", "cve": "CVE-2013-3587"},
    )
    lucky = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-lucky",
        name="LUCKY13",
        description="potentially vulnerable to LUCKY13",
        severity="low",
        category="vulnerability",
        assets=["vpn.example.com"],
        labels=["testssl"],
        extra={"id": "LUCKY13", "cve": "CVE-2013-0169"},
    )
    cert = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-cert",
        name="cert_expirationStatus",
        description="Certificate expired (2020-01-01)",
        severity="high",
        category="vulnerability",
        assets=["vpn.example.com"],
        labels=["testssl"],
        extra={"id": "cert_expirationStatus"},
    )
    assert finding_type(breach) == "tls_breach"
    assert finding_type(lucky) == "tls_lucky13"
    assert finding_type(cert) == "tls_cert_expiration"
    bmap = map_finding(breach)
    lmap = map_finding(lucky)
    cmap = map_finding(cert)
    assert "compress" in bmap["recommended_fix"].lower()
    assert "breach" in bmap["recommended_fix"].lower()
    assert "cve-2013-3587" not in bmap["recommended_fix"].lower()
    assert "cbc" in lmap["recommended_fix"].lower()
    assert "lucky13" in lmap["recommended_fix"].lower()
    assert "gzip" not in lmap["recommended_fix"].lower()
    assert "certificate" in cmap["recommended_fix"].lower()
    assert "expir" in cmap["recommended_fix"].lower()
    assert "cbc" not in cmap["recommended_fix"].lower()
    assert "gzip" not in cmap["recommended_fix"].lower()
    assert weakness_name_for(cert, cmap) == "TLS certificate is expired or expiring"
    assert weakness_name_for(cert, cmap) != "cert_expirationStatus"
    assert bmap["recommended_fix"] != lmap["recommended_fix"] != cmap["recommended_fix"]


def test_sample_testssl_poam_uses_human_titles() -> None:
    recs = [r for r in vuln_scan.parse_file(SAMPLES / "testssl" / "finos_robmoff.at_443_vulnerable.json") if r["kind"] == "finding"]
    cert = next(r for r in recs if r["extra"].get("id") == "cert_expirationStatus")
    breach = next(r for r in recs if r["extra"].get("id") == "BREACH")
    lucky = next(r for r in recs if r["extra"].get("id") == "LUCKY13")
    assert cert["name"] == "TLS certificate is expired or expiring"
    assert "compress" in map_finding(breach)["recommended_fix"].lower()
    assert "cbc" in map_finding(lucky)["recommended_fix"].lower()
    assert weakness_name_for(cert, map_finding(cert)) != "cert_expirationStatus"


def test_nikto_admin_and_breach_have_web_playbooks() -> None:
    demo = [r for r in vuln_scan.parse_file(DEMO / "vuln" / "nikto.txt") if r["kind"] == "finding"]
    admin = next(r for r in demo if "admin" in r["name"].lower())
    assert finding_type(admin) == "web_admin_path"
    mapped = map_finding(admin)
    assert "nikto" in mapped["recommended_fix"].lower()
    assert "easm" not in mapped["recommended_fix"].lower()
    assert mapped.get("generic") is False

    nikto_breach = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-nikto-breach",
        name="Nikto: The Content-Encoding header is set to deflate",
        description="BREACH attack url=/ (Nikto file-drop; not a live HTTP probe)",
        severity="medium",
        category="exposure",
        assets=["example.com"],
        labels=["nikto"],
        extra={"id": "999966", "url": "/"},
    )
    assert finding_type(nikto_breach) == "tls_breach"
    fix = map_finding(nikto_breach)["recommended_fix"].lower()
    assert "compress" in fix and "breach" in fix


def test_pingcastle_risk_id_has_named_playbook() -> None:
    recs = [r for r in identity_ad.parse_file(SAMPLES / "pingcastle" / "one.xml") if r["kind"] == "finding"]
    minpwd = next(r for r in recs if r["extra"].get("risk_id") == "A-MinPwdLen")
    assert finding_type(minpwd) == "pc_min_pwd_len"
    mapped = map_finding(minpwd)
    assert mapped.get("generic") is False
    assert "a-minpwdlen" in mapped["recommended_fix"].lower()
    assert "password" in mapped["recommended_fix"].lower()
    assert "generic fallback" not in mapped["recommended_fix"].lower()
    assert weakness_name_for(minpwd, mapped) == "Domain minimum password length is below policy"
