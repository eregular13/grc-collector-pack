"""H1c: collectors vs real DESKTOP lab-estate scanner output (2026-09-26).

These tests use real in-container nmap/nikto/testssl drops from
172.28.10.0/24 (LAB, not SAMPLE, not client). They assert the behavior
the collectors should have on that output. They are expected RED on
ce67328 until the parsers are fixed.

Do not treat this as a product fix slice.
"""
from __future__ import annotations

from pathlib import Path

from collectors.inventory_nmap import parse_file as parse_nmap
from collectors.vuln_scan import parse_file as parse_vuln
from shared.nikto import parse_nikto

FIX = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "h1-desktop"


def test_h1_desktop_gnmap_samba_does_not_claim_windows_admin_share() -> None:
    """dperson/samba on 172.28.10.50 is Samba smbd, not Windows C$/ADMIN$."""
    path = FIX / "nmap-samba-172.28.10.50.gnmap"
    recs = parse_nmap(path)
    admin = [r for r in recs if r.get("kind") == "finding" and "Administrative share" in (r.get("name") or "")]
    assert admin == [], [r.get("name") for r in admin]


def test_h1_desktop_nikto_v250_text_yields_trace_finding() -> None:
    """ghcr.io/sullo/nikto 2.5.0 text uses 'Target Host' + 'GET /:' lines; must not parse empty."""
    path = FIX / "nikto-172.28.10.11-80.txt"
    rows = parse_nikto(path)
    assert rows is not None
    blob = " ".join(str(r.get("msg") or "") for r in rows).lower()
    assert rows, "nikto 2.5.0 text parsed to zero rows"
    assert "trace" in blob


def test_h1_desktop_testssl_plaintext_http_is_not_a_vulnerability() -> None:
    """testssl against nginx:80 is not TLS; WARN 'not a TLS/SSL enabled server' is not a CVE."""
    path = FIX / "testssl-172.28.10.10-80.json"
    recs = parse_vuln(path)
    findings = [r for r in recs if r.get("kind") == "finding"]
    names = " ".join(str(r.get("name") or "") + " " + str(r.get("description") or "") for r in findings).lower()
    assert "scan interrupted" not in names
    assert "doesn't seem to be a tls" not in names
    assert "optimal proto" not in names
