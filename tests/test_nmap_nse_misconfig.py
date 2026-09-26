"""NMAP_NSE_MISCONFIG: nmap NSE script output -> specific misconfig findings + 800-53 mapping.

Fixture: fixtures/lab-misconfig/nmap/*.xml is real nmap 7.95 output against a
deliberately misconfigured LAB (loopback, not client). Before this change the
collector ignored <script> output entirely, so NSE and -sV-only scans produced
identical registers (open-port rows only; weak TLS on 443 vanished).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from collectors.inventory_nmap import parse_file
from shared.control_map import map_finding
from shared.nmap_nse import nse_findings

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "lab-misconfig"
NSE = FIX / "nmap" / "misconfig-nse.xml"
BASE = FIX / "nmap" / "misconfig-baseline.xml"

# Real SP 800-53 Rev. 5 control ids (base or enhancement).
N53 = re.compile(r"^nist80053_(AC|AU|CA|CM|IA|SC|SI|SA|RA)-\d+(\(\d+\))?$")


def _findings(path: Path) -> list[dict]:
    return [r for r in parse_file(path) if r["kind"] == "finding"]


def _by_check(recs: list[dict]) -> dict[tuple[str, str], dict]:
    out = {}
    for rec in recs:
        check = str(rec["extra"].get("check_id") or "")
        if check:
            out[(rec["extra"]["ip"], check)] = rec
    return out


EXPECTED = {
    ("127.0.10.2", "nse-ftp-anon"): "high",
    ("127.0.10.3", "nse-redis-noauth"): "high",
    ("127.0.10.4", "nse-http-dirlist"): "medium",
    ("127.0.10.5", "nse-tls-deprecated-protocol"): "medium",
    ("127.0.10.5", "nse-tls-weak-cipher"): "high",
    ("127.0.10.5", "nse-tls-self-signed"): "medium",
    ("127.0.10.5", "nse-tls-weak-key"): "medium",
    ("127.0.10.6", "nse-smb-signing-not-required"): "medium",
    ("127.0.10.6", "nse-smb-guest"): "medium",
    ("127.0.10.7", "nse-db-empty-password"): "critical",
    ("127.0.10.7", "nse-tls-self-signed"): "medium",
}


def test_nse_scan_yields_each_misconfig_with_severity() -> None:
    got = _by_check(_findings(NSE))
    for key, sev in EXPECTED.items():
        assert key in got, f"missing {key}; got {sorted(got)}"
        assert got[key]["severity"] == sev, (key, got[key]["severity"])
        assert got[key]["extra"].get("nse_script"), key
        assert got[key]["extra"].get("evidence"), key
    # MariaDB offers only TLS1.2/1.3 at strength A: no protocol/cipher claim there.
    assert ("127.0.10.7", "nse-tls-deprecated-protocol") not in got
    assert ("127.0.10.7", "nse-tls-weak-cipher") not in got
    assert ("127.0.10.7", "nse-tls-weak-key") not in got


def test_baseline_without_nse_makes_no_misconfig_claims() -> None:
    assert not _by_check(_findings(BASE)), "no NSE evidence -> no NSE-class findings"


def test_samba_host_gets_no_windows_admin_share_claim() -> None:
    for path in (NSE, BASE):
        names = [r["name"] for r in _findings(path)]
        assert not [n for n in names if "C$/ADMIN$" in n], names


def test_every_nse_finding_maps_to_specific_control_with_real_800_53() -> None:
    for rec in _by_check(_findings(NSE)).values():
        mapped = map_finding(rec)
        assert not mapped["control_name"].startswith("Remediate:"), rec["name"]
        assert "Reduce unnecessary network exposure" not in mapped["control_name"], rec["name"]
        assert mapped["recommended_fix"].strip() != str(rec["description"]).strip()
        assert len(mapped["recommended_fix"]) > 60
        n53 = mapped["nist_800_53"]
        assert n53 and all(N53.match(f"nist80053_{c}") for c in n53), (rec["name"], n53)
        refs = mapped["framework_refs"].split(",")
        assert any(r.startswith("nist80053_") for r in refs), refs
        assert any(r.startswith("cis_") for r in refs), refs
        assert ":" not in mapped["framework_refs"]
        assert mapped["include_poam"] is True, rec["name"]


@pytest.mark.parametrize(
    ("check", "must_have", "fix_words"),
    [
        ("nse-ftp-anon", {"AC-3", "CM-7"}, ("anonymous_enable", "SFTP")),
        ("nse-redis-noauth", {"IA-2", "AC-3"}, ("requirepass", "protected-mode")),
        ("nse-http-dirlist", {"CM-7", "AC-3"}, ("autoindex", "Indexes")),
        ("nse-tls-deprecated-protocol", {"SC-8(1)", "SC-13"}, ("TLS 1.2", "TLS 1.0")),
        ("nse-tls-weak-cipher", {"SC-8(1)", "SC-13"}, ("aNULL", "RC4")),
        ("nse-tls-self-signed", {"SC-17", "SC-23"}, ("CA",)),
        ("nse-tls-weak-key", {"SC-12", "SC-17"}, ("2048",)),
        ("nse-smb-signing-not-required", {"SC-8", "SC-23"}, ("signing", "mandatory")),
        ("nse-smb-guest", {"AC-3", "IA-2"}, ("guest",)),
        ("nse-db-empty-password", {"IA-5", "AC-2"}, ("password", "bind-address")),
    ],
)
def test_misconfig_control_and_fix_are_topic_specific(check: str, must_have: set, fix_words: tuple) -> None:
    rec = next(r for r in _by_check(_findings(NSE)).values() if r["extra"]["check_id"] == check)
    mapped = map_finding(rec)
    assert must_have <= set(mapped["nist_800_53"]), (check, mapped["nist_800_53"])
    for word in fix_words:
        assert word.lower() in mapped["recommended_fix"].lower(), (check, word, mapped["recommended_fix"])


def test_http_default_accounts_documented_format_is_critical() -> None:
    """Format per nmap http-default-accounts docs (synthetic snippet, not a scan)."""
    out = "\n  [Apache Tomcat] at /manager/html/\n    tomcat:tomcat\n"
    specs = nse_findings("10.0.0.9", "10.0.0.9", "8080", "http", "Apache Tomcat", [("http-default-accounts", out)])
    assert len(specs) == 1
    spec = specs[0]
    assert spec["severity"] == "critical"
    assert spec["check_id"] == "nse-default-credentials"
    assert "tomcat:tomcat" not in spec["description"] and "tomcat:tomcat" not in spec["evidence"], "never echo creds"
    rec = {"name": spec["name"], "description": spec["description"], "severity": "critical",
           "category": "misconfiguration", "extra": {"check_id": spec["check_id"], "port": "8080"}}
    mapped = map_finding(rec)
    assert {"IA-5", "AC-2"} <= set(mapped["nist_800_53"])
    assert "default" in mapped["recommended_fix"].lower()


def test_ftp_anon_denied_output_is_not_a_finding() -> None:
    specs = nse_findings("h", "10.0.0.1", "21", "ftp", "vsftpd", [("ftp-anon", "ERROR: Script execution failed")])
    assert specs == []


def test_lab_drop_to_sor_puts_misconfigs_on_poam(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "in" / "nmap").mkdir(parents=True)
    (work / "in" / "LAB.txt").write_text((FIX / "LAB.txt").read_text(encoding="utf-8"), encoding="utf-8")
    (work / "in" / "nmap" / NSE.name).write_bytes(NSE.read_bytes())
    env = {**os.environ, "PYTHONPATH": str(ROOT), "DRY_RUN": "1", "CISO_PUSH": "0", "RISKREADY_PUSH": "0", "GRC_LIVE_SCAN": "0"}
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "prove_ciso.py"), "--work", str(work), "--use-existing-in"],
        cwd=str(ROOT), env=env, capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-800:]
    poam = (work / "out" / "poam" / "poam.csv").read_text(encoding="utf-8")
    for needle in (
        "Anonymous FTP", "Redis", "directory listing", "TLS 1.0", "cipher", "Self-signed",
        "SMB message signing", "empty password",
    ):
        assert needle.lower() in poam.lower(), needle
    assert "nist80053_" in poam
    assert "C$/ADMIN$" not in poam


def test_console_coverage_counts_800_53_as_its_own_family() -> None:
    from product.server import classify_framework_token

    assert classify_framework_token("nist80053_SC-8(1)") == "nist_800_53"
    assert classify_framework_token("csf_PR") == "nist_csf"
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'nist_800_53: "NIST 800-53"' in js
