"""LAB Lynis + OpenSCAP dest_in feed. Hardening gaps, not only open ports.

Fixtures under fixtures/lab-drop/wazuh/ ingest through the same drop path
as lab nmap (prove --use-existing-in / lab_drop_to_sor). Every row is LAB.
LAB never enters KEEP / keep_real. Not a CIS benchmark.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from collectors import host_wazuh
from keep.adapters import (
    client_keep_ready,
    detect_family,
    pack_in_is_lab,
    sample_as_client_reason,
    scan_keep_dir,
)
from keep.lab import keep_lab
from scripts.prove_ciso import prove_ciso
from shared.drop_manifest import parse_manifest_hashes, write_drop_manifest
from shared.hardening_dedup import dedupe_hardening
from shared.hardening_map import lynis_control
from shared.lab_stamp import LAB_LABEL
from shared.openscap import is_openscap, iter_openscap_failures
from tests.test_lab_prove_lock import stage_lab_drop_dest_in

ROOT = Path(__file__).resolve().parents[1]
LAB_DROP = ROOT / "fixtures" / "lab-drop"
WAZUH = LAB_DROP / "wazuh"
LYNIS = WAZUH / "lynis-lab-jump.dat"
OSCAP = WAZUH / "openscap-lab-jump.xml"
GITATTRIBUTES = ROOT / ".gitattributes"
DEMO_LYNIS = ROOT / "fixtures" / "demo" / "wazuh" / "lynis-report.txt"


def test_gitattributes_pins_lab_drop_eol_lf() -> None:
    text = GITATTRIBUTES.read_text(encoding="utf-8")
    assert "fixtures/lab-drop/**" in text
    pinned = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("fixtures/lab-drop/**") and "eol=lf" in stripped:
            pinned = True
    assert pinned
    for path in (LYNIS, OSCAP, WAZUH / "LAB.txt"):
        assert bytes([13]) not in path.read_bytes(), path.name


def test_lab_hardening_fixtures_are_lab_not_cis() -> None:
    assert (WAZUH / "LAB.txt").is_file()
    assert LYNIS.is_file()
    assert OSCAP.is_file()
    banner = (WAZUH / "LAB.txt").read_text(encoding="utf-8")
    assert "LAB/DEMO" in banner
    assert "not a client" in banner.lower()
    blob = LYNIS.read_text(encoding="utf-8") + OSCAP.read_text(encoding="utf-8") + banner
    assert "cisecurity" not in blob.lower()
    assert "CIS Benchmark" not in blob
    assert "not a CIS" in banner.lower() or "not a cis" in banner.lower()
    assert "ssgproject" in OSCAP.read_text(encoding="utf-8")
    assert "hardening_index=47" in LYNIS.read_text(encoding="utf-8")


def test_lynis_mapped_warnings_and_suggestions_only() -> None:
    recs = host_wazuh.parse_lynis_report(LYNIS.read_text(encoding="utf-8"), "2026-09-25T00:00:00Z", path=LYNIS)
    findings = [r for r in recs if r["kind"] == "finding"]
    assets = [r for r in recs if r["kind"] == "asset"]
    assert assets and assets[0]["name"] == "lab-jump.lab.internal"
    assert assets[0]["extra"].get("hardening_index") == 47
    ids = {r["extra"].get("check_id") for r in findings}
    assert "FIRE-4590" in ids
    assert "SSH-7408" in ids
    assert "SSH-7402" in ids  # mapped suggestion
    assert "ACCT-9622" not in ids  # unmapped suggestion stays silent
    assert not any("hardening_index" in r["name"].lower() for r in findings)
    for rec in recs:
        assert LAB_LABEL in (rec.get("labels") or [])
        assert "SAMPLE" not in (rec.get("labels") or [])
        assert rec["extra"].get("lab") is True


def test_demo_lynis_is_not_lab_labeled() -> None:
    recs = host_wazuh.parse_file(DEMO_LYNIS)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("FIRE-4590" in r["name"] for r in findings)
    assert any("SSH-7408" in r["name"] for r in findings)
    assert not any("ACCT-9622" in r["name"] for r in findings)
    for rec in recs:
        assert LAB_LABEL not in (rec.get("labels") or [])


def test_lynis_hardening_index_alone_is_not_a_finding() -> None:
    text = "hostname=score-only\nhardening_index=80\n"
    recs = host_wazuh.parse_lynis_report(text, "2026-09-25T00:00:00Z")
    assert [r["kind"] for r in recs] == ["asset"]
    assert recs[0]["extra"]["hardening_index"] == 80


def test_openscap_fail_error_only() -> None:
    assert is_openscap(name=OSCAP.name, text=OSCAP.read_text(encoding="utf-8"))
    rows = iter_openscap_failures(OSCAP.read_text(encoding="utf-8"))
    shorts = {r["short_id"] for r in rows}
    results = {r["short_id"]: r["result"] for r in rows}
    assert results["sshd_disable_root_login"] == "fail"
    assert results["package_iptables_installed"] == "fail"
    assert results["sshd_disable_empty_passwords"] == "fail"
    assert results["security_patches_up_to_date"] == "fail"
    assert results["service_auditd_enabled"] == "error"
    assert "sshd_set_idle_timeout" not in shorts
    assert "aide_build_database" not in shorts
    assert "enable_authselect" not in shorts
    recs = host_wazuh.parse_file(OSCAP)
    findings = [r for r in recs if r["kind"] == "finding"]
    names = " ".join(r["name"] for r in findings)
    assert "CIS-CAT" not in names
    assert "CIS " not in names
    for rec in recs:
        assert "cis-cat" not in (rec.get("labels") or [])
        assert LAB_LABEL in (rec.get("labels") or [])
        assert "openscap" in (rec.get("labels") or [])
    root = next(r for r in findings if "sshd_disable_root_login" in r["name"])
    refs = root["extra"].get("ssg_references") or []
    assert any("ANSSI" in str(x) or "CCE-" in str(x) for x in refs)
    assert root["extra"].get("rule_id", "").startswith("xccdf_org.ssgproject")


def test_lynis_oscap_dedupe_same_host_control() -> None:
    merged = dedupe_hardening(host_wazuh.parse_file(LYNIS) + host_wazuh.parse_file(OSCAP))
    findings = [r for r in merged if r["kind"] == "finding"]
    assets = [r for r in merged if r["kind"] == "asset"]
    assert len(assets) == 1
    assert assets[0]["name"] == "lab-jump.lab.internal"
    keys = [r["extra"].get("control_key") for r in findings]
    assert keys.count("ssh_root_login") == 1
    assert keys.count("host_firewall") == 1
    assert keys.count("ssh_empty_passwords") == 1
    root = next(r for r in findings if r["extra"].get("control_key") == "ssh_root_login")
    assert set(root["extra"].get("sources") or []) >= {"lynis", "openscap"}
    assert any(r["extra"].get("check_id") == "security_patches_up_to_date" for r in findings)
    assert any("auditd" in r["name"].lower() for r in findings)
    for rec in findings:
        assert LAB_LABEL in (rec.get("labels") or [])


def test_lynis_control_map_covers_known_ids() -> None:
    assert lynis_control("FIRE-4590") == "host_firewall"
    assert lynis_control("SSH-7408") == "ssh_root_login"
    assert lynis_control("ACCT-9622", "Enable process accounting") is None


def test_lab_hardening_ingest_e2e_through_drop(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    stage_lab_drop_dest_in(dest_in)
    assert (dest_in / "wazuh" / "lynis-lab-jump.dat").is_file()
    assert (dest_in / "nmap" / "pack_drop" / "findings.jsonl").is_file()
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["lab"] is True
    assert stamp["sample"] is False
    assert stamp["client"] is False
    assert stamp["client_keep"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    out = Path(stamp["out_dir"])
    findings_csv = (out / "ciso-assistant" / "findings.csv").read_text(
        encoding="utf-8"
    )
    poam_csv = (out / "poam" / "poam.csv").read_text(encoding="utf-8")
    assert "Lynis" in findings_csv or "lynis" in poam_csv.lower()
    assert "OpenSCAP" in findings_csv or "oscap" in poam_csv.lower() or "openscap" in poam_csv.lower()
    assert "FIRE-4590" in findings_csv or "firewall" in findings_csv.lower()
    assert "sshd_disable_root_login" in findings_csv or "PermitRootLogin" in findings_csv
    assert "CIS-CAT" not in findings_csv
    canonical = (Path(stamp["out_dir"]) / "canonical" / "host-wazuh.jsonl").read_text(
        encoding="utf-8"
    )
    assert '"LAB"' in canonical or ", \"LAB\"" in canonical
    assert "lab-jump.lab.internal" in canonical
    nmap = (Path(stamp["out_dir"]) / "canonical" / "inventory-nmap.jsonl").read_text(
        encoding="utf-8"
    )
    assert "lab-web.lab.internal" in nmap
    assert "192.168.64." in nmap


def test_lab_rows_cannot_enter_keep_path(tmp_path: Path) -> None:
    assert detect_family(LYNIS) is None
    assert detect_family(OSCAP) is None
    assert pack_in_is_lab(LAB_DROP) is True
    rows = scan_keep_dir(LAB_DROP)
    assert client_keep_ready(rows) is False
    reason = sample_as_client_reason(
        [{"lab": True, "path": str(LYNIS)}],
        sample=False,
        client_keep=True,
    )
    assert reason and "LAB" in reason
    stamp = keep_lab(ROOT, pack_in=LAB_DROP, work=tmp_path / "keep-work")
    assert stamp["client_keep"] is False
    assert stamp["sample"] is True
    assert stamp["origin"] == "keep-samples"
    assert stamp["paying_day"] == "FAIL"
    assert stamp.get("keep_real") in (None, 0, "0/4") or stamp["origin"] == "keep-samples"


def test_wazuh_manifest_sha256_matches(tmp_path: Path) -> None:
    dest = tmp_path / "wazuh"
    dest.mkdir()
    for src in (LYNIS, OSCAP, WAZUH / "LAB.txt"):
        (dest / src.name).write_bytes(src.read_bytes())
    write_drop_manifest(
        dest,
        header="LAB dest_in wazuh drop — test\nLAB != SAMPLE != client.",
        relative_to=dest,
    )
    text = (dest / "MANIFEST").read_text(encoding="utf-8")
    hashes = parse_manifest_hashes(text)
    assert hashes
    for name, digest in hashes.items():
        got = hashlib.sha256((dest / name).read_bytes()).hexdigest()
        assert got == digest
    checked = ROOT / "fixtures" / "lab-drop" / "wazuh" / "MANIFEST"
    assert checked.is_file()
    pinned = parse_manifest_hashes(checked.read_text(encoding="utf-8"))
    for rel, digest in pinned.items():
        path = WAZUH / rel
        assert path.is_file(), rel
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
