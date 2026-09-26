#!/usr/bin/env python3
"""Assert GRC lab outputs parse and meet contract."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parents[1] / "out"
if (ROOT / "out").exists() and not str(OUT).endswith("out"):
    OUT = ROOT / "out"

ASSETS_H = "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets"
CONTROLS_H = "ref_id,name,description,domain,status,category,priority,csf_function"
EVID_H = "name,description"
FIND_H = "ref_id,name,description,severity,status,filtering_labels"
VULN_H = "ref_id,name,description,status,severity,assets,applied_controls"
SCEN_H = "ref_id;assets;threats;name;description;existing_controls;current_impact;current_proba;current_risk;additional_controls;residual_impact;residual_proba;residual_risk;treatment"

FIND_SEV = {"low", "medium", "high", "critical"}
VULN_SEV = {"Information", "Low", "Medium", "High", "Critical"}
LIVE_KEY = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{20,}")


def _read(path: Path) -> str:
    assert path.exists() and path.stat().st_size > 0, f"missing/empty {path}"
    return path.read_text(encoding="utf-8")


def _csv_rows(path: Path, expected_header: str, delim: str = ",") -> list[dict]:
    from shared.ciso_shape import csv_rows, first_nonempty_line

    text = _read(path)
    first = first_nonempty_line(path)
    assert first == expected_header, f"{path.name} header {first!r} != {expected_header!r}"
    assert not text.lstrip().startswith("#"), f"{path.name} import CSV must not start with #"
    assert first == text.splitlines()[0].strip()
    return csv_rows(path, delimiter=delim)


def _json(path: Path):
    data = json.loads(_read(path))
    assert data, f"empty json {path}"
    return data


def assert_lab() -> None:
    assets = _csv_rows(OUT / "ciso-assistant" / "assets.csv", ASSETS_H)
    findings = _csv_rows(OUT / "ciso-assistant" / "findings.csv", FIND_H)
    vulns = _csv_rows(OUT / "ciso-assistant" / "vulnerabilities.csv", VULN_H)
    evid = _csv_rows(OUT / "ciso-assistant" / "evidences.csv", EVID_H)
    ctrls = _csv_rows(OUT / "ciso-assistant" / "applied_controls.csv", CONTROLS_H)
    scen = _csv_rows(OUT / "ciso-assistant" / "risk_scenarios.csv", SCEN_H, delim=";")
    from shared.ciso_shape import POAM_HEADER, assert_count_consistency

    poam_h = POAM_HEADER
    poam = _csv_rows(OUT / "poam" / "poam.csv", poam_h)
    sr_path = OUT / "simplerisk" / "poam.csv"
    if sr_path.is_file():
        sr_raw = sr_path.read_text(encoding="utf-8")
        assert sr_raw.splitlines()[0].strip() == poam_h
        assert not any(line.lstrip().startswith("#") for line in sr_raw.splitlines())
        sr = _csv_rows(sr_path, poam_h)
        assert len(sr) == len(poam)
        estate_txt = OUT / "simplerisk" / "ESTATE.txt"
        assert estate_txt.is_file()
        sidecar = estate_txt.read_text(encoding="utf-8")
        assert sidecar.lstrip().startswith("> **")
        assert "CLIENT:" not in sidecar.splitlines()[0]
        assert any(row.get("estate") for row in sr)

    rr_dir = OUT / "riskready"
    assert not rr_dir.exists(), "loader must not write out/riskready"
    assert not any(OUT.rglob("riskready/*")), "no RiskReady JSON leave-behind"
    ocsf = _json(OUT / "ocsf" / "compliance_findings.json")
    summary = _json(OUT / "summary.json")

    assert isinstance(ocsf, list) and ocsf
    assert isinstance(summary, dict)
    assert "incidents" not in summary
    assert "risks_proposed" not in summary

    types = {r["type"] for r in assets}
    assert types <= {"PR", "SP"}, types
    for row in assets + findings:
        labels = row.get("filtering_labels") or ""
        assert labels.strip() == labels
        assert " ," not in labels and ", " != labels
        assert not any(part == "" or part.isspace() for part in labels.split(",") if labels)
        assert ":" not in labels, labels
    for row in findings:
        assert row["severity"] in FIND_SEV, row
    for row in vulns:
        assert row["severity"] in VULN_SEV, row
    for row in ocsf:
        assert row.get("class_uid") == 2003

    assert_count_consistency(OUT, summary)
    assert int(summary.get("risk_scenarios") or 0) == len(scen)
    assert int(summary.get("poam") or 0) == len(poam)
    assert int(summary.get("weaknesses") or 0) == len(findings) + len(vulns)
    assert int(summary.get("open_risks") or 0) == len(poam)

    assert len(assets) >= 20, len(assets)
    assert len(findings) >= 20, len(findings)
    assert len(evid) >= 18, len(evid)
    names = [row["name"] for row in evid]
    assert len(names) == len(set(names)), "evidence names must be unique"
    assert vulns, "vulnerabilities.csv empty"
    assert ctrls and scen
    assert poam, "poam.csv empty"
    assert (OUT / "poam" / "poam.md").is_file()
    excluded_path = OUT / "poam" / "excluded.csv"
    assert excluded_path.is_file(), "poam/excluded.csv missing"
    excluded = _csv_rows(
        excluded_path, "finding_ref_id,weakness,asset,severity,excluded_reason"
    )
    assert int(summary.get("excluded") or 0) == len(excluded)
    assert int(summary.get("weaknesses_total") or 0) == len(poam) + len(excluded)
    md = (OUT / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "Pentera" not in md
    assert "excluded.csv" in md.lower() or "excluded" in md.lower()
    assert "15" in md and "30" in md and "90" in md and "180" in md
    assert "Evergreen default" in md
    exec_sum = OUT / "EXECUTIVE_SUMMARY.md"
    trust = OUT / "SCOPE_AND_TRUST.md"
    if exec_sum.is_file() and trust.is_file():
        exec_text = exec_sum.read_text(encoding="utf-8")
        trust_text = trust.read_text(encoding="utf-8")
        assert exec_text.startswith("> **")
        assert trust_text.startswith("> **")
        assert "not recorded" in trust_text or "Authorization" in trust_text
        assert "CoS #" not in exec_text and "CoS #" not in trust_text
    estate_txt = OUT / "ciso-assistant" / "ESTATE.txt"
    if estate_txt.is_file():
        assert (OUT / "poam" / "ESTATE.txt").is_file()
        assert not (OUT / "ciso-assistant" / "findings.csv").read_text(
            encoding="utf-8"
        ).lstrip().startswith("#")
    smb = [r for r in poam if "SMB" in (r.get("weakness") or "") or "445" in (r.get("recommended_fix") or "")]
    assert smb, "SMB/445 exposure must map into POA&M"
    rdp = [r for r in poam if "RDP" in (r.get("weakness") or "") or "3389" in (r.get("recommended_fix") or "")]
    assert rdp, "open RDP must map into POA&M"
    tls = [
        r
        for r in poam
        if "TLS" in (r.get("weakness") or "")
        or "cipher" in (r.get("recommended_fix") or "").lower()
    ]
    assert tls, "TLS weak cipher / TLS posture must map into POA&M"
    shares = [
        r
        for r in poam
        if "admin share" in (r.get("weakness") or "").lower()
        or "C$" in (r.get("recommended_fix") or "")
        or "ADMIN$" in (r.get("recommended_fix") or "")
    ]
    assert shares, "admin shares (C$/ADMIN$) must map into POA&M"
    telnet = [r for r in poam if "Telnet" in (r.get("weakness") or "") or "23" in (r.get("recommended_fix") or "")]
    assert telnet, "Telnet/23 exposure must map into POA&M"
    for row in smb + rdp + tls + shares:
        refs = row.get("framework_refs") or ""
        assert "csf_" in refs
        assert "CVE-" not in (row.get("recommended_fix") or "")
        assert (row.get("owner") or "") == ""
        assert (row.get("due") or "") == ""
    for row in rdp + shares:
        assert "cpg_2_W" in (row.get("framework_refs") or "")
    exposure_smb = [
        r
        for r in smb
        if "null" not in (r.get("weakness") or "").lower()
        and (
            "445" in (r.get("recommended_fix") or "")
            or "file sharing" in (r.get("weakness") or "").lower()
        )
    ]
    assert exposure_smb, "open-port SMB exposure must remain on the POA&M"
    for row in exposure_smb:
        assert "cpg_2_W" in (row.get("framework_refs") or "")
    for row in smb:
        assert "csf_PR" in (row.get("framework_refs") or "") or "csf_protect" in (row.get("framework_refs") or "")
        fix = (row.get("recommended_fix") or "").lower()
        weak = (row.get("weakness") or "").lower()
        assert (
            "dialect" in fix
            or "port" in fix
            or "null" in fix
            or "null" in weak
        ), (weak, fix)
    for row in poam:
        assert (row.get("owner") or "") == ""
        assert (row.get("due") or "") == ""
        assert row.get("status") == "open"
        assert row.get("severity") in FIND_SEV
        refs = row.get("framework_refs") or ""
        assert ":" not in refs
        assert "csf_" in refs
        # CPG is derived from 800-53 (CM-7/SC-7 → 2_W, CM-8 → 1_E) or omitted.
    high_findings = [r for r in findings if r["severity"] in {"high", "critical"}]
    for row in high_findings:
        labels = row.get("filtering_labels") or ""
        assert "csf_" in labels, row
    smb_ctrl = [r for r in ctrls if "SMB" in (r.get("name") or "") or "445" in (r.get("description") or "")]
    assert smb_ctrl, "applied_controls must include SMB hardening narrative"

    blob = ""
    for path in OUT.rglob("*"):
        if path.is_file() and path.suffix in {".csv", ".json", ".jsonl", ".md"}:
            blob += path.read_text(encoding="utf-8", errors="replace")
    assert not LIVE_KEY.search(blob), "live-looking key in outputs"

    for script in (ROOT / "push_ciso.sh", ROOT / "push_riskready.sh"):
        text = script.read_text(encoding="utf-8")
        assert not re.search(r"curl[^\n]*/api/risks", text)
        assert "${API}/risks" not in text
    rr = (ROOT / "push_riskready.sh").read_text(encoding="utf-8")
    assert "curl" not in rr
    assert "/api/auth/login" not in rr
    assert "/itsm/assets" not in rr

    # demo path: collectors must not open sockets — static check
    collectors = (ROOT / "collectors").read_text if False else None
    del collectors
    for py in (ROOT / "collectors").glob("*.py"):
        src = py.read_text(encoding="utf-8")
        assert "socket.socket" not in src
        assert "urllib.request" not in src
        assert "http.client" not in src


def test_lab_outputs() -> None:
    if not (OUT / "summary.json").exists():
        return
    assert_lab()


if __name__ == "__main__":
    assert_lab()
    print("lab_outputs: PASS")
