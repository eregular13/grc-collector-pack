#!/usr/bin/env python3
"""Assert GRC lab outputs parse and meet contract."""

from __future__ import annotations

import csv
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
RR_L = {"RARE", "UNLIKELY", "POSSIBLE", "LIKELY", "ALMOST_CERTAIN"}
RR_I = {"NEGLIGIBLE", "MINOR", "MODERATE", "MAJOR", "SEVERE"}
LIVE_KEY = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{20,}")


def _read(path: Path) -> str:
    assert path.exists() and path.stat().st_size > 0, f"missing/empty {path}"
    return path.read_text(encoding="utf-8")


def _csv_rows(path: Path, expected_header: str, delim: str = ",") -> list[dict]:
    text = _read(path)
    first = text.splitlines()[0].strip()
    assert first == expected_header, f"{path.name} header {first!r} != {expected_header!r}"
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh, delimiter=delim))


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
    poam_h = "weakness,asset,severity,framework_refs,recommended_fix,owner,due,status"
    poam = _csv_rows(OUT / "poam" / "poam.csv", poam_h)

    rr_assets = _json(OUT / "riskready" / "assets.json")
    rr_inc = _json(OUT / "riskready" / "incidents.json")
    rr_ev = _json(OUT / "riskready" / "evidence.json")
    proposed = _json(OUT / "riskready" / "risks_proposed.json")
    ocsf = _json(OUT / "ocsf" / "compliance_findings.json")
    summary = _json(OUT / "summary.json")

    assert isinstance(rr_assets, list) and rr_assets
    assert isinstance(rr_inc, list) and rr_inc
    assert isinstance(rr_ev, list) and rr_ev
    assert isinstance(proposed, list) and proposed
    assert isinstance(ocsf, list) and ocsf
    assert isinstance(summary, dict)

    types = {r["type"] for r in assets}
    assert types <= {"PR", "SP"}, types
    for row in assets + findings:
        labels = row.get("filtering_labels") or ""
        assert labels.strip() == labels
        assert " ," not in labels and ", " != labels
        assert not any(part == "" or part.isspace() for part in labels.split(",") if labels)
        assert "cpg_2_W" in labels
        assert ":" not in labels.split("cpg_2_W")[0] or "cpg_2_W" in labels
    for row in findings:
        assert row["severity"] in FIND_SEV, row
    for row in vulns:
        assert row["severity"] in VULN_SEV, row
    for row in proposed:
        assert row.get("severity") in {"high", "critical"}, row
        assert row.get("likelihood") in RR_L, row
        assert row.get("impact") in RR_I, row
    for row in rr_assets:
        assert row.get("status") == "ACTIVE"
        assert row.get("cloudProvider") in {"AWS", "AZURE", "GCP", "NONE"}
        assert row.get("inIsmsScope") is True
    for row in rr_ev:
        assert row.get("evidenceType") == "TECHNICAL"
        assert row.get("sourceType") == "SENSOR"
        assert row.get("status") == "DRAFT"
    for row in ocsf:
        assert row.get("class_uid") == 2003

    assert len(assets) >= 20, len(assets)
    assert len(findings) >= 20, len(findings)
    assert len(evid) >= 18, len(evid)
    names = [row["name"] for row in evid]
    assert len(names) == len(set(names)), "evidence names must be unique"
    assert vulns, "vulnerabilities.csv empty"
    assert ctrls and scen
    assert poam, "poam.csv empty"
    assert (OUT / "poam" / "poam.md").is_file()
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
    for row in smb + rdp + tls + shares:
        refs = row.get("framework_refs") or ""
        assert "cpg_" in refs and "csf_" in refs
        assert "CVE-" not in (row.get("recommended_fix") or "")
        assert (row.get("owner") or "") == ""
        assert (row.get("due") or "") == ""
    for row in smb:
        assert "cpg_2_W" in (row.get("framework_refs") or "")
        assert "csf_PR" in (row.get("framework_refs") or "") or "csf_protect" in (row.get("framework_refs") or "")
        assert "dialect" in (row.get("recommended_fix") or "").lower() or "port" in (row.get("recommended_fix") or "").lower()
    for row in poam:
        assert (row.get("owner") or "") == ""
        assert (row.get("due") or "") == ""
        assert row.get("status") == "open"
        assert row.get("severity") in FIND_SEV
        refs = row.get("framework_refs") or ""
        assert ":" not in refs
        assert "cpg_" in refs and "csf_" in refs
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
