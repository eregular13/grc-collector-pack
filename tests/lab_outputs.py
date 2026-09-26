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
EXCLUDED_SEV = FIND_SEV | {"info"}
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
    from shared.ciso_shape import EXCLUDED_HEADER, POAM_HEADER, assert_count_consistency

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
    excluded = _csv_rows(excluded_path, EXCLUDED_HEADER)
    assert excluded, "DEMO/lab excluded.csv must not be header-only"
    assert int(summary.get("excluded") or 0) == len(excluded)
    assert int(summary.get("weaknesses_total") or 0) == len(poam) + len(excluded)
    reasons = {str(row.get("excluded_reason") or "") for row in excluded}
    assert reasons & {"honeypot", "severity_info"}, reasons
    for row in excluded:
        assert row.get("severity") in EXCLUDED_SEV, row
        if row.get("excluded_reason") == "severity_info":
            assert row.get("severity") == "info", row
    md = (OUT / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "Pentera" not in md
    assert "excluded.csv" in md.lower() or "excluded" in md.lower()
    assert "15" in md and "30" in md and "90" in md and "180" in md
    assert "Evergreen default" in md
    assert "Vendor Dependency = No is a default, not a verified determination" in md
    exec_sum = OUT / "EXECUTIVE_SUMMARY.md"
    trust = OUT / "SCOPE_AND_TRUST.md"
    if exec_sum.is_file() and trust.is_file():
        exec_text = exec_sum.read_text(encoding="utf-8")
        trust_text = trust.read_text(encoding="utf-8")
        assert exec_text.startswith("> **")
        assert trust_text.startswith("> **")
        assert "not recorded" in trust_text or "Authorization" in trust_text
        assert "CoS #" not in exec_text and "CoS #" not in trust_text
        assert "### Coverage gaps" in exec_text and "### Coverage gaps" in trust_text
        from shared.estate_pages import assert_client_export_honesty

        assert_client_export_honesty(OUT)
    estate_txt = OUT / "ciso-assistant" / "ESTATE.txt"
    if estate_txt.is_file():
        assert (OUT / "poam" / "ESTATE.txt").is_file()
        assert not (OUT / "ciso-assistant" / "findings.csv").read_text(
            encoding="utf-8"
        ).lstrip().startswith("#")
    fed = OUT / "poam" / "poam_fedramp.csv"
    if fed.is_file():
        from shared.poam_fedramp import FEDRAMP_CSV_HEADERS, FEDRAMP_OPEN_HEADERS

        fed_rows = _csv_rows(fed, ",".join(FEDRAMP_CSV_HEADERS))
        assert ",".join(FEDRAMP_CSV_HEADERS).startswith(",".join(FEDRAMP_OPEN_HEADERS))
        for row in fed_rows:
            vd = row.get("Vendor Dependency") or ""
            assert vd in {"Yes", "No"}, vd
            if vd == "No":
                assert not (row.get("Last Vendor Check-in Date") or "").strip()
                assert not (row.get("Vendor Dependent Product Name") or "").strip()
                comments = row.get("Comments") or ""
                assert (
                    "default, not verified" in comments
                    or "no fix available" in comments.lower()
                ), comments
            else:
                product = (row.get("Vendor Dependent Product Name") or "").strip()
                assert product and product.lower() not in {"n/a", "none"}
        closed = OUT / "poam" / "poam_fedramp_closed.csv"
        if closed.is_file():
            first = closed.read_text(encoding="utf-8").splitlines()[0]
            assert not first.lstrip().startswith("#"), "poam_fedramp_closed.csv header-first"
            closed_rows = _csv_rows(closed, ",".join(FEDRAMP_CSV_HEADERS))
            assert not any(
                (r.get("Vendor Dependency") or "").strip() == "Yes" for r in closed_rows
            ), "spec §2.2: vendor-dependent Yes stays off the Closed tab"
        for rel in ("poam-ledger.json", "kev_provenance.json"):
            path = OUT / "poam" / rel
            if path.is_file():
                blob = path.read_text(encoding="utf-8").lstrip()
                assert blob[:1] in "{[", rel
                assert not blob.startswith("#")
    for row in poam:
        det = (row.get("original_detection_date") or "").strip()
        assert det == "not recorded" or (
            len(det) == 10 and det[4] == "-" and det[7] == "-"
        ), det
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
        refs = row.get("framework_refs") or ""
        assert "cpg_3_I" in refs or "cpg_3_S" in refs or "cpg_" in refs
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
        refs_smb = row.get("framework_refs") or ""
        # DEMO SMB is on .corp.local / RFC1918 — 3.I, not 3.S.
        assert "cpg_3_I" in refs_smb, refs_smb
        assert "cpg_3_S" not in refs_smb
    for row in smb:
        refs = row.get("framework_refs") or ""
        assert "csf_PR_IR_01" in refs or "csf_PR_AA_05" in refs or "csf_PR_DS_02" in refs
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
        # CSF is a 2.0 subcategory stamp (csf_PR_IR_01), never a function catch-all.
        assert "csf_PR," not in refs + "," and not refs.endswith("csf_PR")
        assert "csf_protect" not in refs
    high_findings = [r for r in findings if r["severity"] in {"high", "critical"}]
    for row in high_findings:
        labels = row.get("filtering_labels") or ""
        assert "csf_" in labels, row
        assert "csf_PR," not in labels + "," and not labels.endswith("csf_PR")
        assert "csf_protect" not in labels
    for row in assets:
        labels = row.get("filtering_labels") or ""
        assert "cpg_2_W" not in labels
        assert "cpg_1_E" not in labels
        assert "csf_PR," not in labels + "," and not labels.endswith("csf_PR")
        assert "csf_protect" not in labels
    smb_ctrl = [r for r in ctrls if "SMB" in (r.get("name") or "") or "445" in (r.get("description") or "")]
    assert smb_ctrl, "applied_controls must include SMB hardening narrative"

    redis = [
        r
        for r in vulns
        if "Redis without auth" in (r.get("name") or "")
        or "exposed-redis" in (r.get("ref_id") or "")
    ]
    assert len(redis) == 3, [r.get("assets") for r in redis]
    redis_hosts = set()
    for row in redis:
        redis_hosts.update(part for part in str(row.get("assets") or "").split("|") if part)
    assert redis_hosts >= {
        "https://redis-a.lab.internal",
        "https://redis-b.lab.internal",
        "https://redis-c.lab.internal",
    }

    priv_findings = [r for r in findings if "privileged" in (r.get("name") or "").lower()]
    assert priv_findings, "privileged weakness must remain on the register"
    priv_labels = " ".join(r.get("filtering_labels") or "" for r in priv_findings)
    assert "falco" in priv_labels, priv_labels
    assert "kubescape" in priv_labels, priv_labels
    priv_poam = [r for r in poam if "privileged" in (r.get("weakness") or "").lower()]
    assert priv_poam
    det = " ".join(r.get("detector_source") or "" for r in priv_poam)
    assert "falco" in det and "kubescape" in det, det

    from shared.framework_class_map import csf_cpg_tag_set

    csf_counts: dict[str, int] = {}
    cpg_goals: set[str] = set()
    for row in poam:
        csf, cpg = csf_cpg_tag_set(row.get("framework_refs") or "")
        for tok in csf:
            csf_counts[tok] = csf_counts.get(tok, 0) + 1
        cpg_goals.update(t for t in cpg if t != "cpg_unmapped")
    n_poam = len(poam)
    assert n_poam, "lab POA&M is empty"
    if csf_counts:
        top_tok, top_n = max(csf_counts.items(), key=lambda kv: kv[1])
        share = top_n / n_poam
        assert share <= 0.40, (
            f"honest CSF tag {top_tok} covers {top_n}/{n_poam}={share:.1%} of lab "
            f"POA&M (cap 40%). distribution={csf_counts}"
        )
    assert len(cpg_goals) >= 5, (
        f"lab POA&M must carry ≥5 distinct CPG 2.0 goals; got {sorted(cpg_goals)}"
    )

    if fed.is_file():
        import csv as _csv

        ledger_path = OUT / "poam" / "poam-ledger.json"
        if ledger_path.is_file():
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            by_ref = {
                str(item.get("ref_id") or ""): item
                for item in (ledger.get("items") or {}).values()
            }
            with fed.open(encoding="utf-8", newline="") as fh:
                fed_rows = list(_csv.DictReader(fh))
            fed_by_id = {r.get("POAM ID") or "": r for r in fed_rows}
            poam_by_ref = {r.get("finding_ref_id") or "": r for r in poam}
            for ref, prow in poam_by_ref.items():
                item = by_ref.get(ref)
                if not item:
                    continue
                egp = str(item.get("poam_id") or "")
                frow = fed_by_id.get(egp)
                if not frow:
                    continue
                a = csf_cpg_tag_set(prow.get("framework_refs") or "")
                b = csf_cpg_tag_set(frow.get("Framework Tags") or "")
                assert a == b, (egp, ref, a, b)

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
