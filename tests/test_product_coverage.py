"""CONSOLE_COVERAGE: controls + scenarios + framework_refs heatmap."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from product.server import (
    annotate_evidence_row,
    classify_framework_token,
    estate,
    evidence_rows,
    framework_coverage,
    make_server,
    payload,
    split_ref_tokens,
)

ROOT = Path(__file__).resolve().parents[1]
LAB_OUT = ROOT / "fixtures" / "lab-drop-out"
DROP_CISO = ROOT / "product-lab" / "drop" / "ciso"
CONTROLS_H = "ref_id,name,description,domain,status,category,priority,csf_function"
SCENARIO_H = (
    "ref_id;assets;threats;name;description;existing_controls;current_impact;"
    "current_proba;current_risk;additional_controls;residual_impact;"
    "residual_proba;residual_risk;treatment"
)
POAM_HEADER = "weakness,asset,severity,framework_refs,recommended_fix,owner,due,status"
FINDINGS_H = "ref_id,name,description,severity,status,filtering_labels"


def _write_estate(
    dest: Path,
    *,
    poam: list[str] | None = None,
    findings: list[str] | None = None,
    controls: list[str] | None = None,
    scenarios: list[str] | None = None,
    evidences: list[str] | None = None,
    lab_report: str | None = None,
) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "summary.json").write_text(
        json.dumps(
            {
                "demo": True,
                "lab": True,
                "sample": False,
                "client": False,
                "seeded": False,
                "use_existing_in": True,
                "canonical": 4,
                "assets": 4,
                "findings": 2,
                "applied_controls": len(controls or []),
                "risk_scenarios": len(scenarios or []),
                "poam": len(poam or []),
                "evidences": 1,
            }
        ),
        encoding="utf-8",
    )
    (dest / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    ciso = dest / "ciso-assistant"
    ciso.mkdir(parents=True, exist_ok=True)
    (dest / "poam").mkdir(parents=True, exist_ok=True)
    (dest / "poam" / "poam.csv").write_text(
        POAM_HEADER + "\n" + "\n".join(poam or []) + ("\n" if poam else ""),
        encoding="utf-8",
    )
    (ciso / "findings.csv").write_text(
        FINDINGS_H + "\n" + "\n".join(findings or []) + ("\n" if findings else ""),
        encoding="utf-8",
    )
    (ciso / "applied_controls.csv").write_text(
        CONTROLS_H + "\n" + "\n".join(controls or []) + ("\n" if controls else ""),
        encoding="utf-8",
    )
    (ciso / "risk_scenarios.csv").write_text(
        SCENARIO_H + "\n" + "\n".join(scenarios or []) + ("\n" if scenarios else ""),
        encoding="utf-8",
    )
    (ciso / "evidences.csv").write_text(
        "name,description\n" + "\n".join(evidences or []) + ("\n" if evidences else ""),
        encoding="utf-8",
    )
    if lab_report is not None:
        ev = dest / "evidence"
        ev.mkdir(parents=True, exist_ok=True)
        (ev / "lab-report.md").write_text(lab_report, encoding="utf-8")
    return dest


@pytest.fixture
def coverage_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    out = tmp_path / "out"
    _write_estate(
        out,
        poam=[
            'Critical SMB,host-a,critical,"cpg_2_W,csf_RS,csf_respond",Close 445,,,open',
            "CIS leftover,host-b,high,cis_5_1,Harden share,,,open",
            "ISO leftover,host-c,medium,iso_27001_A5,Review policy,,,open",
        ],
        findings=[
            'F-1,Telnet,LAB exposure,high,open,"LAB,cpg_2_W,csf_PR,nist_csf"',
            "F-2,FTP,LAB exposure,medium,open,LAB",
            "F-3,CIS-CAT leftover,sensor label only,low,open,cis-cat",
        ],
        controls=[
            "CTL-smb,Restrict SMB,Close 445,Global,to_do,technical,1,protect",
            "CTL-telnet,Disable Telnet,Limit listener,Global,to_do,technical,2,identify",
        ],
        scenarios=[
            "RSK-1;host-a;exposure;SMB;LAB;;Very High;Very High;Very High;CTL-smb;High;High;High;mitigate",
            "RSK-2;host-b;exposure;Telnet;LAB;;High;High;High;CTL-telnet;Moderate;Moderate;Moderate;mitigate",
        ],
        evidences=["grc-loader run,Normalized records. See lab-report.md"],
        lab_report="# Lab report\n\nNo /api/risks POST.\n",
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    return out


def test_split_and_classify_framework_tokens() -> None:
    assert split_ref_tokens('cpg_2_W,csf_PR,csf_protect') == [
        "cpg_2_W",
        "csf_PR",
        "csf_protect",
    ]
    assert split_ref_tokens("cis_5_1; iso_27001_A5 nist_csf") == [
        "cis_5_1",
        "iso_27001_A5",
        "nist_csf",
    ]
    assert classify_framework_token("cpg_2_W") == "cisa_cpg"
    assert classify_framework_token("cisa_cpg") == "cisa_cpg"
    assert classify_framework_token("csf_PR") == "nist_csf"
    assert classify_framework_token("protect") == "nist_csf"
    assert classify_framework_token("cis_5_1") == "cis"
    assert classify_framework_token("cis-1.1") == "cis"
    assert classify_framework_token("iso_27001_A5") == "iso"
    assert classify_framework_token("LAB") is None
    assert classify_framework_token("cloud") is None
    assert classify_framework_token("cis-cat") is None
    assert classify_framework_token("nist:csf") is None


def test_framework_coverage_groups_poam_findings_controls(coverage_out: Path) -> None:
    rollup = framework_coverage(coverage_out)
    assert rollup["client"] is False
    assert rollup["controls"] == 2
    assert rollup["scenarios"] == 2
    assert rollup["poam_rows"] == 3
    assert rollup["sources"]["poam"] >= 3
    assert rollup["sources"]["findings"] >= 1
    assert rollup["sources"]["controls"] == 2
    fam = rollup["families"]
    assert fam["cisa_cpg"]["rows"] >= 1
    assert fam["nist_csf"]["rows"] >= 1
    assert fam["cis"]["rows"] == 1
    assert fam["iso"]["rows"] == 1
    by_token = {row["token"]: row for row in rollup["tokens"]}
    assert by_token["cpg_2_W"]["poam"] >= 1
    assert by_token["cpg_2_W"]["findings"] >= 1
    assert by_token["csf_PR"]["controls"] >= 1
    assert by_token["cis_5_1"]["family"] == "cis"
    assert by_token["iso_27001_A5"]["family"] == "iso"
    assert "cis-cat" not in by_token
    assert all(row["total"] >= 1 for row in rollup["tokens"])


def test_lab_drop_out_coverage_from_real_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OUT_DIR", str(LAB_OUT))
    header = (LAB_OUT / "poam" / "poam.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.strip() == POAM_HEADER
    scen_h = (LAB_OUT / "ciso-assistant" / "risk_scenarios.csv").read_text(
        encoding="utf-8"
    ).splitlines()[0]
    assert scen_h.startswith("ref_id;assets;threats")
    ctrl_h = (LAB_OUT / "ciso-assistant" / "applied_controls.csv").read_text(
        encoding="utf-8"
    ).splitlines()[0]
    assert ctrl_h.strip() == CONTROLS_H
    data = estate()
    assert data["lab"] is True
    assert data["client"] is False
    assert data["refresh_mode"] == "reload"
    assert data["safety"]["posts_api_risks"] is False
    cov = data["coverage"]
    assert cov["client"] is False
    assert cov["scenarios"] == 3
    assert cov["controls"] == 0
    assert cov["families"]["cisa_cpg"]["rows"] == 3
    assert cov["families"]["nist_csf"]["rows"] == 3
    tokens = {row["token"] for row in cov["tokens"]}
    assert "cpg_2_W" in tokens
    assert "csf_PR" in tokens or "csf_RS" in tokens
    scenarios = payload("scenarios")
    assert len(scenarios) == 3
    assert scenarios[0]["ref_id"].startswith("RSK-")
    assert "current_risk" in scenarios[0]
    controls = payload("controls")
    assert controls == []
    rows = evidence_rows(LAB_OUT)
    assert rows
    assert rows[0]["path"] == "evidence/lab-report.md"
    assert int(rows[0]["bytes"] or 0) > 0
    assert rows[0]["size"]


def test_product_lab_drop_controls_and_scenarios_headers() -> None:
    controls = (DROP_CISO / "applied_controls.csv").read_text(encoding="utf-8")
    assert controls.splitlines()[0].strip() == CONTROLS_H
    assert "csf_function" in controls.splitlines()[0]
    scenarios = (DROP_CISO / "risk_scenarios.csv").read_text(encoding="utf-8")
    assert scenarios.splitlines()[0].startswith("ref_id;assets")
    assert ";" in scenarios.splitlines()[1]


def test_estate_coverage_keeps_honesty_and_client_false(coverage_out: Path) -> None:
    data = estate()
    assert data["lab"] is True
    assert data["sample"] is False
    assert data["demo"] is True
    assert data["client"] is False
    assert data["seeded"] is False
    assert data["use_existing_in"] is True
    assert data["refresh_mode"] == "reload"
    assert "LAB" in data["honesty_label"]
    assert data["safety"]["posts_api_risks"] is False
    assert data["poam"]["open"] == 3
    assert data["coverage"]["controls"] == 2
    assert data["coverage"]["scenarios"] == 2
    assert data["coverage"]["client"] is False


def test_evidence_path_size_from_out_evidence(coverage_out: Path) -> None:
    rows = evidence_rows(coverage_out)
    assert len(rows) == 1
    assert rows[0]["path"] == "evidence/lab-report.md"
    assert int(rows[0]["bytes"] or 0) > 10
    assert "B" in rows[0]["size"] or "KiB" in rows[0]["size"]
    annotated = annotate_evidence_row(
        {"name": "other", "description": "no file"},
        [{"name": "lab-report.md", "path": "evidence/lab-report.md", "bytes": 12, "size": "12 B"}],
    )
    assert annotated["path"] == "evidence/lab-report.md"


def test_http_controls_scenarios_coverage(coverage_out: Path) -> None:
    httpd = make_server("127.0.0.1", 0)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://{host}:{port}"
        with urllib.request.urlopen(base + "/api/summary", timeout=5) as res:
            summary = json.loads(res.read().decode("utf-8"))
            assert res.status == 200
        assert summary["client"] is False
        assert summary["lab"] is True
        assert summary["refresh_mode"] == "reload"
        assert summary["safety"]["posts_api_risks"] is False
        assert summary["poam"]["open"] == 3
        assert summary["coverage"]["controls"] == 2
        assert summary["coverage"]["scenarios"] == 2
        assert summary["coverage"]["families"]["cis"]["rows"] == 1
        with urllib.request.urlopen(base + "/api/coverage", timeout=5) as res:
            dedicated = json.loads(res.read().decode("utf-8"))
        assert dedicated["client"] is False
        assert dedicated["lab"] is True
        assert dedicated["controls"] == 2
        assert dedicated["scenarios"] == 2
        assert any(row["token"] == "cpg_2_W" for row in dedicated["tokens"])
        with urllib.request.urlopen(base + "/api/controls", timeout=5) as res:
            controls = json.loads(res.read().decode("utf-8"))
        assert [row["ref_id"] for row in controls] == ["CTL-smb", "CTL-telnet"]
        assert controls[0]["csf_function"] == "protect"
        with urllib.request.urlopen(base + "/api/scenarios", timeout=5) as res:
            scenarios = json.loads(res.read().decode("utf-8"))
        assert len(scenarios) == 2
        assert scenarios[0]["treatment"] == "mitigate"
        assert scenarios[0]["current_risk"] == "Very High"
        with urllib.request.urlopen(base + "/api/evidences", timeout=5) as res:
            evidences = json.loads(res.read().decode("utf-8"))
        assert evidences[0]["path"] == "evidence/lab-report.md"
        assert evidences[0]["bytes"]
        with urllib.request.urlopen(base + "/", timeout=5) as res:
            html = res.read().decode("utf-8")
        assert 'data-tab="controls"' in html
        assert 'data-tab="scenarios"' in html
        assert 'data-tab="coverage"' in html
        assert 'id="coverage-kpis"' in html
        assert 'id="coverage-heat"' in html
        assert 'id="lab-pill"' in html
        assert 'id="run-picker"' in html
        assert 'id="poam-kpis"' in html
        assert "Never POSTs /api/risks" in html
        try:
            urllib.request.urlopen(base + "/api/risks", timeout=5)
            raise AssertionError("GET /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
            body = json.loads(exc.read().decode("utf-8"))
            assert body["posted"] is False
        req = urllib.request.Request(base + "/api/risks", data=b"{}", method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("POST /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ui_hooks_controls_scenarios_coverage() -> None:
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="controls"' in html
    assert ">Controls<" in html
    assert 'data-tab="scenarios"' in html
    assert ">Scenarios<" in html
    assert 'data-tab="coverage"' in html
    assert ">Coverage<" in html
    assert 'id="coverage-kpis"' in html
    assert 'id="coverage-heat"' in html
    assert 'id="coverage-sensors"' in html
    assert "framework_refs" in html
    assert "applied_controls.csv" in html
    assert "risk_scenarios.csv" in html
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert '"/api/controls"' in js
    assert '"/api/scenarios"' in js
    assert '"/api/coverage"' in js
    assert "renderCoverageKpis" in js
    assert "renderCoverageHeat" in js
    assert "renderCoverageSensors" in js
    assert "heatClass" in js
    assert '["csf_function", "CSF"]' in js
    assert '["current_risk", "Risk"]' in js
    assert '["path", "Path"]' in js
    assert '["size", "Size"]' in js
    assert "/api/risks" not in js
    css = (ROOT / "product" / "static" / "app.css").read_text(encoding="utf-8")
    assert "heat-4" in css
    assert "coverage-heat" in css


def test_docs_name_coverage_endpoints() -> None:
    docs = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "/api/controls" in docs
    assert "/api/scenarios" in docs
    assert "/api/coverage" in docs
    assert "framework_refs" in docs
    assert "python -m product" in docs
    assert "/api/risks" in docs
    op = (ROOT / "product-lab" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "/api/coverage" in op
    assert "applied_controls.csv" in op
    assert "Never POSTs /api/risks" in (
        ROOT / "product" / "static" / "index.html"
    ).read_text(encoding="utf-8")


def test_brick_a_b_c_still_present() -> None:
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'id="lab-pill"' in html
    assert 'id="sample-pill"' in html
    assert 'id="demo-pill"' in html
    assert "client=false" in html
    assert 'id="run-picker"' in html
    assert "Active out/" in html
    assert 'id="poam-kpis"' in html
    assert "POA&M triage" in html
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert "applyHonesty" in js
    assert "loadRuns" in js
    assert "Reload from disk" in js
    assert "renderPoamKpis" in js
    assert "blank_owner" in js
    src = (ROOT / "product" / "server.py").read_text(encoding="utf-8")
    assert "derive_honesty" in src
    assert "list_runs" in src
    assert "poam_summary" in src
    assert "framework_coverage" in src
    assert "posts_api_risks" in src
    assert 'POST "/api/risks"' not in src
    assert "client" in src
