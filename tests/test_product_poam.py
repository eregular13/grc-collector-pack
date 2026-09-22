"""CONSOLE_POAM_DASH: POA&M KPIs + blank owner/due highlight data path."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from product.server import (
    annotate_poam_row,
    estate,
    make_server,
    poam_rows,
    poam_summary,
    sort_poam_rows,
)

ROOT = Path(__file__).resolve().parents[1]
LAB_OUT = ROOT / "fixtures" / "lab-drop-out"
DROP_POAM = ROOT / "product-lab" / "drop" / "poam" / "poam.csv"
POAM_HEADER = "weakness,asset,severity,framework_refs,recommended_fix,owner,due,status"


def _write_poam(dest: Path, rows: list[str]) -> Path:
    poam = dest / "poam"
    poam.mkdir(parents=True, exist_ok=True)
    path = poam / "poam.csv"
    path.write_text(POAM_HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def _mixed_rows() -> list[str]:
    return [
        "Low leftover,host-d,low,csf_PR,Patch later,,,open",
        "Medium exposure,host-c,medium,csf_PR,Restrict listener,ops,2026-10-01,open",
        "Closed high,host-b,high,csf_PR,Already fixed,soc,2026-09-01,closed",
        "Critical SMB,host-a,critical,csf_RS,Close 445,,,open",
    ]


@pytest.fixture
def mixed_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text(
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
                "findings": 4,
                "poam": 4,
            }
        ),
        encoding="utf-8",
    )
    (out / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    _write_poam(out, _mixed_rows())
    monkeypatch.setenv("OUT_DIR", str(out))
    return out


def test_poam_summary_counts_open_severity_and_blanks(mixed_out: Path) -> None:
    rollup = poam_summary(mixed_out)
    assert rollup["total"] == 4
    assert rollup["open"] == 3
    assert rollup["critical"] == 1
    assert rollup["high"] == 1
    assert rollup["medium"] == 1
    assert rollup["low"] == 1
    assert rollup["severity"]["critical"] == 1
    assert rollup["blank_owner"] == 2
    assert rollup["blank_due"] == 2
    assert rollup["owner_due_blank_for_human"] is True


def test_poam_rows_sort_critical_high_first_and_flag_blanks(mixed_out: Path) -> None:
    rows = poam_rows(mixed_out)
    assert [r["severity"] for r in rows] == ["critical", "high", "medium", "low"]
    crit = rows[0]
    assert crit["weakness"] == "Critical SMB"
    assert crit["blank_owner"] is True
    assert crit["blank_due"] is True
    assert crit["open"] is True
    medium = next(r for r in rows if r["severity"] == "medium")
    assert medium["blank_owner"] is False
    assert medium["blank_due"] is False
    assert medium["owner"] == "ops"
    closed = next(r for r in rows if r["status"] == "closed")
    assert closed["open"] is False
    assert closed["blank_owner"] is False


def test_annotate_and_sort_helpers_do_not_fill_owner_due() -> None:
    raw = {
        "weakness": "RDP",
        "asset": "host-x",
        "severity": "high",
        "owner": "",
        "due": "   ",
        "status": "open",
    }
    flagged = annotate_poam_row(raw)
    assert flagged["blank_owner"] is True
    assert flagged["blank_due"] is True
    assert flagged["owner"] == ""
    assert flagged["due"] == "   "
    ordered = sort_poam_rows(
        [
            {"severity": "low", "weakness": "z"},
            {"severity": "critical", "weakness": "a"},
            {"severity": "high", "weakness": "b"},
        ]
    )
    assert [r["severity"] for r in ordered] == ["critical", "high", "low"]


def test_estate_poam_keeps_honesty_and_client_false(mixed_out: Path) -> None:
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
    assert data["poam"]["blank_owner"] == 2
    assert data["poam"]["blank_due"] == 2
    assert data["poam"]["owner_due_blank_for_human"] is True


def test_lab_drop_out_poam_kpis_all_blank_for_human(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (LAB_OUT / "poam" / "poam.csv").is_file()
    header = (LAB_OUT / "poam" / "poam.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.strip() == POAM_HEADER
    monkeypatch.setenv("OUT_DIR", str(LAB_OUT))
    data = estate()
    assert data["lab"] is True
    assert data["client"] is False
    assert data["refresh_mode"] == "reload"
    rollup = data["poam"]
    assert rollup["total"] == 3
    assert rollup["open"] == 3
    assert rollup["critical"] == 1
    assert rollup["high"] == 1
    assert rollup["medium"] == 1
    assert rollup["blank_owner"] == 3
    assert rollup["blank_due"] == 3
    rows = poam_rows(LAB_OUT)
    assert rows[0]["severity"] == "critical"
    assert all(row["blank_owner"] and row["blank_due"] for row in rows)


def test_product_lab_drop_poam_is_blank_owner_due_by_design() -> None:
    assert DROP_POAM.is_file()
    rows = poam_rows(DROP_POAM.parent.parent)
    assert rows
    assert rows[0]["severity"] in {"critical", "high"}
    assert all(row["blank_owner"] for row in rows)
    assert all(row["blank_due"] for row in rows)
    rollup = poam_summary(DROP_POAM.parent.parent, rows)
    assert rollup["open"] == rollup["total"]
    assert rollup["blank_owner"] == rollup["total"]
    assert rollup["blank_due"] == rollup["total"]
    assert rollup["critical"] + rollup["high"] >= 1


def test_http_summary_and_poam_highlight_path(mixed_out: Path) -> None:
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
        assert summary["honesty_label"]
        assert summary["refresh_mode"] == "reload"
        assert summary["safety"]["posts_api_risks"] is False
        assert summary["poam"]["open"] == 3
        assert summary["poam"]["critical"] == 1
        assert summary["poam"]["blank_owner"] == 2
        assert summary["poam"]["blank_due"] == 2
        with urllib.request.urlopen(base + "/api/poam/summary", timeout=5) as res:
            dedicated = json.loads(res.read().decode("utf-8"))
        assert dedicated["client"] is False
        assert dedicated["lab"] is True
        assert dedicated["poam"] == summary["poam"]
        with urllib.request.urlopen(base + "/api/poam", timeout=5) as res:
            rows = json.loads(res.read().decode("utf-8"))
        assert [r["severity"] for r in rows] == ["critical", "high", "medium", "low"]
        assert rows[0]["blank_owner"] is True
        assert rows[0]["blank_due"] is True
        assert rows[0]["weakness"] == "Critical SMB"
        filled = next(r for r in rows if r["severity"] == "medium")
        assert filled["blank_owner"] is False
        assert filled["owner"] == "ops"
        with urllib.request.urlopen(base + "/", timeout=5) as res:
            html = res.read().decode("utf-8")
        assert 'id="poam-kpis"' in html
        assert "POA&M triage" in html
        assert "blank for a human" in html
        assert 'id="lab-pill"' in html
        assert 'id="run-picker"' in html
        assert "Never POSTs /api/risks" in html
        try:
            urllib.request.urlopen(base + "/api/risks", timeout=5)
            raise AssertionError("GET /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
            body = json.loads(exc.read().decode("utf-8"))
            assert body["posted"] is False
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ui_highlights_blank_owner_due_and_sorts() -> None:
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'id="poam-kpis"' in html
    assert "POA&M triage" in html
    assert "Risk register draft" in html
    assert "blank" in html.lower()
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert '["owner", "Owner"]' in js
    assert '["due", "Due"]' in js
    assert "blank_owner" in js
    assert "blank_due" in js
    assert "needs-human" in js
    assert "sortPoamRows" in js
    assert "renderPoamKpis" in js
    assert "POAM_SEV_RANK" in js
    assert "/api/poam/summary" not in js or "/api/summary" in js
    assert "/api/risks" not in js
    css = (ROOT / "product" / "static" / "app.css").read_text(encoding="utf-8")
    assert "needs-human" in css
    assert "missing" in css


def test_docs_name_poam_kpis() -> None:
    docs = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "blank-owner" in docs or "blank owner" in docs
    assert "/api/poam/summary" in docs
    assert "python -m product" in docs
    assert "/api/risks" in docs
    assert "OUT_DIR=" in docs
    op = (ROOT / "product-lab" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "blank-owner" in op or "blank-owner/due" in op
    assert "Never POSTs /api/risks" in (ROOT / "product" / "static" / "index.html").read_text(
        encoding="utf-8"
    )


def test_brick_a_b_honesty_and_runs_still_present() -> None:
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'id="lab-pill"' in html
    assert 'id="sample-pill"' in html
    assert 'id="demo-pill"' in html
    assert "client=false" in html
    assert 'id="run-picker"' in html
    assert "Active out/" in html
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert "applyHonesty" in js
    assert "loadRuns" in js
    assert "Reload from disk" in js
    src = (ROOT / "product" / "server.py").read_text(encoding="utf-8")
    assert "derive_honesty" in src
    assert "list_runs" in src
    assert "posts_api_risks" in src
    assert 'POST "/api/risks"' not in src
