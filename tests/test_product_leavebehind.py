"""CONSOLE leave-behind: /api/summary surfaces OpenGRC/Probo counts, posted=false."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from product.server import estate, leavebehind_sinks, make_server

ROOT = Path(__file__).resolve().parents[1]


def _write_summary(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    (out / "summary.json").write_text(
        json.dumps(
            {
                "demo": True,
                "lab": True,
                "sample": False,
                "client": False,
                "seeded": False,
                "use_existing_in": True,
                "canonical": 2,
                "assets": 2,
                "findings": 2,
                "poam": 1,
            }
        ),
        encoding="utf-8",
    )


def _write_opengrc(out: Path, *, posted: bool = False, risks: int = 3) -> None:
    dest = out / "opengrc"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "MANIFEST.json").write_text(
        json.dumps(
            {
                "sink": "opengrc",
                "posted": posted,
                "http": posted,
                "sample": False,
                "lab": True,
                "client": False,
                "paying_day": "FAIL",
                "counts": {"risks": risks, "assets": 2, "implementations": 4},
            }
        ),
        encoding="utf-8",
    )
    header = "code,name,description\n"
    rows = "".join(f"R{i},risk {i},LAB/DEMO row\n" for i in range(risks))
    (dest / "risks.csv").write_text(header + rows, encoding="utf-8")
    (dest / "assets.csv").write_text(
        "asset_tag,name\nh1,host-1\nh2,host-2\n", encoding="utf-8"
    )
    (dest / "implementations.csv").write_text(
        "title,details\nctl-a,a\nctl-b,b\nctl-c,c\nctl-d,d\n", encoding="utf-8"
    )


def _write_probo(out: Path, *, posted: bool = False, findings: int = 5) -> None:
    dest = out / "import_preview"
    dest.mkdir(parents=True, exist_ok=True)
    payload = {
        "sink": "probo",
        "posted": posted,
        "http": posted,
        "documentation_only": True,
        "sample": False,
        "lab": True,
        "client": False,
        "paying_day": "FAIL",
        "organization_id": None,
        "addFinding": [{"shape": "addFinding", "posted": False} for _ in range(findings)],
        "addRisk": [{"shape": "addRisk"} for _ in range(2)],
        "createRisk": [{"shape": "createRisk"} for _ in range(1)],
        "counts": {
            "addFinding": findings,
            "addRisk": 2,
            "createRisk": 1,
        },
    }
    (dest / "probo.json").write_text(json.dumps(payload), encoding="utf-8")
    (out / "probo").mkdir(parents=True, exist_ok=True)
    (out / "probo" / "README.md").write_text(
        "LAB/DEMO posted=false. Not live import.\n", encoding="utf-8"
    )


def test_leavebehind_sinks_reads_opengrc_probo_posted_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _write_summary(out)
    _write_opengrc(out, posted=False, risks=3)
    _write_probo(out, posted=False, findings=5)
    monkeypatch.setenv("OUT_DIR", str(out))
    sinks = leavebehind_sinks(out)
    og = sinks["opengrc"]
    assert og["present"] is True
    assert og["posted"] is False
    assert og["http"] is False
    assert og["client"] is False
    assert og["lab"] is True
    assert og["sample"] is False
    assert og["counts"]["risks"] == 3
    assert og["counts"]["assets"] == 2
    assert og["counts"]["implementations"] == 4
    probo = sinks["probo"]
    assert probo["present"] is True
    assert probo["posted"] is False
    assert probo["http"] is False
    assert probo["client"] is False
    assert probo["organization_id"] is None
    assert probo["counts"]["addFinding"] == 5
    assert probo["counts"]["addRisk"] == 2
    data = estate()
    assert data["opengrc"]["posted"] is False
    assert data["opengrc"]["counts"]["risks"] == 3
    assert data["probo"]["posted"] is False
    assert data["probo"]["counts"]["addFinding"] == 5
    assert data["client"] is False
    assert data["safety"]["posts_api_risks"] is False


def test_leavebehind_missing_files_posted_false_zero_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _write_summary(out)
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["opengrc"]["present"] is False
    assert data["opengrc"]["posted"] is False
    assert data["opengrc"]["http"] is False
    assert data["opengrc"]["counts"]["risks"] == 0
    assert data["probo"]["present"] is False
    assert data["probo"]["posted"] is False
    assert data["probo"]["organization_id"] is None
    assert data["probo"]["counts"]["addFinding"] == 0


def test_leavebehind_file_posted_true_still_false_on_console(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Console never claims live OpenGRC/Probo import even if leave-behind lies."""
    out = tmp_path / "out"
    _write_summary(out)
    _write_opengrc(out, posted=True, risks=1)
    _write_probo(out, posted=True, findings=1)
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["opengrc"]["posted"] is False
    assert data["opengrc"]["http"] is False
    assert data["probo"]["posted"] is False
    assert data["probo"]["http"] is False
    assert data["safety"]["posts_api_risks"] is False


def test_http_summary_surfaces_opengrc_probo_posted_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _write_summary(out)
    _write_opengrc(out, posted=False, risks=3)
    _write_probo(out, posted=False, findings=5)
    monkeypatch.setenv("OUT_DIR", str(out))
    httpd = make_server("127.0.0.1", 0)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://{host}:{port}"
        with urllib.request.urlopen(base + "/api/summary", timeout=5) as res:
            summary = json.loads(res.read().decode("utf-8"))
            assert res.status == 200
        assert summary["lab"] is True
        assert summary["sample"] is False
        assert summary["client"] is False
        assert summary["opengrc"]["posted"] is False
        assert summary["opengrc"]["http"] is False
        assert summary["opengrc"]["counts"]["risks"] == 3
        assert summary["opengrc"]["counts"]["assets"] == 2
        assert summary["opengrc"]["counts"]["implementations"] == 4
        assert summary["probo"]["posted"] is False
        assert summary["probo"]["counts"]["addFinding"] == 5
        assert summary["probo"]["organization_id"] is None
        assert summary["safety"]["posts_api_risks"] is False
        with urllib.request.urlopen(base + "/", timeout=5) as res:
            html = res.read().decode("utf-8")
        assert 'id="sink-kpis"' in html
        assert "posted=false" in html.lower()
        assert "Never POSTs /api/risks" in html
        try:
            urllib.request.urlopen(base + "/api/risks", timeout=5)
            raise AssertionError("GET /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ui_renders_opengrc_probo_leavebehind_kpis() -> None:
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="sink-kpis"' in html
    assert "OpenGRC" in html
    assert "Probo" in html
    assert "posted=false" in html.lower()
    assert "/api/risks" not in js or "Never POSTs" in html
    assert "renderSinkKpis" in js
    assert "opengrc" in js
    assert "addFinding" in js
