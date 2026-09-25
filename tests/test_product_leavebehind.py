"""CONSOLE leave-behind: /api/summary and /export.zip surface OpenGRC/Probo, posted=false."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from product.server import build_drop_zip, estate, leavebehind_sinks, make_server

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
    assert data["opengrc"]["source"] == "out"
    assert data["opengrc"]["counts"]["risks"] == 3
    assert data["probo"]["posted"] is False
    assert data["probo"]["source"] == "out"
    assert data["probo"]["counts"]["addFinding"] == 5
    assert data["client"] is False
    assert data["safety"]["posts_api_risks"] is False


def test_leavebehind_missing_files_posted_false_zero_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _write_summary(out)
    empty_drop = tmp_path / "no-packaged-drop"
    empty_drop.mkdir()
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setattr("product.server.packaged_drop", lambda: empty_drop)
    data = estate()
    assert data["opengrc"]["present"] is False
    assert data["opengrc"]["posted"] is False
    assert data["opengrc"]["http"] is False
    assert data["opengrc"]["source"] == ""
    assert data["opengrc"]["counts"]["risks"] == 0
    assert data["probo"]["present"] is False
    assert data["probo"]["posted"] is False
    assert data["probo"]["source"] == ""
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


def test_ui_sink_kpis_show_source_out_vs_packaged_drop() -> None:
    """SAMPLE packaged counts must not look like LAB dest_in on the sink KPIs."""
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="sink-kpis-label"' in html
    assert "SAMPLE packaged" in html
    assert "LAB dest_in" in html
    assert "source=out" in html
    assert "source=product-lab/drop" in html
    assert "renderSinkKpis" in js
    assert "og.source" in js
    assert "probo.source" in js
    assert "source=out" in js
    assert "source=product-lab/drop" in js
    assert "OpenGRC source" in js
    assert "Probo source" in js
    assert "SAMPLE packaged" in js
    assert "LAB dest_in" in js


def test_ui_sink_kpis_show_opengrc_and_probo_lab_sample() -> None:
    """SAMPLE packaged fallback must not look like LAB dest_in on sink KPIs."""
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="sink-kpis"' in html
    assert "opengrc.lab" in html
    assert "opengrc.sample" in html
    assert "probo.lab" in html
    assert "probo.sample" in html
    assert "posted=false" in html.lower()
    assert "SAMPLE packaged" in html
    assert "LAB dest_in" in html
    assert "renderSinkKpis" in js
    assert "og.lab" in js
    assert "og.sample" in js
    assert "probo.lab" in js
    assert "probo.sample" in js
    assert "OpenGRC lab" in js
    assert "OpenGRC sample" in js
    assert "Probo lab" in js
    assert "Probo sample" in js
    assert "posted=false" in js.lower() or "posted=false" in html.lower()


def test_ui_sink_kpis_label_rewrite_includes_opengrc_and_probo_lab_sample() -> None:
    """Live sink-kpis-label after renderSinkKpis must match lab/sample KPI tiles."""
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="sink-kpis-label"' in html
    assert "renderSinkKpis" in js
    assert "sink-kpis-label" in js
    assert "labelEl.textContent" in js
    assert "opengrc.lab=" in js
    assert "opengrc.sample=" in js
    assert "probo.lab=" in js
    assert "probo.sample=" in js
    assert "posted=false" in js.lower()
    assert "SAMPLE packaged" in js
    assert "LAB dest_in" in js
    assert "sinkSourceHonesty" in js


def test_drop_zip_includes_opengrc_csvs_and_probo_drafts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Download drop matches /api/summary sinks: file-true OpenGRC + Probo, posted=false."""
    out = tmp_path / "out"
    _write_summary(out)
    _write_opengrc(out, posted=False, risks=3)
    _write_probo(out, posted=False, findings=5)
    monkeypatch.setenv("OUT_DIR", str(out))
    blob = build_drop_zip()
    assert blob[:2] == b"PK"
    with zipfile.ZipFile(BytesIO(blob)) as zf:
        names = set(zf.namelist())
        import_md = zf.read("IMPORT.md").decode("utf-8")
    assert "opengrc/risks.csv" in names
    assert "opengrc/assets.csv" in names
    assert "opengrc/implementations.csv" in names
    assert "opengrc/MANIFEST.json" in names
    assert "import_preview/probo.json" in names
    assert "probo/README.md" in names
    assert "OpenGRC" in import_md
    assert "Probo" in import_md
    assert "posted=false" in import_md.lower()
    assert "Do not POST /api/risks" in import_md
    assert "file-true" in import_md.lower() or "not live" in import_md.lower()
    assert "live import" not in import_md.lower() or "not live" in import_md.lower()


def test_http_export_zip_includes_opengrc_probo(
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
        with urllib.request.urlopen(base + "/export.zip", timeout=5) as res:
            assert res.status == 200
            ctype = res.headers.get("Content-Type", "")
            blob = res.read()
        assert "zip" in ctype.lower()
        with zipfile.ZipFile(BytesIO(blob)) as zf:
            names = set(zf.namelist())
            import_md = zf.read("IMPORT.md").decode("utf-8")
        assert "opengrc/risks.csv" in names
        assert "import_preview/probo.json" in names
        assert "Do not POST /api/risks" in import_md
        try:
            urllib.request.urlopen(base + "/api/risks", timeout=5)
            raise AssertionError("GET /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_leavebehind_sinks_falls_back_to_product_lab_drop_when_out_lacks_sinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KPIs match packaged zip when OUT_DIR has no OpenGRC/Probo leave-behind."""
    out = tmp_path / "empty-out"
    out.mkdir()
    (out / "summary.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("OUT_DIR", str(out))
    drop = ROOT / "product-lab" / "drop"
    og_manifest = json.loads(
        (drop / "opengrc" / "MANIFEST.json").read_text(encoding="utf-8")
    )
    probo_payload = json.loads(
        (drop / "import_preview" / "probo.json").read_text(encoding="utf-8")
    )
    sinks = leavebehind_sinks(out)
    og = sinks["opengrc"]
    assert og["present"] is True
    assert og["posted"] is False
    assert og["http"] is False
    assert og["client"] is False
    assert og["sample"] is True
    assert og["lab"] is False
    assert og["source"] == "product-lab/drop"
    assert og["counts"]["risks"] == og_manifest["counts"]["risks"]
    assert og["counts"]["assets"] == og_manifest["counts"]["assets"]
    assert og["counts"]["implementations"] == og_manifest["counts"]["implementations"]
    probo = sinks["probo"]
    assert probo["present"] is True
    assert probo["posted"] is False
    assert probo["http"] is False
    assert probo["client"] is False
    assert probo["sample"] is True
    assert probo["lab"] is False
    assert probo["source"] == "product-lab/drop"
    assert probo["organization_id"] is None
    assert probo["counts"]["addFinding"] == probo_payload["counts"]["addFinding"]
    data = estate()
    assert data["opengrc"]["source"] == "product-lab/drop"
    assert data["opengrc"]["counts"]["risks"] == og["counts"]["risks"]
    assert data["probo"]["counts"]["addFinding"] == probo["counts"]["addFinding"]
    assert data["opengrc"]["posted"] is False
    assert data["probo"]["posted"] is False
    assert data["client"] is False
    assert data["safety"]["posts_api_risks"] is False


def test_http_summary_falls_back_to_product_lab_drop_when_out_lacks_sinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "empty-out"
    _write_summary(out)
    monkeypatch.setenv("OUT_DIR", str(out))
    drop = ROOT / "product-lab" / "drop"
    og_manifest = json.loads(
        (drop / "opengrc" / "MANIFEST.json").read_text(encoding="utf-8")
    )
    probo_payload = json.loads(
        (drop / "import_preview" / "probo.json").read_text(encoding="utf-8")
    )
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
        assert summary["opengrc"]["present"] is True
        assert summary["opengrc"]["posted"] is False
        assert summary["opengrc"]["http"] is False
        assert summary["opengrc"]["sample"] is True
        assert summary["opengrc"]["lab"] is False
        assert summary["opengrc"]["source"] == "product-lab/drop"
        assert summary["opengrc"]["counts"]["risks"] == og_manifest["counts"]["risks"]
        assert summary["opengrc"]["counts"]["assets"] == og_manifest["counts"]["assets"]
        assert (
            summary["opengrc"]["counts"]["implementations"]
            == og_manifest["counts"]["implementations"]
        )
        assert summary["probo"]["present"] is True
        assert summary["probo"]["posted"] is False
        assert summary["probo"]["source"] == "product-lab/drop"
        assert (
            summary["probo"]["counts"]["addFinding"]
            == probo_payload["counts"]["addFinding"]
        )
        assert summary["safety"]["posts_api_risks"] is False
        try:
            urllib.request.urlopen(base + "/api/risks", timeout=5)
            raise AssertionError("GET /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ui_lab_dest_in_packaged_sinks_show_sample_pill() -> None:
    """LAB dest_in + product-lab/drop sinks must not look like lab counts."""
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="lab-pill"' in html
    assert 'id="sample-pill"' in html
    assert 'id="sink-sample-pill"' in html
    assert "SAMPLE packaged sinks" in html
    assert "applySinkSamplePill" in js
    assert "sink-sample-pill" in js
    assert "product-lab/drop" in js
    assert "estate.lab" in js
    assert "SAMPLE packaged sinks" in js or "sink-sample-pill" in js
    # dest_in SAMPLE pill stays separate from sink honesty
    assert 'id="sample-pill"' in html
    assert "applyHonesty" in js


def test_http_lab_dest_in_packaged_sinks_keep_dest_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Header must be able to show SAMPLE packaged sinks while dest_in stays LAB."""
    out = tmp_path / "lab-out"
    _write_summary(out)
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["lab"] is True
    assert data["sample"] is False
    assert data["client"] is False
    assert data["opengrc"]["source"] == "product-lab/drop"
    assert data["opengrc"]["sample"] is True
    assert data["opengrc"]["lab"] is False
    assert data["probo"]["source"] == "product-lab/drop"
    assert data["probo"]["sample"] is True
    assert data["safety"]["posts_api_risks"] is False
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
        assert summary["opengrc"]["source"] == "product-lab/drop"
        assert summary["opengrc"]["posted"] is False
        with urllib.request.urlopen(base + "/", timeout=5) as res:
            html = res.read().decode("utf-8")
        assert 'id="lab-pill"' in html
        assert 'id="sink-sample-pill"' in html
        assert "SAMPLE packaged sinks" in html
        assert "Never POSTs /api/risks" in html
        try:
            urllib.request.urlopen(base + "/api/risks", timeout=5)
            raise AssertionError("GET /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()
