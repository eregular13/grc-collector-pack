from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

from product.server import build_drop_zip, estate, make_server

ROOT = Path(__file__).resolve().parents[1]


def test_estate_reads_out() -> None:
    data = estate()
    assert data["product"] == "GRC Collector Pack"
    assert data["safety"]["posts_api_risks"] is False
    if (ROOT / "out" / "summary.json").exists():
        assert data["ready"] is True
        assert data["summary"]["assets"] >= 20


def test_drop_zip_has_ciso_and_proposed() -> None:
    blob = build_drop_zip()
    assert blob[:2] == b"PK"
    with zipfile.ZipFile(BytesIO(blob)) as zf:
        names = set(zf.namelist())
    assert "IMPORT.md" in names
    assert "ciso-assistant/assets.csv" in names
    assert "riskready/risks_proposed.json" in names
    assert "summary.json" in names


def test_http_console_and_forbids_risks() -> None:
    httpd = make_server("127.0.0.1", 0)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://{host}:{port}"
        with urllib.request.urlopen(base + "/health", timeout=5) as res:
            health = json.loads(res.read().decode("utf-8"))
        assert health["ok"] is True
        with urllib.request.urlopen(base + "/api/summary", timeout=5) as res:
            summary = json.loads(res.read().decode("utf-8"))
        assert summary["safety"]["posts_api_risks"] is False
        with urllib.request.urlopen(base + "/", timeout=5) as res:
            html = res.read().decode("utf-8")
        assert "GRC Collector Pack" in html
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


def test_product_source_never_posts_risks() -> None:
    text = (ROOT / "product" / "server.py").read_text(encoding="utf-8")
    assert "curl" not in text
    assert 'POST "/api/risks"' not in text
    assert "localhost:18080" not in text
