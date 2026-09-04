from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from product.server import (
    assert_loopback_host,
    bind_host,
    build_drop_zip,
    estate,
    make_server,
)

ROOT = Path(__file__).resolve().parents[1]


def test_estate_reads_out() -> None:
    data = estate()
    assert data["product"] == "GRC Collector Pack"
    assert data["safety"]["posts_api_risks"] is False
    assert data["safety"]["riskready_review_only"] is True
    assert data["safety"]["riskready_wrap"] is False
    assert data["safety"]["bind"] == "127.0.0.1"
    if (ROOT / "out" / "summary.json").exists():
        assert data["ready"] is True
        assert data["summary"]["assets"] >= 20


def test_drop_zip_has_ciso_and_proposed() -> None:
    blob = build_drop_zip()
    assert blob[:2] == b"PK"
    with zipfile.ZipFile(BytesIO(blob)) as zf:
        names = set(zf.namelist())
    assert "IMPORT.md" in names
    if not (ROOT / "out" / "summary.json").exists():
        return
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
        try:
            with urllib.request.urlopen(base + "/api/summary", timeout=5) as res:
                summary = json.loads(res.read().decode("utf-8"))
                summary_code = res.status
        except urllib.error.HTTPError as exc:
            assert exc.code == 503
            summary = json.loads(exc.read().decode("utf-8"))
            summary_code = exc.code
        assert summary_code in {200, 503}
        assert summary["safety"]["posts_api_risks"] is False
        assert summary["safety"]["riskready_review_only"] is True
        assert summary["safety"]["riskready_wrap"] is False
        assert summary["bind"].startswith("127.0.0.1:")
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


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "*", "192.168.1.10", "10.0.0.5"])
def test_bind_lock_rejects_non_loopback(host: str) -> None:
    with pytest.raises(SystemExit) as exc:
        assert_loopback_host(host)
    assert exc.value.code == 2


def test_bind_lock_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_PRODUCT_HOST", "0.0.0.0")
    with pytest.raises(SystemExit) as exc:
        assert_loopback_host(bind_host())
    assert exc.value.code == 2


def test_refresh_500_has_no_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> dict:
        raise RuntimeError("secret-boom")

    monkeypatch.setattr("product.server.refresh_estate", boom)
    httpd = make_server("127.0.0.1", 0)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        req = urllib.request.Request(
            f"http://{host}:{port}/api/refresh", data=b"{}", method="POST"
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("refresh should fail")
        except urllib.error.HTTPError as exc:
            assert exc.code == 500
            body = exc.read().decode("utf-8")
            assert "Traceback" not in body
            assert "secret-boom" not in body
            data = json.loads(body)
            assert data["error"] == "refresh failed"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_make_server_rejects_all_interfaces() -> None:
    with pytest.raises(SystemExit) as exc:
        make_server("0.0.0.0", 0)
    assert exc.value.code == 2
