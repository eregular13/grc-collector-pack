"""CONSOLE_HONESTY: LAB/SAMPLE/DEMO pills + LAB refresh is disk reload only."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from product.server import derive_honesty, estate, make_server, refresh_estate

ROOT = Path(__file__).resolve().parents[1]
LAB_OUT = ROOT / "fixtures" / "lab-drop-out"


def test_lab_fixture_out_summary_honesty(monkeypatch: pytest.MonkeyPatch) -> None:
    assert (LAB_OUT / "LAB.txt").is_file()
    assert (LAB_OUT / "summary.json").is_file()
    monkeypatch.setenv("OUT_DIR", str(LAB_OUT))
    data = estate()
    assert data["ready"] is True
    assert data["lab"] is True
    assert data["sample"] is False
    assert data["demo"] is True
    assert data["client"] is False
    assert data["seeded"] is False
    assert data["use_existing_in"] is True
    assert data["refresh_mode"] == "reload"
    assert "LAB" in data["honesty_label"]
    assert "not a client" in data["honesty_label"].lower()
    assert "SAMPLE" not in data["honesty_label"]
    assert data["safety"]["posts_api_risks"] is False
    assert data["safety"]["riskready_review_only"] is True
    assert data["safety"]["bind"] == "127.0.0.1"


def test_lab_txt_without_summary_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "LAB.txt").write_text(
        "LAB/DEMO -- not a client estate.\n", encoding="utf-8"
    )
    (out / "summary.json").write_text(
        json.dumps({"demo": True, "canonical": 1, "assets": 1, "findings": 1}),
        encoding="utf-8",
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["lab"] is True
    assert data["sample"] is False
    assert data["client"] is False
    assert data["seeded"] is False
    assert data["refresh_mode"] == "reload"
    assert "LAB" in data["honesty_label"]


def test_honesty_from_parent_prove_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "prove"
    out = work / "out"
    out.mkdir(parents=True)
    (out / "summary.json").write_text(
        json.dumps({"demo": True, "canonical": 2, "assets": 2, "findings": 2}),
        encoding="utf-8",
    )
    (work / "prove-ciso.json").write_text(
        json.dumps(
            {
                "lab": True,
                "sample": False,
                "demo": True,
                "client": False,
                "seeded": False,
                "use_existing_in": True,
                "estate": "LAB/DEMO — not a client estate",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["lab"] is True
    assert data["sample"] is False
    assert data["client"] is False
    assert data["seeded"] is False
    assert data["refresh_mode"] == "reload"


def test_never_invents_client_true(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text(
        json.dumps(
            {
                "demo": True,
                "lab": True,
                "client": True,
                "canonical": 1,
                "assets": 1,
                "findings": 1,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["client"] is False
    honesty = derive_honesty(out, json.loads((out / "summary.json").read_text()))
    assert honesty["client"] is False


def test_lab_refresh_does_not_run_collectors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(LAB_OUT))

    def boom() -> list[str]:
        raise AssertionError("DEMO collectors must not run when honesty is LAB")

    monkeypatch.setattr("product.server.run_collectors", boom)
    result = refresh_estate()
    assert result["ok"] is True
    assert result["ran"] == []
    assert result["collectors_ran"] is False
    assert result["mode"] == "reload"
    assert result["reloaded"] is True
    assert result["lab"] is True
    assert result["client"] is False
    assert result["seeded"] is False


def test_demo_refresh_still_runs_collectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text(
        json.dumps({"demo": True, "canonical": 1, "assets": 1, "findings": 1}),
        encoding="utf-8",
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    called: list[str] = []

    def fake() -> list[str]:
        called.append("ran")
        return ["grc_loader.py"]

    monkeypatch.setattr("product.server.run_collectors", fake)
    result = refresh_estate()
    assert called == ["ran"]
    assert result["collectors_ran"] is True
    assert result["mode"] == "collectors"
    assert result["ran"] == ["grc_loader.py"]
    assert result["lab"] is False
    assert result["client"] is False


def test_non_demo_live_out_reloads_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text(
        json.dumps({"demo": False, "canonical": 4, "assets": 4, "findings": 4}),
        encoding="utf-8",
    )
    monkeypatch.setenv("OUT_DIR", str(out))

    def boom() -> list[str]:
        raise AssertionError("collectors must not run for non-demo live out")

    monkeypatch.setattr("product.server.run_collectors", boom)
    result = refresh_estate()
    assert result["mode"] == "reload"
    assert result["ran"] == []
    assert result["collectors_ran"] is False
    assert result["demo"] is False
    assert result["client"] is False


def test_http_lab_summary_and_refresh_reload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(LAB_OUT))
    httpd = make_server("127.0.0.1", 0)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    calls: list[str] = []

    def boom() -> list[str]:
        calls.append("collectors")
        raise AssertionError("HTTP LAB refresh must not run collectors")

    monkeypatch.setattr("product.server.run_collectors", boom)
    try:
        base = f"http://{host}:{port}"
        with urllib.request.urlopen(base + "/api/summary", timeout=5) as res:
            summary = json.loads(res.read().decode("utf-8"))
            assert res.status == 200
        assert summary["lab"] is True
        assert summary["sample"] is False
        assert summary["demo"] is True
        assert summary["client"] is False
        assert summary["seeded"] is False
        assert summary["refresh_mode"] == "reload"
        assert "LAB" in summary["honesty_label"]
        assert summary["safety"]["posts_api_risks"] is False
        req = urllib.request.Request(base + "/api/refresh", data=b"{}", method="POST")
        with urllib.request.urlopen(req, timeout=5) as res:
            body = json.loads(res.read().decode("utf-8"))
            assert res.status == 200
        assert body["ran"] == []
        assert body["collectors_ran"] is False
        assert body["mode"] == "reload"
        assert body["lab"] is True
        assert calls == []
        with urllib.request.urlopen(base + "/", timeout=5) as res:
            html = res.read().decode("utf-8")
        assert 'id="lab-pill"' in html
        assert ">LAB<" in html
        assert ">SAMPLE<" in html
        assert ">DEMO<" in html
        assert "client=false" in html
        assert "Never POSTs /api/risks" in html
        try:
            urllib.request.urlopen(base + "/api/risks", timeout=5)
            raise AssertionError("GET /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ui_has_honesty_pills() -> None:
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'id="lab-pill"' in html
    assert ">LAB<" in html
    assert 'id="sample-pill"' in html
    assert ">SAMPLE<" in html
    assert 'id="demo-pill"' in html
    assert ">DEMO<" in html
    assert 'id="client-pill"' in html
    assert "client=false" in html
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert "Reload from disk" in js
    assert "collectors not run" in js
    assert "applyHonesty" in js
    assert "/api/risks" not in js


def test_docs_lab_console_paragraph() -> None:
    docs = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "python -m product" in docs
    assert "OUT_DIR=" in docs
    assert "fixtures/lab-drop-out" in docs
    assert "disk reload" in docs
    assert "DEMO collectors" in docs
    assert "/api/risks" in docs
