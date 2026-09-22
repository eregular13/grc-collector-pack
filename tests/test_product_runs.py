"""CONSOLE_RUNS: list/switch sibling prove outs; honesty re-derived after switch."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from product.server import (
    derive_honesty,
    estate,
    list_runs,
    make_server,
    refresh_estate,
    stamp_name,
    switch_active_out,
)

ROOT = Path(__file__).resolve().parents[1]
LAB_OUT = ROOT / "fixtures" / "lab-drop-out"


def _write_out(
    dest: Path,
    *,
    lab: bool = False,
    sample: bool = False,
    demo: bool = True,
    client: bool = False,
    assets: int = 1,
    findings: int = 1,
) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    payload = {
        "demo": demo,
        "lab": lab,
        "sample": sample,
        "client": client,
        "seeded": sample and not lab,
        "canonical": findings,
        "assets": assets,
        "findings": findings,
    }
    (dest / "summary.json").write_text(json.dumps(payload), encoding="utf-8")
    if lab:
        (dest / "LAB.txt").write_text(
            "LAB/DEMO -- not a client estate.\n", encoding="utf-8"
        )
    if sample:
        (dest / "SAMPLE.txt").write_text(
            "SAMPLE/DEMO — not a client estate.\n", encoding="utf-8"
        )


def _stamp_tree(root: Path) -> dict[str, Path]:
    """Sibling prove outs: stamp/out, lab-prove-* as out, lab-prove-*/out."""
    sample_out = root / "stamp-sample" / "out"
    older_lab = root / "lab-prove-20260920"
    newer_lab = root / "lab-prove-20260922" / "out"
    _write_out(sample_out, sample=True, assets=2, findings=2)
    _write_out(older_lab, lab=True, assets=4, findings=4)
    _write_out(newer_lab, lab=True, assets=8, findings=8)
    older = time.time() - 120
    newer = time.time() - 10
    os.utime(older_lab, (older, older))
    os.utime(newer_lab, (newer, newer))
    return {
        "sample": sample_out,
        "older_lab": older_lab,
        "newer_lab": newer_lab,
    }


@pytest.fixture
def work_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    root = tmp_path / "prove-work"
    root.mkdir()
    stamps = _stamp_tree(root)
    monkeypatch.setenv("PROVE_WORK_ROOT", str(root))
    monkeypatch.setenv("OUT_DIR", str(stamps["sample"]))
    return {"root": root, **stamps}


def test_list_runs_finds_sibling_outs_and_lab_prove(work_root: dict[str, Path]) -> None:
    data = list_runs()
    assert data["client"] is False
    assert data["root"] == str(work_root["root"])
    stamps = {row["stamp"] for row in data["runs"]}
    assert "stamp-sample" in stamps
    assert "lab-prove-20260920" in stamps
    assert "lab-prove-20260922" in stamps
    assert stamp_name(work_root["newer_lab"]) == "lab-prove-20260922"
    by_stamp = {row["stamp"]: row for row in data["runs"]}
    assert by_stamp["stamp-sample"]["sample"] is True
    assert by_stamp["stamp-sample"]["lab"] is False
    assert by_stamp["stamp-sample"]["client"] is False
    assert by_stamp["stamp-sample"]["active"] is True
    assert by_stamp["lab-prove-20260922"]["lab"] is True
    assert by_stamp["lab-prove-20260922"]["sample"] is False
    assert by_stamp["lab-prove-20260922"]["client"] is False
    assert data["preferred_stamp"] == "lab-prove-20260922"
    assert by_stamp["lab-prove-20260922"]["preferred"] is True
    assert by_stamp["lab-prove-20260920"]["preferred"] is False
    assert data["runs"][0]["stamp"].startswith("lab-prove-")


def test_list_runs_infers_parent_of_out_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "prove-work"
    sibling = root / "alpha" / "out"
    other = root / "beta" / "out"
    _write_out(sibling, sample=True)
    _write_out(other, lab=True)
    monkeypatch.delenv("PROVE_WORK_ROOT", raising=False)
    monkeypatch.setenv("OUT_DIR", str(sibling))
    data = list_runs()
    stamps = {row["stamp"] for row in data["runs"]}
    assert "alpha" in stamps
    assert "beta" in stamps


def test_switch_rederives_honesty_and_keeps_client_false(
    work_root: dict[str, Path],
) -> None:
    before = estate()
    assert before["sample"] is True
    assert before["lab"] is False
    assert before["client"] is False
    assert before["refresh_mode"] == "collectors"
    result = switch_active_out(stamp="lab-prove-20260922")
    assert result["ok"] is True
    assert result["switched"] is True
    assert result["stamp"] == "lab-prove-20260922"
    assert result["lab"] is True
    assert result["sample"] is False
    assert result["demo"] is True
    assert result["client"] is False
    assert result["seeded"] is False
    assert result["refresh_mode"] == "reload"
    assert "LAB" in result["honesty_label"]
    assert "SAMPLE" not in result["honesty_label"]
    after = estate()
    assert Path(after["out_dir"]).resolve() == work_root["newer_lab"].resolve()
    assert after["lab"] is True
    assert after["sample"] is False
    assert after["client"] is False
    assert after["refresh_mode"] == "reload"
    honesty = derive_honesty(work_root["newer_lab"])
    assert honesty["client"] is False
    assert honesty["lab"] is True


def test_switch_never_invents_client_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "prove-work"
    hostile = root / "lab-prove-hostile"
    _write_out(hostile, lab=True, client=True, assets=3, findings=3)
    monkeypatch.setenv("PROVE_WORK_ROOT", str(root))
    monkeypatch.setenv("OUT_DIR", str(hostile))
    result = switch_active_out(stamp="lab-prove-hostile")
    assert result["client"] is False
    data = estate()
    assert data["client"] is False
    listed = list_runs()
    assert listed["client"] is False
    assert all(row["client"] is False for row in listed["runs"])


def test_lab_refresh_still_reload_after_switch(
    work_root: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    switch_active_out(stamp="lab-prove-20260922")

    def boom() -> list[str]:
        raise AssertionError("DEMO collectors must not run after LAB switch")

    monkeypatch.setattr("product.server.run_collectors", boom)
    result = refresh_estate()
    assert result["mode"] == "reload"
    assert result["ran"] == []
    assert result["collectors_ran"] is False
    assert result["lab"] is True
    assert result["client"] is False


def test_switch_unknown_stamp_fails(work_root: dict[str, Path]) -> None:
    from product.server import RunSwitchError

    with pytest.raises(RunSwitchError) as exc:
        switch_active_out(stamp="not-a-run")
    assert exc.value.code == 404
    assert Path(estate()["out_dir"]).resolve() == work_root["sample"].resolve()


def test_http_list_and_switch_and_honesty(
    work_root: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    httpd = make_server("127.0.0.1", 0)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    calls: list[str] = []

    def boom() -> list[str]:
        calls.append("collectors")
        raise AssertionError("HTTP LAB refresh after switch must not run collectors")

    monkeypatch.setattr("product.server.run_collectors", boom)
    try:
        base = f"http://{host}:{port}"
        with urllib.request.urlopen(base + "/api/runs", timeout=5) as res:
            listed = json.loads(res.read().decode("utf-8"))
            assert res.status == 200
        assert listed["client"] is False
        stamps = {row["stamp"] for row in listed["runs"]}
        assert "lab-prove-20260922" in stamps
        assert listed["preferred_stamp"] == "lab-prove-20260922"
        req = urllib.request.Request(
            base + "/api/runs",
            data=json.dumps({"stamp": "lab-prove-20260922"}).encode("utf-8"),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=5) as res:
            switched = json.loads(res.read().decode("utf-8"))
            assert res.status == 200
        assert switched["ok"] is True
        assert switched["lab"] is True
        assert switched["sample"] is False
        assert switched["client"] is False
        assert switched["refresh_mode"] == "reload"
        with urllib.request.urlopen(base + "/api/summary", timeout=5) as res:
            summary = json.loads(res.read().decode("utf-8"))
        assert summary["lab"] is True
        assert summary["client"] is False
        assert summary["refresh_mode"] == "reload"
        assert "LAB" in summary["honesty_label"]
        refresh = urllib.request.Request(base + "/api/refresh", data=b"{}", method="POST")
        with urllib.request.urlopen(refresh, timeout=5) as res:
            body = json.loads(res.read().decode("utf-8"))
        assert body["mode"] == "reload"
        assert body["ran"] == []
        assert calls == []
        with urllib.request.urlopen(
            base + "/api/runs/select?stamp=stamp-sample", timeout=5
        ) as res:
            back = json.loads(res.read().decode("utf-8"))
        assert back["sample"] is True
        assert back["lab"] is False
        assert back["client"] is False
        with urllib.request.urlopen(base + "/", timeout=5) as res:
            html = res.read().decode("utf-8")
        assert 'id="run-picker"' in html
        assert "Active out/" in html
        assert 'id="lab-pill"' in html
        assert "Never POSTs /api/risks" in html
        try:
            urllib.request.urlopen(base + "/api/risks", timeout=5)
            raise AssertionError("GET /api/risks should be forbidden")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_http_unknown_stamp_and_rejects_arbitrary_path(
    work_root: dict[str, Path],
) -> None:
    httpd = make_server("127.0.0.1", 0)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://{host}:{port}"
        req = urllib.request.Request(
            base + "/api/runs",
            data=json.dumps({"stamp": "missing"}).encode("utf-8"),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("unknown stamp should 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
            body = json.loads(exc.read().decode("utf-8"))
            assert body["ok"] is False
            assert body["client"] is False
        req2 = urllib.request.Request(
            base + "/api/runs",
            data=json.dumps({"out_dir": "/etc"}).encode("utf-8"),
            method="POST",
        )
        req2.add_header("Content-Type", "application/json")
        try:
            urllib.request.urlopen(req2, timeout=5)
            raise AssertionError("arbitrary out_dir should 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ui_and_docs_name_run_picker() -> None:
    html = (ROOT / "product" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'id="run-picker"' in html
    assert "Active out/" in html
    js = (ROOT / "product" / "static" / "app.js").read_text(encoding="utf-8")
    assert "/api/runs" in js
    assert "loadRuns" in js
    assert "/api/risks" not in js
    docs = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "PROVE_WORK_ROOT" in docs
    assert "GET /api/runs" in docs
    assert "Active out/" in docs
    assert "python -m product" in docs
    assert "derive_honesty" in docs
    assert "/api/risks" in docs


def test_brick_a_lab_fixture_still_honest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(LAB_OUT))
    monkeypatch.delenv("PROVE_WORK_ROOT", raising=False)
    data = estate()
    assert data["lab"] is True
    assert data["sample"] is False
    assert data["client"] is False
    assert data["refresh_mode"] == "reload"
    listed = list_runs()
    assert listed["client"] is False
    active = next(row for row in listed["runs"] if row["active"])
    assert "lab-drop-out" in active["stamp"]
    assert active["lab"] is True
