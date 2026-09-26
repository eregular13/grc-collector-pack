"""Stop generating out/riskready. Console reads count-identity outputs only.

Cold CISO review #2 item 7: RiskReady JSON is out of scope (PR #128 dropped
it from the packaged drop). The loader must not write out/riskready, the
console must work with that directory absent, and KPIs /api/proposed must
match findings vs POA&M vs register counts.
"""

from __future__ import annotations

import csv
import importlib
import json
import threading
import urllib.request
from pathlib import Path

import pytest

from product.server import estate, make_server, payload
from shared.ciso_shape import POAM_HEADER, assert_count_consistency


def _finding(ref: str, sev: str = "high") -> dict:
    return {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": ref,
        "name": f"FTP exposed {ref}",
        "description": f"{ref} has open TCP/21 (ftp).",
        "severity": sev,
        "category": "exposure",
        "assets": ["host-a"],
        "labels": ["nmap"],
        "extra": {"port": "21", "service": "ftp", "ip": "10.0.0.5"},
    }


def _asset() -> dict:
    return {
        "kind": "asset",
        "source": "inventory-nmap",
        "ref_id": "asset-host-a",
        "name": "host-a",
        "description": "Host host-a",
        "severity": "info",
        "category": "host",
        "assets": ["host-a"],
        "labels": ["nmap"],
        "extra": {"asset_type": "PR", "ip": "10.0.0.5"},
    }


def _run_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: list[dict]) -> Path:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    with (out / "canonical" / "inventory-nmap.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    return out


def _csv_rows(path: Path) -> list[dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def test_loader_writes_no_riskready_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1"), _finding("f2", "medium")])
    assert not (out / "riskready").exists()
    leftover = [p for p in out.rglob("*") if "riskready" in p.as_posix().lower()]
    assert leftover == []
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert "incidents" not in summary
    assert "risks_proposed" not in summary
    shape = assert_count_consistency(out, summary)
    assert summary["open_risks"] == summary["poam"] == shape["poam"]
    assert summary["risk_scenarios"] == summary["weaknesses"] == shape["weaknesses"]


def test_simplerisk_poam_csv_has_estate_banner_and_column(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Covered on master now. PR #132 (open) may add # comments to more CSVs.

    This test skips comment lines for the header so it stays correct if #132
    lands later. Banner may live as a CSV # comment, ESTATE.txt, or README.
    """
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")])
    sr = out / "simplerisk" / "poam.csv"
    assert sr.is_file()
    text = sr.read_text(encoding="utf-8")
    header = next(
        line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    assert header == POAM_HEADER
    assert header.split(",")[8] == "estate"
    rows = _csv_rows(sr)
    assert rows
    assert {row["estate"] for row in rows} == {"LAB"}
    blob = text
    for name in ("ESTATE.txt", "README.md"):
        extra = out / "simplerisk" / name
        if extra.is_file():
            blob += "\n" + extra.read_text(encoding="utf-8")
    assert "ESTATE: LAB" in blob
    assert "not a client estate" in blob


def test_console_works_without_riskready_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1"), _finding("f2")])
    assert not (out / "riskready").exists()
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["ready"] is True
    assert data["client"] is False
    assert data["safety"]["posts_api_risks"] is False
    assert "incidents" not in (data.get("summary") or {})
    assert "risks_proposed" not in (data.get("summary") or {})
    proposed = payload("proposed")
    assert isinstance(proposed, list) and proposed
    assert payload("incidents") == []

    httpd = make_server("127.0.0.1", 0)
    host, port = httpd.server_address[:2]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://{host}:{port}"
        with urllib.request.urlopen(base + "/api/summary", timeout=5) as res:
            summary = json.loads(res.read().decode("utf-8"))
        assert summary["ready"] is True
        assert "incidents" not in (summary.get("summary") or {})
        assert "risks_proposed" not in (summary.get("summary") or {})
        with urllib.request.urlopen(base + "/api/proposed", timeout=5) as res:
            rows = json.loads(res.read().decode("utf-8"))
        assert isinstance(rows, list) and rows
        with urllib.request.urlopen(base + "/", timeout=5) as res:
            html = res.read().decode("utf-8")
        assert "risks_proposed.json" not in html
        assert "Never POSTs /api/risks" in html
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_console_counts_match_count_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1"), _finding("f2")])
    disk = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    shape = assert_count_consistency(out, disk)
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    summary = data["summary"]
    assert summary["findings"] == shape["findings"] == disk["findings"]
    assert summary["vulnerabilities"] == shape["vulnerabilities"] == disk["vulnerabilities"]
    assert summary["weaknesses"] == shape["weaknesses"] == disk["weaknesses"]
    assert summary["risk_scenarios"] == shape["risk_scenarios"] == disk["risk_scenarios"]
    assert summary["poam"] == shape["poam"] == disk["poam"]
    assert summary["open_risks"] == shape["open_risks"] == disk["open_risks"]
    assert summary["open_risks"] == summary["poam"]
    assert summary["risk_scenarios"] == summary["weaknesses"]
    assert summary["weaknesses"] == summary["findings"] + summary["vulnerabilities"]
    proposed = payload("proposed")
    assert len(proposed) == summary["open_risks"] == summary["poam"]
    poam = payload("poam")
    assert len(poam) == summary["poam"]
    findings = payload("findings")
    assert len(findings) == summary["findings"]
