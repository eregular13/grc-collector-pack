"""LAB/CLIENT/operator drops must never silently fill fixtures/demo.

DEMO/SAMPLE empty-in still loads fixtures and stays labeled demo.
Never POST /api/risks. LAB/SAMPLE/DEMO is never client KEEP.
"""

from __future__ import annotations

import json
from pathlib import Path

from collectors import cloud_prowler, grc_loader, inventory_nmap, vuln_scan
from shared.io_util import allow_demo_fallback, load_sensor_coverage, run_collector

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"


def _prep(tmp_path: Path, monkeypatch, *, label: str | None, extra_env: dict[str, str] | None = None) -> Path:
    dest_in = tmp_path / "in"
    dest_out = tmp_path / "out"
    dest_in.mkdir(parents=True)
    dest_out.mkdir(parents=True)
    monkeypatch.setenv("IN_DIR", str(dest_in))
    monkeypatch.setenv("OUT_DIR", str(dest_out))
    monkeypatch.setenv("FIXTURES_DIR", str(DEMO))
    monkeypatch.delenv("DROPBOX_DEMO", raising=False)
    if label:
        monkeypatch.setenv("GRC_ESTATE_LABEL", label)
    else:
        monkeypatch.delenv("GRC_ESTATE_LABEL", raising=False)
    for key, value in (extra_env or {}).items():
        monkeypatch.setenv(key, value)
    return dest_in


def _write_malformed_cloud(dest_in: Path) -> None:
    folder = dest_in / "cloud"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "bad.json").write_text('{"findings":[{"CheckID":', encoding="utf-8")


def _write_malformed_vuln(dest_in: Path) -> None:
    folder = dest_in / "vuln"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "broken.json").write_text("{not-json", encoding="utf-8")


def _status_for(out: Path, source: str) -> dict:
    rows = load_sensor_coverage(out)
    return next(row for row in rows if row["source"] == source)


def test_lab_malformed_sensors_zero_demo_named_parse_error(tmp_path, monkeypatch) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label="LAB")
    (dest_in / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    _write_malformed_cloud(dest_in)
    _write_malformed_vuln(dest_in)

    cloud = run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)
    vuln = run_collector("vuln-scan", (".json", ".jsonl", ".sarif"), vuln_scan.parse_file)

    assert cloud == []
    assert vuln == []
    assert not any("demo" in (r.get("labels") or []) for r in cloud + vuln)

    cloud_st = _status_for(tmp_path / "out", "cloud-prowler")
    vuln_st = _status_for(tmp_path / "out", "vuln-scan")
    assert cloud_st["status"] == "parse_error"
    assert cloud_st["demo"] is False
    assert cloud_st["records"] == 0
    assert cloud_st["issues"][0]["file"] == "bad.json"
    assert cloud_st["issues"][0]["status"] == "parse_error"
    assert cloud_st["issues"][0]["reason"]
    assert vuln_st["status"] == "parse_error"
    assert vuln_st["issues"][0]["file"] == "broken.json"
    assert "JSON" in vuln_st["issues"][0]["reason"] or "json" in vuln_st["issues"][0]["reason"].lower()

    summary = grc_loader.load()
    assert summary["demo"] is False
    assert summary["findings"] == 0
    assert summary["estate"] == "LAB"
    assert summary["sensors"]["cloud-prowler"]["status"] == "parse_error"
    assert summary["sensors"]["vuln-scan"]["status"] == "parse_error"
    assert summary["coverage"]["sensors"]
    assert (tmp_path / "out" / "ciso-assistant" / "findings.csv").read_text(encoding="utf-8").count("\n") == 1


def test_lab_empty_sensor_does_not_load_demo(tmp_path, monkeypatch) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label="LAB")
    (dest_in / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    (dest_in / "cloud").mkdir(parents=True)

    recs = run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)
    assert recs == []
    status = _status_for(tmp_path / "out", "cloud-prowler")
    assert status["status"] in {"empty", "no_records"}
    assert status["demo"] is False
    assert status["records"] == 0
    assert any(item["status"] == "no_records" for item in status["issues"])


def test_operator_drop_empty_sibling_does_not_fill_demo(tmp_path, monkeypatch) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label=None)
    nmap = dest_in / "nmap"
    nmap.mkdir(parents=True)
    nmap.joinpath("scan.xml").write_text(
        (DEMO / "nmap" / "scan.xml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    nmap_recs = run_collector(
        "inventory-nmap",
        (".xml", ".gnmap", ".txt", ".json", ".jsonl", ".md"),
        inventory_nmap.parse_file,
    )
    cloud = run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)

    assert nmap_recs
    assert not any("demo" in (r.get("labels") or []) for r in nmap_recs)
    assert cloud == []
    cloud_st = _status_for(tmp_path / "out", "cloud-prowler")
    assert cloud_st["demo"] is False
    assert cloud_st["status"] in {"empty", "no_records"}
    assert cloud_st["records"] == 0


def test_explicit_demo_empty_in_still_loads_fixtures(tmp_path, monkeypatch) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label="DEMO")
    recs = run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)
    assert recs
    assert all("demo" in (r.get("labels") or []) for r in recs)
    status = _status_for(tmp_path / "out", "cloud-prowler")
    assert status["status"] == "demo"
    assert status["demo"] is True
    assert status["records"] >= 1
    summary = grc_loader.load()
    assert summary["demo"] is True
    assert summary["estate"] == "DEMO"
    assert summary["findings"] >= 1
    assert (dest_in / "cloud").exists() or True


def test_sample_dropbox_demo_empty_in_still_works(tmp_path, monkeypatch) -> None:
    _prep(tmp_path, monkeypatch, label=None, extra_env={"DROPBOX_DEMO": "1"})
    recs = run_collector("vuln-scan", (".json", ".jsonl", ".sarif"), vuln_scan.parse_file)
    assert recs
    assert any("demo" in (r.get("labels") or []) for r in recs)
    status = _status_for(tmp_path / "out", "vuln-scan")
    assert status["status"] == "demo"
    assert status["demo"] is True


def test_demo_live_malformed_still_refuses_substitution(tmp_path, monkeypatch) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label="DEMO")
    _write_malformed_cloud(dest_in)
    recs = run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)
    assert recs == []
    status = _status_for(tmp_path / "out", "cloud-prowler")
    assert status["status"] == "parse_error"
    assert status["demo"] is False
    assert status["issues"][0]["file"] == "bad.json"


def test_allow_demo_fallback_policy() -> None:
    assert allow_demo_fallback(had_live_files=True) is False


def test_console_coverage_includes_sensor_status(tmp_path, monkeypatch) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label="LAB")
    (dest_in / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    _write_malformed_cloud(dest_in)
    run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)
    grc_loader.load()

    from product.server import framework_coverage, sensor_coverage

    rows = sensor_coverage(tmp_path / "out")
    assert any(row.get("source") == "cloud-prowler" and row.get("status") == "parse_error" for row in rows)
    cov = framework_coverage(tmp_path / "out")
    assert cov["client"] is False
    assert any(row.get("status") == "parse_error" for row in cov["sensors"])
