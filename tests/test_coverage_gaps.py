"""Lab-report mode, unread-file coverage, and client-page Coverage gaps.

Estate kind from classify_estate is the source of truth. Unrecognized
shape vs parse_error vs no_records must be named (file + reason) in
out/coverage/sensors, summary.json, and /api/coverage. LAB/SAMPLE/DEMO
is never client KEEP. Never POST /api/risks.
"""

from __future__ import annotations

import importlib
import json
import threading
import urllib.request
from pathlib import Path

import pytest

from collectors import cloud_prowler, code_secrets, grc_loader, vuln_scan
from shared.estate_pages import (
    COVERAGE_GAPS_HEADING,
    COVERAGE_GAPS_NONE,
    LABEL_FOR_KIND,
    MAX_PAGE_LINES,
    classify_estate,
)
from shared.io_util import UNRECOGNIZED_STATUS, load_sensor_coverage, run_collector

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"


def _prep(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, label: str | None) -> Path:
    dest_in = tmp_path / "in"
    dest_out = tmp_path / "out"
    dest_in.mkdir(parents=True)
    dest_out.mkdir(parents=True)
    monkeypatch.setenv("IN_DIR", str(dest_in))
    monkeypatch.setenv("OUT_DIR", str(dest_out))
    monkeypatch.setenv("FIXTURES_DIR", str(DEMO))
    monkeypatch.delenv("DROPBOX_DEMO", raising=False)
    monkeypatch.delenv("GRC_CLIENT_NAME", raising=False)
    monkeypatch.delenv("GRC_AUTHORIZER", raising=False)
    monkeypatch.delenv("GRC_AUTH_DATE", raising=False)
    monkeypatch.delenv("GRC_SCOPE_REF", raising=False)
    if label:
        monkeypatch.setenv("GRC_ESTATE_LABEL", label)
    else:
        monkeypatch.delenv("GRC_ESTATE_LABEL", raising=False)
    return dest_in


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


def _finding(labels: list[str] | None = None) -> dict:
    return {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "f1",
        "name": "FTP exposed f1",
        "description": "f1 has open TCP/21 (ftp).",
        "severity": "high",
        "category": "exposure",
        "assets": ["host-a"],
        "labels": labels or ["nmap"],
        "extra": {"port": "21", "service": "ftp", "ip": "10.0.0.5"},
    }


def _run_loader_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    records: list[dict],
    **env: str,
) -> Path:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    with (out / "canonical" / "inventory-nmap.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("FIXTURES_DIR", str(DEMO))
    for key in (
        "GRC_ESTATE_LABEL",
        "DROPBOX_DEMO",
        "GRC_CLIENT_NAME",
        "GRC_HIDE_ESTATE",
        "GRC_AUTHORIZER",
        "GRC_AUTH_DATE",
        "GRC_SCOPE_REF",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    return out


def _status(out: Path, source: str) -> dict:
    rows = load_sensor_coverage(out)
    return next(row for row in rows if row["source"] == source)


def _issue(status: dict, name: str) -> dict:
    return next(item for item in status["issues"] if item.get("file") == name)


@pytest.mark.parametrize(
    ("kind", "env", "labels"),
    [
        ("DEMO", {"GRC_ESTATE_LABEL": "DEMO"}, ["nmap", "demo"]),
        ("SAMPLE", {"GRC_ESTATE_LABEL": "SAMPLE"}, ["nmap"]),
        ("LAB", {"GRC_ESTATE_LABEL": "LAB"}, ["nmap"]),
        (
            "CLIENT",
            {
                "GRC_ESTATE_LABEL": "CLIENT",
                "GRC_CLIENT_NAME": "Acme Corp",
                "GRC_AUTHORIZER": "Jane Roe",
                "GRC_AUTH_DATE": "2026-09-20",
            },
            ["nmap"],
        ),
    ],
)
def test_lab_report_mode_matches_estate_kind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    env: dict[str, str],
    labels: list[str],
) -> None:
    stamp = classify_estate(
        [_finding(labels)],
        env={**env},
        client_name=env.get("GRC_CLIENT_NAME"),
    )
    assert stamp.kind == kind
    out = _run_loader_records(
        tmp_path,
        monkeypatch,
        [_asset(), _finding(labels)],
        **env,
    )
    report = (out / "evidence" / "lab-report.md").read_text(encoding="utf-8")
    assert f"{kind} mode" in report
    assert "Demo mode" not in report
    if kind == "CLIENT":
        assert "CLIENT mode" in report
    else:
        assert "CLIENT mode" not in report
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["estate_kind"] == kind
    if kind != "CLIENT":
        assert summary.get("client") is False
    else:
        assert summary.get("client") is True


def test_lab_sample_demo_never_client_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader_records(
        tmp_path,
        monkeypatch,
        [_asset(), _finding(["nmap", "demo"])],
        GRC_ESTATE_LABEL="CLIENT",
        GRC_CLIENT_NAME="Acme Corp",
    )
    report = (out / "evidence" / "lab-report.md").read_text(encoding="utf-8")
    assert "CLIENT mode" not in report
    assert "Demo mode" not in report
    assert any(tok in report for tok in ("DEMO mode", "SAMPLE mode", "MIXED mode"))


def _drop_gap_files(dest_in: Path) -> None:
    (dest_in / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    cloud = dest_in / "cloud"
    cloud.mkdir(parents=True)
    (cloud / "notes.txt").write_text("not prowler json\n", encoding="utf-8")
    vuln = dest_in / "vuln"
    vuln.mkdir(parents=True)
    (vuln / "broken.json").write_text("{not-json", encoding="utf-8")
    code = dest_in / "code"
    code.mkdir(parents=True)
    (code / "empty.json").write_text("[]\n", encoding="utf-8")


def _run_gap_collectors() -> None:
    run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)
    run_collector(
        "vuln-scan",
        (".json", ".jsonl", ".sarif", ".txt", ".xml", ".nessus", ".csv"),
        vuln_scan.parse_file,
    )
    run_collector("code-secrets", (".json", ".jsonl", ".sarif"), code_secrets.parse_file)
    grc_loader.load()


def test_unread_parse_error_no_records_named_in_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label="LAB")
    _drop_gap_files(dest_in)
    _run_gap_collectors()
    out = tmp_path / "out"

    unread = _status(out, "cloud-prowler")
    assert unread["status"] == UNRECOGNIZED_STATUS
    assert unread["demo"] is False
    assert unread["records"] == 0
    assert "notes.txt" in unread["unread"]
    issue = _issue(unread, "notes.txt")
    assert issue["status"] == UNRECOGNIZED_STATUS
    assert "notes.txt" == issue["file"]
    assert "unrecognized shape" in issue["reason"]
    assert ".txt" in issue["reason"]

    broken = _status(out, "vuln-scan")
    assert broken["status"] == "parse_error"
    parse_issue = _issue(broken, "broken.json")
    assert parse_issue["status"] == "parse_error"
    assert parse_issue["file"] == "broken.json"
    assert "JSON" in parse_issue["reason"] or "json" in parse_issue["reason"].lower()

    empty = _status(out, "code-secrets")
    assert empty["status"] == "no_records"
    empty_issue = _issue(empty, "empty.json")
    assert empty_issue["status"] == "no_records"
    assert empty_issue["file"] == "empty.json"
    assert "no records" in empty_issue["reason"]

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["estate_kind"] == "LAB"
    assert summary["sensors"]["cloud-prowler"]["status"] == UNRECOGNIZED_STATUS
    assert summary["sensors"]["vuln-scan"]["status"] == "parse_error"
    assert summary["sensors"]["code-secrets"]["status"] == "no_records"
    by_source = {row["source"]: row for row in summary["coverage"]["sensors"]}
    assert by_source["cloud-prowler"]["issues"][0]["file"] == "notes.txt"
    assert by_source["vuln-scan"]["issues"][0]["file"] == "broken.json"
    assert by_source["code-secrets"]["issues"][0]["file"] == "empty.json"

    from product.server import framework_coverage, sensor_coverage

    rows = sensor_coverage(out)
    assert any(
        row.get("source") == "cloud-prowler" and row.get("status") == UNRECOGNIZED_STATUS
        for row in rows
    )
    assert any(
        row.get("source") == "vuln-scan" and row.get("status") == "parse_error" for row in rows
    )
    assert any(
        row.get("source") == "code-secrets" and row.get("status") == "no_records" for row in rows
    )
    cov = framework_coverage(out)
    assert cov["client"] is False
    cov_by = {row["source"]: row for row in cov["sensors"]}
    assert cov_by["cloud-prowler"]["issues"][0]["file"] == "notes.txt"
    assert cov_by["vuln-scan"]["issues"][0]["file"] == "broken.json"
    assert cov_by["code-secrets"]["issues"][0]["file"] == "empty.json"

    httpd = None
    try:
        from product.server import make_server

        httpd = make_server("127.0.0.1", 0)
        host, port = httpd.server_address[:2]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        with urllib.request.urlopen(f"http://{host}:{port}/api/coverage", timeout=5) as res:
            payload = json.loads(res.read().decode("utf-8"))
        assert payload["client"] is False
        api_by = {row["source"]: row for row in payload["sensors"]}
        assert api_by["cloud-prowler"]["status"] == UNRECOGNIZED_STATUS
        assert api_by["cloud-prowler"]["issues"][0]["file"] == "notes.txt"
        assert api_by["vuln-scan"]["issues"][0]["file"] == "broken.json"
        assert api_by["code-secrets"]["issues"][0]["file"] == "empty.json"
    finally:
        if httpd is not None:
            httpd.shutdown()


def test_coverage_gaps_section_lists_failed_sensors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label="LAB")
    _drop_gap_files(dest_in)
    _run_gap_collectors()
    out = tmp_path / "out"
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    trust = (out / "SCOPE_AND_TRUST.md").read_text(encoding="utf-8")
    for blob in (exec_text, trust):
        assert COVERAGE_GAPS_HEADING in blob
        assert COVERAGE_GAPS_NONE not in blob
        assert "cloud-prowler" in blob
        assert "notes.txt" in blob
        assert UNRECOGNIZED_STATUS in blob
        assert "vuln-scan" in blob
        assert "broken.json" in blob
        assert "parse_error" in blob
        assert "code-secrets" in blob
        assert "empty.json" in blob
        assert "no_records" in blob
        assert LABEL_FOR_KIND["LAB"] in blob
        assert "CLIENT:" not in blob.splitlines()[0]
        assert len(blob.splitlines()) <= MAX_PAGE_LINES


def test_coverage_gaps_none_when_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader_records(
        tmp_path,
        monkeypatch,
        [_asset(), _finding(["nmap"])],
        GRC_ESTATE_LABEL="SAMPLE",
    )
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    trust = (out / "SCOPE_AND_TRUST.md").read_text(encoding="utf-8")
    for blob in (exec_text, trust):
        assert COVERAGE_GAPS_HEADING in blob
        assert COVERAGE_GAPS_NONE in blob
        assert "None" in blob
        assert len(blob.splitlines()) <= MAX_PAGE_LINES


def test_unread_file_does_not_look_like_empty_sensor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest_in = _prep(tmp_path, monkeypatch, label="LAB")
    (dest_in / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    cloud = dest_in / "cloud"
    cloud.mkdir(parents=True)
    (cloud / "notes.txt").write_text("not prowler\n", encoding="utf-8")
    recs = run_collector("cloud-prowler", (".json",), cloud_prowler.parse_file)
    assert recs == []
    status = _status(tmp_path / "out", "cloud-prowler")
    assert status["status"] == UNRECOGNIZED_STATUS
    assert status["status"] != "empty"
    assert not any("empty sensor" in str(item.get("reason") or "") for item in status["issues"])
    assert status["issues"][0]["file"] == "notes.txt"
