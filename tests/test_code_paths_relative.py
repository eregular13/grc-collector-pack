"""Code-scanner file paths are made relative to the scanned root; no absolute/home path leaks.

Synthetic paths only (/home/someuser/..., /Users/someone/..., C:\\Users\\someone\\...).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from collectors import code_secrets
from dropbox.orchestrator.ciso_path import run_ciso_path
from dropbox.scope import ROOT

SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
BASE = "/home/someuser/work/scan-target"
LEAKS = ("/home/", "home/someuser", "someuser", "/Users/", "C:/Users", "C:\\Users")

GITLEAKS = [
    {"RuleID": "generic-api-key", "Description": "Generic API Key", "File": f"{BASE}/src/app/config.py",
     "StartLine": 3, "Secret": "synthetic-not-a-secret-000", "Match": "x"},
    {"RuleID": "generic-api-key", "Description": "Generic API Key", "File": f"{BASE}/tests/keys.py",
     "StartLine": 9, "Secret": "synthetic-not-a-secret-001", "Match": "y"},
]
TRUFFLEHOG = {"DetectorName": "AWS", "Verified": False, "Raw": "synthetic",
              "SourceMetadata": {"Data": {"Filesystem": {"file": f"{BASE}/src/app/aws.py", "line": 1}}}}
SEMGREP = {"results": [
    {"check_id": "python.lang.security.audit.eval", "path": f"{BASE}/src/app/run.py",
     "extra": {"message": "eval use", "severity": "ERROR"}},
    {"check_id": "python.lang.security.audit.exec", "path": f"{BASE}/src/lib/x.py",
     "extra": {"message": "exec use", "severity": "WARNING"}},
]}
SARIF = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}}, "results": [
    {"ruleId": "r1", "level": "error", "message": {"text": "eval use"},
     "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"file://{BASE}/src/app/run.py"}}}]},
    {"ruleId": "r2", "level": "warning", "message": {"text": "exec use"},
     "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"file://{BASE}/src/lib/x.py"}}}]},
]}]}
CHECKOV = {"check_type": "terraform", "results": {"failed_checks": [
    {"check_id": "CKV_AWS_20", "check_name": "S3 bucket public", "file_path": "/main.tf",
     "file_abs_path": f"{BASE}/infra/main.tf", "resource": "aws_s3_bucket.b"}]}}


def _write(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "gitleaks.json").write_text(json.dumps(GITLEAKS), encoding="utf-8")
    (d / "trufflehog.jsonl").write_text(json.dumps(TRUFFLEHOG) + "\n", encoding="utf-8")
    (d / "semgrep.json").write_text(json.dumps(SEMGREP), encoding="utf-8")
    (d / "semgrep.sarif").write_text(json.dumps(SARIF), encoding="utf-8")
    (d / "checkov.json").write_text(json.dumps(CHECKOV), encoding="utf-8")


def _no_leak(text: str, where: str) -> None:
    for bad in LEAKS:
        assert bad not in text, f"{where}: leaked {bad!r}"


@pytest.mark.parametrize("name", ["gitleaks.json", "trufflehog.jsonl", "semgrep.json", "semgrep.sarif", "checkov.json"])
def test_parser_assets_are_relative(name: str, tmp_path: Path) -> None:
    _write(tmp_path)
    recs = code_secrets.parse_file(tmp_path / name)
    assert recs
    _no_leak(json.dumps(recs), name)
    for r in recs:
        for a in r["assets"]:
            assert not a.startswith("/") and ":" not in a, a


def test_multi_file_keeps_subdirs(tmp_path: Path) -> None:
    _write(tmp_path)
    assets = {a for r in code_secrets.parse_file(tmp_path / "gitleaks.json") for a in r["assets"]}
    assert {"src/app/config.py", "tests/keys.py"} <= assets


def test_windows_and_mac_home_paths(tmp_path: Path) -> None:
    rows = [dict(GITLEAKS[0], File="C:\\Users\\someone\\repo\\src\\a.py"),
            dict(GITLEAKS[1], File="/Users/someone/repo/b.py")]
    (tmp_path / "gitleaks.json").write_text(json.dumps(rows), encoding="utf-8")
    _no_leak(json.dumps(code_secrets.parse_file(tmp_path / "gitleaks.json")), "mixed")


def test_no_abs_path_in_any_output(tmp_path: Path) -> None:
    _write(tmp_path / "in" / "code")
    run_ciso_path(tmp_path / "in", tmp_path / "out", scope_path=SCOPE, write_pack_in=False)
    shutil.rmtree(tmp_path / "out" / "in", ignore_errors=True)  # staged copies of the inputs
    for p in (tmp_path / "out").rglob("*"):
        if p.is_file():
            _no_leak(p.read_text(encoding="utf-8", errors="replace"), str(p.relative_to(tmp_path)))


def test_checkov_root_relative_and_home_file_path(tmp_path: Path) -> None:
    rel = {"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_1", "check_name": "x", "file_path": "/infra/main.tf", "resource": "r"}]}}
    home = {"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_2", "check_name": "y", "file_path": f"{BASE}/infra/a.tf", "resource": "r"},
        {"check_id": "CKV_3", "check_name": "z", "file_path": f"{BASE}/modules/b.tf", "resource": "r"}]}}
    (tmp_path / "rel.json").write_text(json.dumps(rel), encoding="utf-8")
    (tmp_path / "home.json").write_text(json.dumps(home), encoding="utf-8")
    assert {a for r in code_secrets.parse_file(tmp_path / "rel.json") for a in r["assets"]} == {"infra/main.tf"}
    got = {a for r in code_secrets.parse_file(tmp_path / "home.json") for a in r["assets"]}
    assert got == {"infra/a.tf", "modules/b.tf"}
