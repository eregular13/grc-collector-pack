"""in/code/ drops (SARIF, gitleaks, trufflehog, checkov) reach the register and POA&M.

Synthetic fixtures from fixtures/demo/code only.
"""
from __future__ import annotations

import csv
import shutil
from pathlib import Path

from dropbox.orchestrator.ciso_path import SENSOR_COLLECTORS, run_ciso_path, unread_sensor_dirs
from dropbox.scope import ROOT

SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
CODE = ROOT / "fixtures" / "demo" / "code"
FILES = ("semgrep.sarif.json", "gitleaks.json", "trufflehog.jsonl", "checkov.json")


def _drop(dest_in: Path) -> None:
    code = dest_in / "code"
    code.mkdir(parents=True)
    for name in FILES:
        shutil.copy2(CODE / name, code / name)


def test_code_dir_is_a_known_sensor(tmp_path: Path) -> None:
    assert SENSOR_COLLECTORS.get("code") == "code_secrets.py"
    _drop(tmp_path / "in")
    assert unread_sensor_dirs(tmp_path / "in") == []


def test_code_drop_reaches_register_and_poam(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    dest_out = tmp_path / "out"
    _drop(dest_in)
    result = run_ciso_path(dest_in, dest_out, scope_path=SCOPE, write_pack_in=False)
    assert "code" in result["sensors"]
    assert "code_secrets.py" in result["collectors"]
    findings = (dest_out / "ciso-assistant" / "findings.csv").read_text(encoding="utf-8")
    with (dest_out / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        poam = list(csv.DictReader(fh))
    blob = " ".join(" ".join(str(v) for v in row.values()) for row in poam).lower()
    for tool in ("gitleaks", "trufflehog", "checkov", "semgrep"):
        assert tool in findings.lower() or tool in blob, f"{tool} missing from register/POA&M"
    assert any("code-secrets" in " ".join(str(v) for v in r.values()) for r in poam)
