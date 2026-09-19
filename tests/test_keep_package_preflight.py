"""Fail-closed keep package check for cold SAMPLE→SoR.

A partial copy / corrupt cold-path-gate tree must name the missing
path and demand a full git clone — not ModuleNotFoundError.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from dropbox.keep_preflight import (
    KEEP_PACKAGE_CLONE,
    KEEP_PACKAGE_FILES,
    KEEP_PACKAGE_HINT,
    KeepPackageIncomplete,
    check_keep_package,
    keep_package_incomplete_message,
    require_keep_package,
)
from dropbox.mcp_stub import dispatch
from dropbox.scope import GateError

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sample_to_sor.sh"
PS1 = ROOT / "scripts" / "sample_to_sor.ps1"
SCOPE = ROOT / "dropbox" / "SCOPE.yaml"


def _partial_keep(tmp_path: Path, *, skip: str = "keep/__main__.py") -> Path:
    keep = tmp_path / "keep"
    keep.mkdir()
    for rel in KEEP_PACKAGE_FILES:
        if rel == skip:
            continue
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# partial checkout stub\n", encoding="utf-8")
    return tmp_path / skip


def test_require_keep_package_fails_closed_when_main_missing(tmp_path: Path) -> None:
    missing = _partial_keep(tmp_path)
    assert not missing.is_file()
    report = check_keep_package(tmp_path)
    assert report["ok"] is False
    assert any(str(missing) == item or item.endswith("keep/__main__.py") for item in report["missing"])
    with pytest.raises(KeepPackageIncomplete, match="keep/__main__.py") as excinfo:
        require_keep_package(tmp_path)
    msg = str(excinfo.value)
    assert KEEP_PACKAGE_CLONE in msg
    assert "full git clone" in msg
    assert "cold-path-gate" in msg
    assert "keep/__main__.py" in msg
    helper_msg = keep_package_incomplete_message(tmp_path)
    assert "keep/__main__.py" in helper_msg
    assert KEEP_PACKAGE_HINT in helper_msg


def test_require_keep_package_ok_on_full_clone() -> None:
    assert require_keep_package(ROOT) == ROOT
    report = check_keep_package(ROOT)
    assert report["ok"] is True
    assert report["missing"] == []
    assert report["message"] == ""


def test_require_keep_package_ok_on_complete_temp_tree(tmp_path: Path) -> None:
    for rel in KEEP_PACKAGE_FILES:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# stub\n", encoding="utf-8")
    assert require_keep_package(tmp_path) == tmp_path
    env = os.environ.copy()
    env["PYTHONPATH"] = "/unrelated"
    report = check_keep_package(tmp_path, pythonpath=env["PYTHONPATH"], require_pythonpath=True)
    assert report["ok"] is False
    assert "PYTHONPATH" in str(report["message"])
    assert KEEP_PACKAGE_CLONE in str(report["message"])


def test_sample_to_sor_scripts_name_keep_files_and_full_clone() -> None:
    sh = SCRIPT.read_text(encoding="utf-8")
    ps1 = PS1.read_text(encoding="utf-8")
    for blob in (sh, ps1):
        assert "keep/__main__.py" in blob or "keep\\__main__.py" in blob
        assert "keep/lab.py" in blob or "keep\\lab.py" in blob
        assert "keep/adapters.py" in blob or "keep\\adapters.py" in blob
        assert KEEP_PACKAGE_CLONE in blob
        assert "full git clone" in blob
        assert "cold-path-gate" in blob
        assert "require_keep_package" in blob.lower() or "Require-KeepPackage" in blob


def test_sample_to_sor_sh_fails_closed_on_partial_clone(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    dest = scripts / "sample_to_sor.sh"
    dest.write_text(SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
    dest.chmod(0o755)
    _partial_keep(tmp_path)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(tmp_path)
    proc = subprocess.run(
        ["bash", str(dest), "--verify-only"],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    blob = (proc.stderr or "") + (proc.stdout or "")
    assert "ModuleNotFoundError" not in blob
    assert "keep/__main__.py" in blob
    assert "full git clone" in blob
    assert KEEP_PACKAGE_CLONE in blob
    assert "cold-path-gate" in blob


def test_keep_status_and_keep_ciso_fail_closed_when_keep_package_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _partial_keep(tmp_path)
    monkeypatch.setattr("dropbox.mcp_stub._repo_root", lambda: tmp_path)
    with pytest.raises(GateError, match="keep/__main__.py") as status_exc:
        dispatch("keep_status", scope_path=SCOPE)
    status_msg = str(status_exc.value)
    assert KEEP_PACKAGE_CLONE in status_msg
    assert "full git clone" in status_msg
    assert "ModuleNotFoundError" not in status_msg
    with pytest.raises(GateError, match="full git clone") as ciso_exc:
        dispatch("keep_ciso", scope_path=SCOPE)
    assert "keep/__main__.py" in str(ciso_exc.value)
    assert KEEP_PACKAGE_CLONE in str(ciso_exc.value)
