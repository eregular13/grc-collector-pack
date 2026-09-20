"""Windows-safe keep/work wipe. SAMPLE path leftover out/ must not raise WinError 145."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path

from keep.ciso_import import CISO_REQUIRED
from keep.lab import keep_lab
from keep.wipe import reset_dir, retryable_wipe_error, wipe_tree

ROOT = Path(__file__).resolve().parents[1]


def _nested_out(folder: Path) -> Path:
    """Leftover keep/work/out tree like sample_to_sor leaves on DESKTOP."""
    nested = folder / "ciso-assistant" / "nested"
    nested.mkdir(parents=True)
    (nested / "stale.csv").write_text("ref_id,name\nSTALE,left-behind\n", encoding="utf-8")
    (folder / "summary.json").write_text("{}\n", encoding="utf-8")
    (folder / "canonical" / "cloud-prowler.jsonl").parent.mkdir(parents=True, exist_ok=True)
    (folder / "canonical" / "cloud-prowler.jsonl").write_text("{}\n", encoding="utf-8")
    return folder


def test_keep_lab_and_keep_ciso_do_not_call_bare_rmtree() -> None:
    lab = (ROOT / "keep" / "lab.py").read_text(encoding="utf-8")
    stub = (ROOT / "dropbox" / "mcp_stub.py").read_text(encoding="utf-8")
    assert "shutil.rmtree" not in lab
    assert "reset_dir" in lab
    assert "from keep.wipe import reset_dir" in stub
    assert "shutil.rmtree" not in stub


def test_retryable_wipe_error_covers_winerror_145() -> None:
    exc = OSError(145, "The directory is not empty")
    exc.winerror = 145
    assert retryable_wipe_error(exc) is True
    assert retryable_wipe_error(OSError(errno.ENOTEMPTY, "Directory not empty")) is True
    assert retryable_wipe_error(ValueError("nope")) is False


def test_wipe_tree_clears_nonempty_nested_out(tmp_path: Path) -> None:
    target = _nested_out(tmp_path / "out")
    assert (target / "ciso-assistant" / "nested" / "stale.csv").is_file()
    wipe_tree(target)
    assert not target.exists()


def test_wipe_tree_clears_readonly_nested_file(tmp_path: Path) -> None:
    target = _nested_out(tmp_path / "out")
    stubborn = target / "ciso-assistant" / "nested" / "stale.csv"
    os.chmod(stubborn, 0o444)
    wipe_tree(target)
    assert not target.exists()


def test_wipe_tree_retries_winerror_145(tmp_path: Path, monkeypatch) -> None:
    target = _nested_out(tmp_path / "out")
    real_rmdir = os.rmdir
    state = {"n": 0}

    def flaky_rmdir(path):
        state["n"] += 1
        if state["n"] == 1:
            err = OSError(145, "The directory is not empty")
            err.winerror = 145
            raise err
        return real_rmdir(path)

    monkeypatch.setattr(os, "rmdir", flaky_rmdir)
    wipe_tree(target)
    assert not target.exists()
    assert state["n"] >= 2


def test_wipe_tree_missing_path_is_noop(tmp_path: Path) -> None:
    missing = tmp_path / "keep" / "work" / "out"
    wipe_tree(missing)
    assert not missing.exists()


def test_reset_dir_recreates_empty_out(tmp_path: Path) -> None:
    target = _nested_out(tmp_path / "out")
    reset_dir(target)
    assert target.is_dir()
    assert list(target.iterdir()) == []


def test_keep_lab_wipes_leftover_out_then_emits_ciso_csvs(tmp_path: Path) -> None:
    """sample_to_sor leftovers in keep/work/out must not block keep_ciso / keep-lab."""
    empty = tmp_path / "empty-in"
    empty.mkdir()
    work = tmp_path / "work"
    _nested_out(work / "out")
    stamp = keep_lab(ROOT, pack_in=empty, work=work)
    assert stamp["status"] == "pass", stamp.get("reason")
    ciso = work / "out" / "ciso-assistant"
    for name in CISO_REQUIRED:
        assert (ciso / name).is_file()
        assert (ciso / name).stat().st_size > 0
    assert not (ciso / "nested" / "stale.csv").exists()


def test_keep_lab_wipe_work_then_keep_lab_emits_ciso_csvs(tmp_path: Path) -> None:
    """Dual stranger path: keep-lab → wipe keep/work → keep-lab still emits the four CSVs."""
    empty = tmp_path / "empty-in"
    empty.mkdir()
    work = tmp_path / "work"
    first = keep_lab(ROOT, pack_in=empty, work=work)
    assert first["status"] == "pass", first.get("reason")
    for name in CISO_REQUIRED:
        assert (work / "out" / "ciso-assistant" / name).is_file()
    wipe_tree(work)
    assert not work.exists() or not any(work.rglob("*.csv"))
    second = keep_lab(ROOT, pack_in=empty, work=work)
    assert second["status"] == "pass", second.get("reason")
    ciso = work / "out" / "ciso-assistant"
    for name in CISO_REQUIRED:
        path = ciso / name
        assert path.is_file(), name
        assert path.stat().st_size > 0
    import_doc = json.loads((ciso / "IMPORT.json").read_text(encoding="utf-8"))
    assert import_doc["sample"] is True
    assert import_doc["paying_day"] == "FAIL"
    assert import_doc["client_keep"] is False
