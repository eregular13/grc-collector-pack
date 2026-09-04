from __future__ import annotations

import pytest

from shared import io_util


def test_out_dir_unset_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OUT_DIR", raising=False)
    with pytest.raises(SystemExit):
        io_util.out_dir()


def test_out_dir_missing_parent_fails(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    missing = tmp_path / "nope" / "deeper" / "out"
    monkeypatch.setenv("OUT_DIR", str(missing))
    with pytest.raises(SystemExit):
        io_util.out_dir()
