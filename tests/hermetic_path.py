"""Isolate PATH / FARM_TOOL_BIN so host scanners cannot flip farm_which.

In-process farm_which falls through to shutil.which(PATH). Tests that assert
demo_stub / present / will_run / live_ready must not see a system nmap (or
curl / lynis / nessus) installed on the runner. Empty PATH would also hide
python3, so subprocess CLI tests keep a temp bin with python3/python
symlinks and nothing else.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _place_hermetic_bin(hermetic: Path, name: str, target: Path, *, win32: bool) -> None:
    """Symlink on POSIX. Windows: ``name.cmd`` shim (no symlink privilege)."""
    target = Path(target).resolve()
    if win32:
        dest = hermetic / f"{name}.cmd"
        if dest.exists():
            dest.unlink()
        dest.write_text(f'@echo off\r\n"{target}" %*\r\n', encoding="ascii")
        return
    dest = hermetic / name
    if dest.exists() or dest.is_symlink():
        dest.unlink()
    dest.symlink_to(target)


def isolate_farm_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    farm_tool_bin: Path | None = None,
    extra_bins: dict[str, Path] | None = None,
    keep_python: bool = True,
) -> Path:
    """Set PATH to a temp bin; unset FARM_TOOL_BIN unless farm_tool_bin is given.

    extra_bins maps a PATH name to an existing file to symlink in (for tests
    that need a fake host binary *inside* the isolated PATH).
    """
    hermetic = tmp_path / "hermetic-bin"
    hermetic.mkdir(parents=True, exist_ok=True)
    win32 = sys.platform == "win32"
    if keep_python:
        exe = Path(sys.executable).resolve()
        for name in ("python3", "python"):
            _place_hermetic_bin(hermetic, name, exe, win32=win32)
    if extra_bins:
        for name, src in extra_bins.items():
            _place_hermetic_bin(hermetic, name, Path(src), win32=win32)
    if farm_tool_bin is None:
        monkeypatch.delenv("FARM_TOOL_BIN", raising=False)
    else:
        monkeypatch.setenv("FARM_TOOL_BIN", str(farm_tool_bin))
    monkeypatch.setenv("PATH", str(hermetic))
    return hermetic
