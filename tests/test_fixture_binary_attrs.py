"""Binary stress fixtures must not be text-normalized by .gitattributes.

fixtures/** is pinned text eol=lf; garbage-binary files carry raw CR/LF bytes,
so without an explicit -text they show as modified in every fresh checkout.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GB = "fixtures/keep-stress/garbage-binary"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True
    ).stdout


@pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(), reason="no git checkout")
def test_garbage_binary_fixtures_are_not_text_normalized() -> None:
    files = [f for f in _git("ls-files", GB).splitlines() if f]
    assert files
    for f in files:
        assert _git("check-attr", "text", "--", f).strip().endswith("text: unset"), f
    assert _git("status", "--porcelain", "--", GB).strip() == ""
