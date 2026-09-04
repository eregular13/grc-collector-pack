from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_riskready_wrap_cannot_post() -> None:
    text = (ROOT / "push_riskready.sh").read_text(encoding="utf-8")
    assert "LICENSE-LOCK" in text
    assert "curl" not in text
    assert not re.search(r"curl\s+", text)


def test_repo_has_no_riskready_login_wrap() -> None:
    banned = re.compile(r"curl[^\n]*/auth/login")
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(
            part in {".git", "product-lab", "__pycache__", ".pytest_cache", "tests"}
            for part in path.parts
        ):
            continue
        if path.suffix.lower() not in {".sh", ".py", ".ps1", ".ts", ".js"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        assert not banned.search(text), path
