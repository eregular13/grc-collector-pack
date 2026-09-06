"""Write clock-independent lab SCOPE files; rewrite expired inline test windows."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.scope_clock import EXPIRED_END, write_lab_scopes, with_open_window


@pytest.fixture(scope="session", autouse=True)
def _write_lab_scopes() -> None:
    write_lab_scopes()


@pytest.fixture(autouse=True)
def _inline_open_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    orig = Path.write_text

    def wrapped(self: Path, data: str | bytes, *args, **kwargs):
        if isinstance(data, str) and EXPIRED_END in data and "window_end" in data:
            data = with_open_window(data)
        return orig(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", wrapped)
