"""Broken .json must not become {} via a silent JSONL fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.io_util import load_json_prefer


def test_truncated_json_raises(tmp_path: Path) -> None:
    dest = tmp_path / "blob.json"
    dest.write_text('{"a":', encoding="utf-8")
    with pytest.raises(ValueError, match="refusing silent JSONL fallback"):
        load_json_prefer(dest)


def test_trailing_garbage_json_raises(tmp_path: Path) -> None:
    dest = tmp_path / "blob.json"
    dest.write_text('{"a": 1}\nNOTJSON\n', encoding="utf-8")
    with pytest.raises(ValueError, match="refusing silent JSONL fallback"):
        load_json_prefer(dest)


def test_jsonl_suffix_still_falls_back(tmp_path: Path) -> None:
    dest = tmp_path / "rows.jsonl"
    dest.write_text('{"id": 1}\n{"id": 2}\n', encoding="utf-8")
    rows = load_json_prefer(dest)
    assert isinstance(rows, list) and len(rows) == 2
