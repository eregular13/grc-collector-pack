"""Refuse empty / deeply nested JSON that used to silent-zero."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.io_util import load_json_prefer, read_json


def test_normal_object_ok(tmp_path: Path) -> None:
    p = tmp_path / "ok.json"
    p.write_text(json.dumps({"results": [{"id": 1}]}), encoding="utf-8")
    assert read_json(p) == {"results": [{"id": 1}]}


def test_empty_object_refused(tmp_path: Path) -> None:
    p = tmp_path / "empty-object.json"
    p.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="empty JSON object refused"):
        read_json(p)


def test_empty_file_still_empty_decode_error(tmp_path: Path) -> None:
    # Empty file remains JSONDecodeError("empty"); load_json_prefer maps to {}.
    p = tmp_path / "empty-file.json"
    p.write_bytes(b"")
    with pytest.raises(json.JSONDecodeError, match="empty"):
        read_json(p)
    assert load_json_prefer(p) == {}


def test_deeply_nested_refused(tmp_path: Path) -> None:
    node: dict = {}
    cur = node
    for _ in range(70):
        nxt: dict = {}
        cur["n"] = nxt
        cur = nxt
    p = tmp_path / "deep.json"
    p.write_text(json.dumps(node), encoding="utf-8")
    with pytest.raises(ValueError, match="deeply nested"):
        read_json(p)




def test_load_json_prefer_empty_object_refused(tmp_path: Path) -> None:
    p = tmp_path / "empty-object.json"
    p.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="empty JSON object refused"):
        load_json_prefer(p)


def test_code_secrets_empty_object_loud(tmp_path: Path) -> None:
    from collectors.code_secrets import parse_file

    p = tmp_path / "gitleaks.json"
    p.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="empty JSON object refused"):
        parse_file(p)
