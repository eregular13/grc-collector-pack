"""UTF-16-with-BOM inputs decode; JSONL UTF-8 BOM must not drop line 1."""

from __future__ import annotations

import json
from pathlib import Path

from shared.io_util import decode_text, read_jsonl, read_text


def test_decode_text_utf16_le_bom() -> None:
    raw = b"\xff\xfe" + "finding-one\nfinding-two\n".encode("utf-16-le")
    assert raw[:2] == b"\xff\xfe"
    text = decode_text(raw)
    assert "finding-one" in text and "finding-two" in text


def test_decode_text_utf16_be_bom() -> None:
    raw = b"\xfe\xff" + "alpha\n".encode("utf-16-be")
    assert raw[:2] == b"\xfe\xff"
    assert "alpha" in decode_text(raw)


def test_read_text_utf16_le_bom_file(tmp_path: Path) -> None:
    dest = tmp_path / "report.txt"
    dest.write_bytes(b"\xff\xfe" + "hello-demo\n".encode("utf-16-le"))
    assert read_text(dest).strip() == "hello-demo"


def test_jsonl_utf8_bom_keeps_first_row(tmp_path: Path) -> None:
    dest = tmp_path / "rows.jsonl"
    body = json.dumps({"id": "first"}) + "\n" + json.dumps({"id": "second"}) + "\n"
    dest.write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
    rows = read_jsonl(dest)
    assert [r["id"] for r in rows] == ["first", "second"]
