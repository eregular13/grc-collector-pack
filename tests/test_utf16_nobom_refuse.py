"""UTF-16 without a BOM must refuse loudly, not silent-zero or mojibake."""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.io_util import UnrecognizedShape, decode_text, read_text


def test_utf16_le_without_bom_refused() -> None:
    raw = "row-one\nrow-two\n".encode("utf-16-le")  # no BOM
    assert raw[:2] != b"\xff\xfe"
    with pytest.raises(UnrecognizedShape, match="UTF-16 without a byte-order mark"):
        decode_text(raw)


def test_utf16_be_without_bom_refused() -> None:
    raw = "row-one\n".encode("utf-16-be")
    with pytest.raises(UnrecognizedShape, match="UTF-16 without a byte-order mark"):
        decode_text(raw)


def test_read_text_utf16_nobom_file(tmp_path: Path) -> None:
    dest = tmp_path / "report.txt"
    dest.write_bytes("demo-content\n".encode("utf-16-le"))
    with pytest.raises(UnrecognizedShape):
        read_text(dest)


def test_utf8_with_nul_bytes_still_decodes() -> None:
    # A short UTF-8 blob that happens to contain a NUL must not trip the refuse path.
    raw = b"ok\x00still-utf8"
    assert "still-utf8" in decode_text(raw)
