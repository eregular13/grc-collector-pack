"""CSV parsing refuses duplicate headers and tolerates trailing NUL / quoted newlines."""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.io_util import read_csv_dicts, read_text


def test_duplicate_headers_refuse() -> None:
    text = "host,host,finding\na,b,c\n"
    with pytest.raises(ValueError, match="duplicate header"):
        read_csv_dicts(text)


def test_trailing_nul_does_not_invent_rows(tmp_path: Path) -> None:
    dest = tmp_path / "rows.csv"
    dest.write_bytes(b"host,finding\na,one\nb,two\n\x00\x00")
    text = read_text(dest)
    rows = read_csv_dicts(text)
    assert len(rows) == 2
    assert rows[0]["host"] == "a"


def test_quoted_embedded_newline_kept() -> None:
    text = 'id,name\n1,"line1\nline2"\n'
    rows = read_csv_dicts(text)
    assert len(rows) == 1
    assert "line1\nline2" in rows[0]["name"]


def test_greenbone_csv_dup_header_loud() -> None:
    from shared.greenbone import iter_greenbone_csv

    text = "IP,IP,NVT Name\n1.2.3.4,1.2.3.4,demo\n"
    with pytest.raises(ValueError, match="duplicate header"):
        list(iter_greenbone_csv(text))
