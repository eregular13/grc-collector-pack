"""smbmap CSV path uses read_csv_dicts: dup headers and restkey lists refuse/clean."""

from __future__ import annotations

import pytest

from shared.smbmap import _from_csv


def test_smbmap_csv_duplicate_header_refused() -> None:
    text = "host,share,share,privs\nfilesrv.example.invalid,C$,C$,READ\n"
    with pytest.raises(ValueError, match="duplicate header"):
        _from_csv(text)


def test_smbmap_csv_clean_parses() -> None:
    text = "host,share,privs,comment\nfilesrv.example.invalid,public,READ,ok\n"
    rows = _from_csv(text)
    assert rows is not None
    assert rows[0]["shares"][0]["name"] == "public"
