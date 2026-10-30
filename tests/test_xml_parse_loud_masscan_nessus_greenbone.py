"""Malformed masscan / Nessus / Greenbone XML must raise, not return 0 rows."""

from __future__ import annotations

import pytest

from shared.greenbone import iter_greenbone_xml
from shared.masscan import _from_xml as masscan_from_xml
from shared.nessus import iter_nessus_items

_TRUNC = "<root><item>"
_NUL = "<root><item>x</item></root>\x00\x00\x00\x00"
_XXE = """<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
<r>&xxe;</r>
"""


@pytest.mark.parametrize("payload", [_TRUNC, _NUL, _XXE], ids=["truncated", "trailing_nul", "doctype_entity"])
def test_masscan_xml_parse_errors_loud(payload: str) -> None:
    with pytest.raises(ValueError, match="masscan XML parse error"):
        masscan_from_xml(payload)


@pytest.mark.parametrize("payload", [_TRUNC, _NUL, _XXE], ids=["truncated", "trailing_nul", "doctype_entity"])
def test_nessus_xml_parse_errors_loud(payload: str) -> None:
    with pytest.raises(ValueError, match="nessus XML parse error"):
        iter_nessus_items(payload)


@pytest.mark.parametrize("payload", [_TRUNC, _NUL, _XXE], ids=["truncated", "trailing_nul", "doctype_entity"])
def test_greenbone_xml_parse_errors_loud(payload: str) -> None:
    with pytest.raises(ValueError, match="greenbone XML parse error"):
        list(iter_greenbone_xml(payload))
