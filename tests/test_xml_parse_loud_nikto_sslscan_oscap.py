"""Malformed nikto / sslscan / OpenSCAP XML must raise, not return 0 rows."""

from __future__ import annotations

import pytest

from shared.nikto import iter_nikto_xml_rows
from shared.openscap import iter_openscap_failures
from shared.sslscan import _from_xml as sslscan_from_xml

_TRUNC = "<root><item>"
_NUL = "<root><item>x</item></root>\x00\x00\x00\x00"
_XXE = """<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
<r>&xxe;</r>
"""


@pytest.mark.parametrize(
    "payload",
    [_TRUNC, _NUL, _XXE],
    ids=["truncated", "trailing_nul", "doctype_entity"],
)
def test_nikto_xml_parse_errors_loud(payload: str) -> None:
    with pytest.raises(ValueError, match="nikto XML parse error"):
        list(iter_nikto_xml_rows(payload))


@pytest.mark.parametrize(
    "payload",
    [_TRUNC, _NUL, _XXE],
    ids=["truncated", "trailing_nul", "doctype_entity"],
)
def test_sslscan_xml_parse_errors_loud(payload: str) -> None:
    with pytest.raises(ValueError, match="sslscan XML parse error"):
        sslscan_from_xml(payload)


@pytest.mark.parametrize(
    "payload",
    [_TRUNC, _NUL, _XXE],
    ids=["truncated", "trailing_nul", "doctype_entity"],
)
def test_openscap_xml_parse_errors_loud(payload: str) -> None:
    with pytest.raises(ValueError, match="OpenSCAP XML parse error"):
        iter_openscap_failures(payload)
