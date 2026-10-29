"""Corrupt or truncated nmap XML must be refused with a clear error naming the file."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from collectors import inventory_nmap

SEED = Path(__file__).resolve().parents[1] / "fixtures" / "samples" / "nmap-vulners.xml"


def _variants(data: bytes) -> dict[str, bytes]:
    i = data.index(b"<host")
    return {
        "truncate_half": data[: len(data) // 2],
        "nul_in_tag": data[:i] + b"<h\x00ost" + data[i + 5 :],
        "junk_after_document": data + b"\n<<<junk>>>\n",
    }


def test_seed_parses(tmp_path: Path) -> None:
    p = tmp_path / "scan.xml"
    p.write_bytes(SEED.read_bytes())
    assert inventory_nmap.parse_file(p)


@pytest.mark.parametrize("variant", ["truncate_half", "nul_in_tag", "junk_after_document"])
def test_corrupt_nmap_xml_refused_cleanly(variant: str, tmp_path: Path) -> None:
    p = tmp_path / f"nmap-{variant}.xml"
    p.write_bytes(_variants(SEED.read_bytes())[variant])
    with pytest.raises(ValueError) as ei:
        inventory_nmap.parse_file(p)
    assert not isinstance(ei.value, (ET.ParseError, SyntaxError))
    assert p.name in str(ei.value)
    assert "nmap XML" in str(ei.value)
