"""Truncated, UTF-16 or unparseable scanner files must fail closed, never yield 0 rows silently.

UTF-16 (with BOM) that is otherwise valid must decode and parse.
"""
from __future__ import annotations

import importlib
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
JSON_SEEDS = {
    "grype.json": (ROOT / "fixtures/samples/grype/synthetic_grype-image.json", "collectors.vuln_scan"),
    "checkov.json": (ROOT / "fixtures/demo/code/checkov.json", "collectors.code_secrets"),
    "gitleaks.json": (ROOT / "fixtures/demo/code/gitleaks.json", "collectors.code_secrets"),
    "semgrep.json": (ROOT / "fixtures/demo/code/semgrep.json", "collectors.code_secrets"),
}
SSLSCAN = ROOT / "fixtures/demo/vuln/sslscan.xml"


def _parse(mod: str):
    return importlib.import_module(mod).parse_file


def _refused(mod: str, p: Path) -> None:
    with pytest.raises(ValueError) as ei:
        _parse(mod)(p)
    assert not isinstance(ei.value, (ET.ParseError, SyntaxError))
    assert p.name in str(ei.value)


@pytest.mark.parametrize("name", sorted(JSON_SEEDS))
def test_seed_parses(name: str, tmp_path: Path) -> None:
    seed, mod = JSON_SEEDS[name]
    p = tmp_path / name
    p.write_bytes(seed.read_bytes())
    assert _parse(mod)(p)


@pytest.mark.parametrize("name", sorted(JSON_SEEDS))
def test_empty_file_is_zero_rows(name: str, tmp_path: Path) -> None:
    p = tmp_path / name
    p.write_bytes(b"")
    assert _parse(JSON_SEEDS[name][1])(p) == []


@pytest.mark.parametrize("name", sorted(JSON_SEEDS))
def test_truncated_json_refused(name: str, tmp_path: Path) -> None:
    seed, mod = JSON_SEEDS[name]
    data = seed.read_bytes()
    p = tmp_path / f"trunc-{name}"
    p.write_bytes(data[: len(data) // 2])
    _refused(mod, p)


@pytest.mark.parametrize("enc", ["utf-16", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("name", sorted(JSON_SEEDS))
def test_utf16_bom_json_decodes(name: str, enc: str, tmp_path: Path) -> None:
    seed, mod = JSON_SEEDS[name]
    text = seed.read_bytes().decode("utf-8").lstrip("\ufeff")
    bom = {"utf-16": b"", "utf-16-le": b"\xff\xfe", "utf-16-be": b"\xfe\xff"}[enc]
    p = tmp_path / f"utf16-{name}"
    p.write_bytes(bom + text.encode(enc))
    base = tmp_path / name
    base.write_bytes(seed.read_bytes())
    assert len(_parse(mod)(p)) == len(_parse(mod)(base)) > 0


@pytest.mark.parametrize("name", sorted(JSON_SEEDS))
def test_truncated_utf16_json_refused(name: str, tmp_path: Path) -> None:
    seed, mod = JSON_SEEDS[name]
    data = seed.read_bytes().decode("utf-8").encode("utf-16")
    p = tmp_path / f"trunc16-{name}"
    p.write_bytes(data[: (len(data) // 4) * 2])
    _refused(mod, p)


def test_sslscan_seed_parses(tmp_path: Path) -> None:
    p = tmp_path / "sslscan.xml"
    p.write_bytes(SSLSCAN.read_bytes())
    assert _parse("collectors.vuln_scan")(p)


def test_truncated_sslscan_xml_refused(tmp_path: Path) -> None:
    data = SSLSCAN.read_bytes()
    p = tmp_path / "trunc-sslscan.xml"
    p.write_bytes(data[: len(data) // 2])
    _refused("collectors.vuln_scan", p)


def test_utf16_sslscan_xml_decodes(tmp_path: Path) -> None:
    text = SSLSCAN.read_bytes().decode("utf-8")
    p = tmp_path / "utf16-sslscan.xml"
    p.write_bytes(text.encode("utf-16"))
    base = tmp_path / "sslscan.xml"
    base.write_bytes(SSLSCAN.read_bytes())
    assert len(_parse("collectors.vuln_scan")(p)) == len(_parse("collectors.vuln_scan")(base)) > 0
