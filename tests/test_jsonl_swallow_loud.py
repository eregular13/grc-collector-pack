"""Corrupt JSONL / gnmap / named empties must fail loud — never silent OK under-counts."""

from __future__ import annotations

from pathlib import Path

import pytest

from collectors import vuln_scan
from collectors.inventory_nmap import parse_file as nmap_parse_file
from collectors.inventory_nmap import parse_gnmap
from shared.enum4linux import parse_enum4linux
from shared.fast_portscan import parse_fast_portscan
from shared.honeypot import parse_honeypot
from shared.io_util import iso_now
from shared.pack_drop import _iter_rows

ROOT = Path(__file__).resolve().parents[1]
NUCLEI = ROOT / "fixtures/demo/vuln/nuclei.jsonl"
EVENTS = ROOT / "fixtures/demo/honeypot/events.jsonl"
SESSIONS = ROOT / "fixtures/demo/honeypot/sessions.jsonl"
ENUM4 = ROOT / "fixtures/samples/enum4linux/enum4linux-ng.json"
NAABU = ROOT / "fixtures/demo/nmap/naabu.jsonl"
GNMAP = ROOT / "fixtures/demo/nmap/scan.gnmap"
FINDINGS = ROOT / "fixtures/pack_drop/naabu/findings.jsonl"


def test_seed_files_still_parse() -> None:
    assert len(vuln_scan.parse_file(NUCLEI)) >= 1
    assert len(parse_honeypot(EVENTS, EVENTS.read_text(encoding="utf-8"), iso_now()) or []) >= 1
    assert len(parse_honeypot(SESSIONS, SESSIONS.read_text(encoding="utf-8"), iso_now()) or []) >= 1
    assert parse_enum4linux(ENUM4, ENUM4.read_text(encoding="utf-8"))
    assert parse_fast_portscan(NAABU)
    assert len(parse_gnmap(GNMAP.read_text(encoding="utf-8"), iso_now())) >= 1
    assert len(_iter_rows(FINDINGS.read_text(encoding="utf-8"), path_name=FINDINGS.name)) >= 1


def test_nuclei_corrupt_line_loud(tmp_path: Path) -> None:
    lines = NUCLEI.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2
    lines[1] = "{not-json"
    dest = tmp_path / "nuclei.jsonl"
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt JSONL"):
        vuln_scan.parse_file(dest)


def test_nuclei_empty_loud(tmp_path: Path) -> None:
    dest = tmp_path / "nuclei.jsonl"
    dest.write_bytes(b"")
    with pytest.raises(ValueError, match="empty nuclei|0 bytes"):
        vuln_scan.parse_file(dest)


def test_honeypot_events_corrupt_line_loud(tmp_path: Path) -> None:
    lines = EVENTS.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2
    lines[1] = "{not-json"
    dest = tmp_path / "events.jsonl"
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt JSONL"):
        parse_honeypot(dest, dest.read_text(encoding="utf-8"), iso_now())


def test_honeypot_sessions_empty_loud(tmp_path: Path) -> None:
    dest = tmp_path / "sessions.jsonl"
    dest.write_bytes(b"")
    with pytest.raises(ValueError, match="empty honeypot|0 bytes"):
        parse_honeypot(dest, "", iso_now())


def test_enum4linux_truncated_json_loud(tmp_path: Path) -> None:
    raw = ENUM4.read_bytes()
    dest = tmp_path / "enum4linux-ng.json"
    dest.write_bytes(raw[: len(raw) // 2])
    with pytest.raises(ValueError, match="not valid JSON|refusing silent"):
        parse_enum4linux(dest, dest.read_text(encoding="utf-8", errors="replace"))


def test_enum4linux_flipped_json_loud(tmp_path: Path) -> None:
    raw = bytearray(ENUM4.read_bytes())
    raw[1] = ord("x")  # "{x..." breaks object start
    dest = tmp_path / "enum4linux-ng.json"
    dest.write_bytes(bytes(raw))
    with pytest.raises(ValueError, match="not valid JSON|refusing silent"):
        parse_enum4linux(dest, dest.read_text(encoding="utf-8", errors="replace"))


def test_naabu_corrupt_line_loud(tmp_path: Path) -> None:
    dest = tmp_path / "naabu.jsonl"
    dest.write_text(
        '{"ip":"10.0.0.1","port":22,"protocol":"tcp"}\n'
        "{not-json\n"
        '{"ip":"10.0.0.2","port":80,"protocol":"tcp"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="corrupt JSONL"):
        parse_fast_portscan(dest)


def test_naabu_empty_loud(tmp_path: Path) -> None:
    dest = tmp_path / "naabu.jsonl"
    dest.write_bytes(b"")
    with pytest.raises(ValueError, match="empty fast-portscan|0 bytes"):
        parse_fast_portscan(dest)


def test_gnmap_ports_token_flip_loud(tmp_path: Path) -> None:
    lines = GNMAP.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if "Ports:" in line:
            lines[i] = line.replace("Ports:", "PortX:", 1)
            break
    else:
        raise AssertionError("no Ports: line in fixture")
    dest = tmp_path / "scan.gnmap"
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unparseable gnmap"):
        parse_gnmap(dest.read_text(encoding="utf-8"), iso_now(), path_name=dest.name)


def test_gnmap_open_state_flip_loud(tmp_path: Path) -> None:
    raw = bytearray(GNMAP.read_bytes())
    idx = raw.find(b"/open/")
    assert idx > 0
    raw[idx + 2] ^= 0x01
    dest = tmp_path / "scan.gnmap"
    dest.write_bytes(bytes(raw))
    with pytest.raises(ValueError, match="unparseable gnmap"):
        nmap_parse_file(dest)


def test_pack_drop_findings_corrupt_line_loud(tmp_path: Path) -> None:
    lines = FINDINGS.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2
    lines[1] = "{not-json"
    with pytest.raises(ValueError, match="corrupt JSONL"):
        _iter_rows("\n".join(lines) + "\n", path_name="findings.jsonl")
