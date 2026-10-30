"""Refuse Lynis bang lines whose check id was corrupted."""
from __future__ import annotations

from pathlib import Path

import pytest

from collectors.host_wazuh import parse_file, parse_lynis_report

NOW = "2026-03-01T00:00:00Z"


def test_lynis_ok_bang_lines() -> None:
    text = (
        "Hostname = app-01.example.test\n"
        "! No firewall configured [FIRE-4590]\n"
        "! SSH root login permitted [SSH-7408]\n"
    )
    rows = parse_lynis_report(text, NOW)
    findings = [r for r in rows if r.get("kind") == "finding"]
    assert len(findings) == 2


def test_lynis_corrupt_check_id_loud() -> None:
    text = (
        "Hostname = app-01.example.test\n"
        "! No firewall configured [FIRE-4590]\n"
        "! SSH root login permitted [9SSH-7408]\n"
    )
    with pytest.raises(ValueError, match="check-id"):
        parse_lynis_report(text, NOW)


def test_lynis_corrupt_check_id_via_parse_file(tmp_path: Path) -> None:
    dest = tmp_path / "lynis-report.example.test.txt"
    dest.write_text(
        "Hostname = app-01.example.test\n"
        "! SSH root login permitted [9SSH-7408]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="check-id"):
        parse_file(dest)
