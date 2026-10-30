"""Refuse osquery query names that contain control characters."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from collectors.host_wazuh import parse_file


def _payload(name: str = "system_info") -> dict:
    return {
        "osquery": [
            {
                "name": name,
                "status": "active",
                "columns": {
                    "hostname": "app-01.example.test",
                    "uuid": "11111111-1111-1111-1111-111111111111",
                },
            }
        ]
    }


def test_osquery_system_info_ok(tmp_path: Path) -> None:
    dest = tmp_path / "osquery.example.test.json"
    dest.write_text(json.dumps(_payload()), encoding="utf-8")
    rows = parse_file(dest)
    assert len(rows) >= 1
    assert not any("unmapped" in (r.get("labels") or []) for r in rows)


def test_osquery_control_char_query_name_loud(tmp_path: Path) -> None:
    bad_name = "system\x7finfo"
    dest = tmp_path / "osquery-ctrl.example.test.json"
    dest.write_text(json.dumps(_payload(bad_name)), encoding="utf-8")
    with pytest.raises(ValueError, match="control"):
        parse_file(dest)
