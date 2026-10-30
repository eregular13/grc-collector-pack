"""Refuse corrupted bloodhound data.nodes keys that used to silent-zero."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from collectors.identity_ad import parse_file


def _payload() -> dict:
    return {
        "data": {
            "nodes": [
                {
                    "objectid": "S-1-5-21-1000-2000-3000-1103",
                    "kind": "User",
                    "label": "svc-sql",
                    "properties": {
                        "name": "SVC-SQL@CORP.EXAMPLE",
                        "hasspn": True,
                        "serviceprincipalnames": ["MSSQLSvc/db.corp.example"],
                    },
                },
                {
                    "objectid": "S-1-5-32-544",
                    "kind": "Group",
                    "label": "Administrators",
                    "properties": {
                        "name": "ADMINISTRATORS@CORP.EXAMPLE",
                        "highvalue": True,
                    },
                },
            ],
            "edges": [
                {
                    "kind": "MemberOf",
                    "start": "S-1-5-21-1000-2000-3000-1103",
                    "end": "S-1-5-32-544",
                }
            ],
        }
    }


def test_bloodhound_nodes_ok_example(tmp_path: Path) -> None:
    good = tmp_path / "bloodhound.example.test.json"
    good.write_text(json.dumps(_payload()), encoding="utf-8")
    assert len(parse_file(good)) >= 1


def test_bloodhound_nodes_key_insert_corruption_loud(tmp_path: Path) -> None:
    """Single-byte insert renaming nodes -> Fnodes must not silent-zero."""
    bad_payload = json.loads(json.dumps(_payload()))
    bad_payload["data"]["Fnodes"] = bad_payload["data"].pop("nodes")
    bad = tmp_path / "bloodhound-fnodes.example.test.json"
    bad.write_text(json.dumps(bad_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="nodes"):
        parse_file(bad)


def test_bloodhound_nodes_key_punct_corruption_loud(tmp_path: Path) -> None:
    bad_payload = json.loads(json.dumps(_payload()))
    bad_payload["data"]["nod]es"] = bad_payload["data"].pop("nodes")
    bad = tmp_path / "bloodhound-punct.example.test.json"
    bad.write_text(json.dumps(bad_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="nodes"):
        parse_file(bad)
