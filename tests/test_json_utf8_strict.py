"""Refuse invalid UTF-8 in JSON inputs (wrong-count class)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.io_util import load_json_prefer, read_json


def test_read_json_valid_utf8(tmp_path: Path) -> None:
    p = tmp_path / "ok.json"
    p.write_text(json.dumps({"agents": [{"name": "host-a"}]}), encoding="utf-8")
    assert read_json(p) == {"agents": [{"name": "host-a"}]}


def test_read_json_invalid_utf8_in_key_refused(tmp_path: Path) -> None:
    # Insert a non-UTF-8 byte into a JSON key (status -> st\x95atus).
    good = b'{"data":{"affected_items":[{"id":"1","name":"a","status":"active"}]}}'
    bad = good.replace(b'"status"', b'"st\x95atus"')
    assert b"\x95" in bad
    p = tmp_path / "agents-corrupt.json"
    p.write_bytes(bad)
    with pytest.raises(ValueError, match="invalid UTF-8"):
        read_json(p)


def test_load_json_prefer_invalid_utf8_refused(tmp_path: Path) -> None:
    good = b'{"users":[{"userPrincipalName":"a@example.com","assignedRoles":["Admin"]}]}'
    bad = good.replace(b"Admin", b"Adm\x9ain")
    p = tmp_path / "entra-corrupt.json"
    p.write_bytes(bad)
    with pytest.raises(ValueError, match="invalid UTF-8"):
        load_json_prefer(p)


def test_host_wazuh_agents_invalid_utf8_loud(tmp_path: Path) -> None:
    from collectors.host_wazuh import parse_file

    good = (
        b'{"data":{"affected_items":['
        b'{"id":"001","name":"web-01","status":"active","ip":"203.0.113.10"}'
        b"]}}"
    )
    bad = good.replace(b'"status"', b'"st\x95atus"', 1)
    p = tmp_path / "agents.json"
    p.write_bytes(bad)
    with pytest.raises(ValueError, match="invalid UTF-8"):
        parse_file(p)


def test_saas_idp_invalid_utf8_loud(tmp_path: Path) -> None:
    from collectors.saas_idp import parse_file

    good = (
        b'{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users",'
        b'"tenant":"contoso.example","value":['
        b'{"userPrincipalName":"a@contoso.example","userType":"Member",'
        b'"isMfaRegistered":true,"assignedRoles":[]}]}'
    )
    bad = good.replace(b"Member", b"Mem\x9aber", 1)
    p = tmp_path / "entra-users.json"
    p.write_bytes(bad)
    with pytest.raises(ValueError, match="invalid UTF-8"):
        parse_file(p)
