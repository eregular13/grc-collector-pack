"""Refuse corrupted schema keys that used to silent-miscount."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from collectors.host_wazuh import parse_file as parse_wazuh
from collectors.saas_idp import parse_file as parse_idp


def test_agents_affected_items_key_corruption_loud(tmp_path: Path) -> None:
    payload = {
        "data": {
            "affected_items": [
                {"id": "001", "name": "web-01", "status": "active", "ip": "203.0.113.10"},
                {"id": "002", "name": "db-01", "status": "disconnected", "ip": "203.0.113.20"},
            ]
        },
        "alerts": [],
    }
    good = tmp_path / "agents-ok.json"
    good.write_text(json.dumps(payload), encoding="utf-8")
    assert len(parse_wazuh(good)) >= 2

    # Rename affected_items -> affected_items| (single-byte insert class).
    bad_payload = json.loads(json.dumps(payload))
    bad_payload["data"]["affected_items|"] = bad_payload["data"].pop("affected_items")
    bad = tmp_path / "agents-bad.json"
    bad.write_text(json.dumps(bad_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="affected_items"):
        parse_wazuh(bad)


def test_entra_signinactivity_case_corruption_loud(tmp_path: Path) -> None:
    payload = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
        "tenant": "contoso.example",
        "value": [
            {
                "userPrincipalName": "guest@contoso.example",
                "displayName": "Vendor",
                "userType": "Guest",
                "mail": "guest@contoso.example",
                "accountEnabled": True,
                "createdDateTime": "2020-01-01T00:00:00Z",
                "isMfaRegistered": True,
                "assignedRoles": [],
                "signInActivity": {"lastSignInDateTime": "2020-02-01T00:00:00Z"},
            }
        ],
    }
    good = tmp_path / "entra-ok.json"
    good.write_text(json.dumps(payload), encoding="utf-8")
    assert len(parse_idp(good)) >= 1

    bad_payload = json.loads(json.dumps(payload))
    act = bad_payload["value"][0].pop("signInActivity")
    bad_payload["value"][0]["signInActivIty"] = act
    bad = tmp_path / "entra-bad.json"
    bad.write_text(json.dumps(bad_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="signInActivity"):
        parse_idp(bad)
