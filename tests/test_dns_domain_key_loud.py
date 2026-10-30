"""Refuse dns_email domains entries whose identity key was corrupted."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from collectors.dns_email import parse_file


def _seed_domains() -> dict:
    return {
        "schema": "dns_email.v1",
        "domains": [
            {
                "domain": "a.example",
                "spf": "v=spf1 -all",
                "dmarc": "v=DMARC1; p=reject",
                "dkim": ["s1"],
                "mx": ["mx.a.example"],
                "ns": ["ns.a.example"],
            },
            {
                "domain": "b.example",
                "spf": "v=spf1 -all",
                "dmarc": "v=DMARC1; p=none",
                "dkim": [],
                "mx": [],
            },
        ],
    }


def test_valid_domains_parse(tmp_path: Path) -> None:
    p = tmp_path / "dns-txt.json"
    p.write_text(json.dumps(_seed_domains()), encoding="utf-8")
    rows = parse_file(p)
    assert len(rows) > 0


def test_corrupted_domain_key_refused(tmp_path: Path) -> None:
    payload = _seed_domains()
    # Rename domain -> dLomain on the first entry (key corruption).
    row0 = payload["domains"][0]
    row0["dLomain"] = row0.pop("domain")
    p = tmp_path / "dns-txt.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="missing domain/name/host"):
        parse_file(p)


def test_domains_list_without_schema_also_refused(tmp_path: Path) -> None:
    payload = {
        "domains": [
            {"dLomain": "a.example", "spf": "v=spf1 -all"},
            {"domain": "b.example", "spf": "v=spf1 -all"},
        ]
    }
    p = tmp_path / "dns-txt.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="missing domain/name/host"):
        parse_file(p)
