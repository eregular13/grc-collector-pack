"""Scan-derived CIS v8 IG1 safeguard ids on host-firewall and dormant-account findings.

Synthetic Lynis and IdP exports only.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from dropbox.orchestrator.ciso_path import run_ciso_path
from dropbox.scope import ROOT

SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
LYNIS = """# Synthetic Lynis report for tests
lynis_version=3.1.4
report_datetime_start=2026-01-01 00:00:00
hostname=synthetic-linux-02
os=Linux
warning[]=FIRE-4590|No firewall software installed|Install a host firewall
hardening_index=55
"""
OKTA_USERS = [
    {
        "id": "00u-synthetic-1",
        "status": "ACTIVE",
        "userType": "guest",
        "created": "2020-01-01T00:00:00Z",
        "lastLogin": "2020-02-01T00:00:00Z",
        "profile": {"login": "guest.synthetic@example.com", "userType": "guest"},
    }
]


@pytest.fixture(scope="module")
def poam(tmp_path_factory) -> list[dict[str, str]]:
    base = tmp_path_factory.mktemp("cisig1")
    (base / "in" / "wazuh").mkdir(parents=True)
    (base / "in" / "wazuh" / "lynis-report.dat").write_text(LYNIS, encoding="utf-8")
    (base / "in" / "saas").mkdir(parents=True)
    (base / "in" / "saas" / "okta-users.json").write_text(json.dumps(OKTA_USERS), encoding="utf-8")
    run_ciso_path(base / "in", base / "out", scope_path=SCOPE, write_pack_in=False)
    with (base / "out" / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _refs(rows, needle: str) -> list[str]:
    hit = [r for r in rows if needle.lower() in " ".join(r.values()).lower()]
    assert hit, f"no POA&M row for {needle}"
    return [r["framework_refs"].split(",") for r in hit]


def test_host_firewall_maps_server_firewall_safeguard(poam) -> None:
    for refs in _refs(poam, "FIRE-4590"):
        assert "cis_4_4" in refs and "cis_4_5" in refs


def test_stale_guest_maps_dormant_account_safeguard(poam) -> None:
    for refs in _refs(poam, "Stale guest account"):
        assert "cis_5_3" in refs
