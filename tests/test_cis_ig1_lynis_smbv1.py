"""Lynis audit-logging row carries the audit-log safeguard id; hashing rounds stays unmapped
with a stated reason; SMBv1 is not tagged as an account-inventory safeguard. Synthetic only."""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from dropbox.orchestrator.ciso_path import run_ciso_path
from dropbox.scope import ROOT
from shared import cis_ig1
from shared.framework_class_map import ENV_EVAL_HEURISTICS

SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
REPORT = """# Synthetic Lynis report for tests
lynis_version=3.1.4
report_datetime_start=2026-01-01 00:00:00
hostname=synthetic-linux-03
os=Linux
warning[]=ACCT-9628|Enable auditd to collect audit information|Install and enable auditd
suggestion[]=AUTH-9230|Configure password hashing rounds in /etc/login.defs|Set SHA_CRYPT_MIN_ROUNDS
hardening_index=60
"""


@pytest.fixture(scope="module")
def rows(tmp_path_factory) -> dict[str, list[str]]:
    base = tmp_path_factory.mktemp("lyniscis")
    (base / "in" / "wazuh").mkdir(parents=True)
    (base / "in" / "wazuh" / "lynis-report.dat").write_text(REPORT, encoding="utf-8")
    run_ciso_path(base / "in", base / "out", scope_path=SCOPE, write_pack_in=False)
    out: dict[str, list[str]] = {}
    with (base / "out" / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            for cid in ("ACCT-9628", "AUTH-9230"):
                if cid in " ".join(r.values()):
                    out[cid] = r["framework_refs"].split(",")
    return out


def test_audit_logging_row_has_audit_log_id(rows) -> None:
    assert "cis_8_2" in rows["ACCT-9628"]


def test_hashing_rounds_left_unmapped_with_reason(rows) -> None:
    assert not [t for t in rows["AUTH-9230"] if t.startswith("cis_")]
    assert cis_ig1.UNMAPPED_FINDINGS.get("AUTH-9230")


def test_smbv1_not_account_inventory() -> None:
    rule = next(r for _p, r in ENV_EVAL_HEURISTICS if r.get("rule_id") == "smb-v1")
    assert "5.1" not in rule["cis_v8_internal"]
    assert rule["cis_v8_internal"] == ("4.8",)
    assert "5.1" not in cis_ig1.mapped_safeguards()
