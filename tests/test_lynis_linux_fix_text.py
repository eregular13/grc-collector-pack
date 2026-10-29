"""Lynis audit-logging and password-policy findings get Linux fix text, not Windows text.

Synthetic Lynis report.dat only.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from dropbox.orchestrator.ciso_path import run_ciso_path
from dropbox.scope import ROOT

SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
REPORT = """# Synthetic Lynis report for tests
lynis_version=3.1.4
report_datetime_start=2026-01-01 00:00:00
hostname=synthetic-linux-01
os=Linux
warning[]=ACCT-9628|Enable auditd to collect audit information|Install and enable auditd
suggestion[]=AUTH-9230|Configure password hashing rounds in /etc/login.defs|Set SHA_CRYPT_MIN_ROUNDS
hardening_index=60
"""
WINDOWS_MARKERS = ("hardeningkitty", "ms security baseline", "windows", "microsoft", "advanced audit policy")


@pytest.fixture(scope="module")
def out(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("lynis")
    wazuh = base / "in" / "wazuh"
    wazuh.mkdir(parents=True)
    (wazuh / "lynis-report.dat").write_text(REPORT, encoding="utf-8")
    run_ciso_path(base / "in", base / "out", scope_path=SCOPE, write_pack_in=False)
    return base / "out"


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


@pytest.mark.parametrize("rel", ["poam/poam.csv", "simplerisk/poam.csv"])
def test_lynis_rows_have_linux_fix_text(out: Path, rel: str) -> None:
    rows = _rows(out / rel)
    hits = [r for r in rows if any(c in " ".join(r.values()) for c in ("ACCT-9628", "AUTH-9230"))]
    assert len(hits) >= 2, f"Lynis rows missing from {rel}"
    for row in hits:
        blob = " ".join(row.values()).lower()
        for marker in WINDOWS_MARKERS:
            assert marker not in blob, f"{rel}: Windows text {marker!r} on Lynis row: {row}"
        assert "lynis" in blob


def test_lynis_fix_text_is_linux_specific(out: Path) -> None:
    blob = " ".join(" ".join(r.values()) for r in _rows(out / "poam" / "poam.csv")).lower()
    assert "auditd" in blob
    assert "login.defs" in blob
