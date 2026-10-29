"""Fail-before/pass-after: fixstack never silently drops open reobserved items."""
from __future__ import annotations

import json
from pathlib import Path

from scripts.fixstack_apply import apply_migration_to_ledger


def _ledger(tmp_path: Path, *, with_excl: bool = False) -> Path:
    items = {
        "fp-port": {
            "fp": "fp-port",
            "poam_id": "EGP-PORT000001",
            "status": "open",
            "name": "SSH exposed demo",
            "asset_key": "EGA-DEMO:22/TCP",
            "weakness_key": "nmap:nmap-port-22/tcp",
            "original_detection_date": "2026-01-01",
            "excluded_reason": "superseded_by_specific" if with_excl else "",
            "poam_decision": "superseded_by_specific",
            "rolled_into": "EGP-CVE0000001",
        },
        "fp-cve": {
            "fp": "fp-cve",
            "poam_id": "EGP-CVE0000001",
            "status": "open",
            "name": "CVE-demo",
            "asset_key": "EGA-DEMO:22",
            "weakness_key": "cve:CVE-2024-0001",
            "original_detection_date": "2026-01-02",
            "excluded_reason": "",
        },
    }
    doc = {
        "items": items,
        "closed": [],
        "events": [
            {
                "kind": "created",
                "fp": "fp-port",
                "poam_id": "EGP-PORT000001",
                "at": "2026-01-01T00:00:00Z",
            },
            {
                "kind": "reobserved",
                "fp": "fp-port",
                "poam_id": "EGP-PORT000001",
                "at": "2026-02-01T00:00:00Z",
            },
            {
                "kind": "created",
                "fp": "fp-cve",
                "poam_id": "EGP-CVE0000001",
                "at": "2026-02-01T00:00:00Z",
            },
        ],
        "events_this_run": [
            {
                "kind": "reobserved",
                "fp": "fp-port",
                "poam_id": "EGP-PORT000001",
                "at": "2026-02-01T00:00:00Z",
            },
            {
                "kind": "created",
                "fp": "fp-cve",
                "poam_id": "EGP-CVE0000001",
                "at": "2026-02-01T00:00:00Z",
            },
        ],
        "fp_migrations": [],
        "sha256": "x",
    }
    path = tmp_path / "poam-ledger.json"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


def test_fixstack_keeps_open_reobserved_not_on_plan(tmp_path: Path) -> None:
    """Port row reobserved but not on poam.csv must stay with explicit reason."""
    path = _ledger(tmp_path, with_excl=True)
    report: dict = {}
    apply_migration_to_ledger(
        path, map_rows=[], new_poam_ids={"EGP-CVE0000001"}, report=report
    )
    doc = json.loads(path.read_text(encoding="utf-8"))
    items = doc.get("items") or {}
    assert "fp-port" in items, "open reobserved port item must not be silently dropped"
    port = items["fp-port"]
    assert str(port.get("poam_id")) == "EGP-PORT000001"
    reason = str(port.get("excluded_reason") or "").strip()
    assert reason, "must carry explicit excluded_reason"
    assert "fp-cve" in items


def test_fixstack_keeps_even_if_excluded_reason_empty(tmp_path: Path) -> None:
    path = _ledger(tmp_path, with_excl=False)
    report: dict = {}
    apply_migration_to_ledger(
        path, map_rows=[], new_poam_ids={"EGP-CVE0000001"}, report=report
    )
    doc = json.loads(path.read_text(encoding="utf-8"))
    items = doc.get("items") or {}
    assert "fp-port" in items
    reason = str(items["fp-port"].get("excluded_reason") or "").strip()
    assert reason, "must mint explicit excluded_reason when missing"
