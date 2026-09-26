"""Carried-unobserved POA&M rows keep Controls and Plan (Metis / #179).

Old ledgers store name / weakness_key / source only. Rebuilding those rows
from ledger fields left Controls and Overall Remediation Plan blank.
Persist the stamps (and check_id / kind) on mint/update; re-derive via
control_map for older items. POA&M IDs and aliasing stay put.
SAMPLE/DEMO/LAB only. No POST /api/risks. RiskReady stay-out.
"""

from __future__ import annotations

import csv
import importlib
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import pytest

from shared.control_map import map_finding
from shared.kev import KevCatalog
from shared.poam_ledger import (
    apply_ledger,
    empty_ledger,
    finding_from_ledger_item,
    persist_mapped_fields,
    plan_from_ledger_item,
)
from tests.lab_outputs import assert_no_blank_high_critical

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL_CHAIN_LEDGERS = (
    FIXTURES / "demo-poam-ledger-master.json",
    FIXTURES / "demo-poam-ledger-7ebc697.json",
)


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _run(when: str) -> datetime:
    return datetime.fromisoformat(when.replace("Z", "+00:00"))


def _ftp(**kw) -> dict:
    extra = kw.pop(
        "extra",
        {
            "port": "21",
            "ip": "10.0.0.5",
            "check_id": "nse-ftp-anon",
            "nse_script": "ftp-anon",
            "tool": "nmap",
            "scan_time": "2026-09-01T12:00:00Z",
        },
    )
    rec = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": kw.pop("ref_id", "NMAP-10-0-0-5-21-nse-ftp-anon"),
        "name": kw.pop("name", "Anonymous FTP login allowed"),
        "description": kw.pop(
            "description", "10.0.0.5 accepts anonymous FTP login (nmap ftp-anon)."
        ),
        "severity": kw.pop("severity", "high"),
        "category": "misconfiguration",
        "assets": kw.pop("assets", ["10.0.0.5"]),
        "labels": ["nmap"],
        "collected_at": "2026-09-20T10:00:00Z",
        "extra": extra,
    }
    rec.update(kw)
    return rec


def _ssh(**kw) -> dict:
    extra = kw.pop(
        "extra",
        {
            "port": "22",
            "ip": "10.0.0.5",
            "check_id": "nmap-port-22/tcp",
            "service": "ssh",
            "protocol": "tcp",
            "tool": "nmap",
        },
    )
    rec = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": kw.pop("ref_id", "NMAP-10-0-0-5-22-tcp"),
        "name": kw.pop("name", "SSH exposed"),
        "description": "Open SSH on 10.0.0.5",
        "severity": kw.pop("severity", "medium"),
        "category": "exposure",
        "assets": kw.pop("assets", ["10.0.0.5"]),
        "labels": ["nmap"],
        "collected_at": "2026-09-20T10:00:00Z",
        "extra": extra,
    }
    rec.update(kw)
    return rec


def _apply(findings, ledger=None, when="2026-09-10T00:00:00Z"):
    return apply_ledger(
        findings,
        catalog=_unevaluated(),
        run_at=_run(when),
        ledger_in=ledger,
        overrides={},
        prior_existed=True,
    )


def _strip_map_fields(item: dict) -> dict:
    out = deepcopy(item)
    for key in ("controls", "remediation_plan", "check_id", "finding_kind", "framework_refs"):
        out.pop(key, None)
    out["remediation_plan"] = ""
    return out


def _old_style_item(rec: dict, poam_id: str) -> dict:
    """Pre-persist ledger row: identity fields only, no controls/plan/check_id."""
    from shared.poam_ledger import asset_key, fp_v1, source_family, weakness_key
    from shared.asset_key import display_asset

    return {
        "poam_id": poam_id,
        "fp": fp_v1(rec),
        "source_family": source_family(rec),
        "weakness_key": weakness_key(rec),
        "asset_key": asset_key(rec),
        "display_asset": display_asset(rec),
        "ref_id": rec["ref_id"],
        "name": rec["name"],
        "description": rec["description"],
        "original_detection_date": "2026-09-01",
        "first_seen": "2026-09-01T00:00:00Z",
        "status": "open",
        "status_date": "2026-09-01",
        "severity": rec["severity"],
        "current_scanner_rating": rec["severity"],
        "original_risk_rating": "High" if rec["severity"] == "high" else "Moderate",
        "missed_covered_runs": 0,
        "kev_comments": [],
        "cves": [],
    }


def test_mint_persists_controls_plan_check_id_kind() -> None:
    rec = _ftp()
    mapped = map_finding(rec)
    ledger = _apply([rec])
    item = next(iter(ledger["items"].values()))
    assert item["poam_id"].startswith("EGP-")
    assert item["check_id"] == "nse-ftp-anon"
    assert item["finding_kind"]
    assert item["controls"]
    assert {"AC-3", "CM-7"} <= {c.strip() for c in item["controls"].split(",")}
    assert item["remediation_plan"] == mapped["recommended_fix"]
    assert item["controls"] == ", ".join(mapped.get("nist_800_53") or [])


def test_old_ledger_loads_and_fills_on_next_observed_run() -> None:
    rec = _ftp()
    fresh = _apply([rec], when="2026-09-10T00:00:00Z")
    prior = empty_ledger()
    src = next(iter(fresh["items"].values()))
    old = _strip_map_fields(src)
    prior["items"] = {old["fp"]: old}
    upgrade = _apply([rec], ledger=prior, when="2026-09-11T00:00:00Z")
    item = next(iter(upgrade["items"].values()))
    fresh_item = next(iter(fresh["items"].values()))
    assert item["poam_id"] == fresh_item["poam_id"] == src["poam_id"]
    assert item["controls"] == fresh_item["controls"]
    assert item["remediation_plan"] == fresh_item["remediation_plan"]
    assert item["check_id"] == fresh_item["check_id"]
    assert item["status_date"] == "2026-09-01"
    new_events = [e for e in upgrade["events"] if str(e.get("at") or "").startswith("2026-09-11")]
    assert not any(e.get("kind") == "field_changed" for e in new_events), new_events


def test_carried_unobserved_old_ledger_has_controls_and_plan() -> None:
    ftp = _ftp()
    ssh = _ssh()
    first = _apply([ftp, ssh], when="2026-09-10T00:00:00Z")
    prior = deepcopy(first)
    ftp_fp = None
    for fp, item in prior["items"].items():
        if "ftp" in str(item.get("ref_id") or "").lower() or "ftp" in str(item.get("name") or "").lower():
            prior["items"][fp] = _strip_map_fields(item)
            ftp_fp = fp
    assert ftp_fp
    upgrade = _apply([ssh], ledger=prior, when="2026-09-12T00:00:00Z")
    carried = upgrade["items"][ftp_fp]
    assert carried["poam_id"] == first["items"][ftp_fp]["poam_id"]
    assert carried["controls"]
    assert carried["remediation_plan"]
    assert carried["check_id"] == "nse-ftp-anon"
    planned = plan_from_ledger_item(carried)
    assert planned["controls"] == carried["controls"]
    assert planned["recommended_fix"] == carried["remediation_plan"]


def test_finding_from_old_item_uses_same_control_map_as_fresh() -> None:
    rec = _ftp()
    mapped = map_finding(rec)
    item = _old_style_item(rec, "EGP-KEEPFTP01")
    rebuilt = finding_from_ledger_item(item)
    again = map_finding(rebuilt)
    assert again["nist_800_53"] == mapped["nist_800_53"]
    assert again["recommended_fix"] == mapped["recommended_fix"]
    persist_mapped_fields(item, overwrite_plan=False)
    assert item["poam_id"] == "EGP-KEEPFTP01"
    assert item["controls"]
    assert item["remediation_plan"]


def test_upgrade_equals_fresh_for_observed_rows() -> None:
    recs = [_ftp(), _ssh()]
    fresh = _apply(recs, when="2026-09-10T00:00:00Z")
    prior = empty_ledger()
    prior["items"] = {fp: _strip_map_fields(item) for fp, item in fresh["items"].items()}
    upgrade = _apply(recs, ledger=prior, when="2026-09-11T00:00:00Z")
    assert set(upgrade["items"]) == set(fresh["items"])
    for fp, fresh_item in fresh["items"].items():
        got = upgrade["items"][fp]
        assert got["poam_id"] == fresh_item["poam_id"]
        assert got["controls"] == fresh_item["controls"]
        assert got["remediation_plan"] == fresh_item["remediation_plan"]
        assert got["check_id"] == fresh_item["check_id"]


def test_carried_row_on_poam_and_fedramp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ftp = _ftp()
    ssh = _ssh()
    ssh_asset = {
        "kind": "asset",
        "source": "inventory-nmap",
        "ref_id": "NMAP-asset-10-0-0-5",
        "name": "10.0.0.5",
        "description": "host",
        "severity": "info",
        "category": "host",
        "assets": ["10.0.0.5"],
        "labels": ["nmap"],
        "extra": {"asset_type": "PR", "ip": "10.0.0.5"},
    }
    old = _old_style_item(ftp, "EGP-8EC6F7CA09")
    seeded = empty_ledger()
    seeded["items"] = {old["fp"]: old}
    incoming = tmp_path / "in"
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    (incoming / "poam").mkdir(parents=True)
    (incoming / "poam" / "poam-ledger.json").write_text(
        json.dumps(seeded, indent=2) + "\n", encoding="utf-8"
    )
    with (out / "canonical" / "x.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(ssh_asset) + "\n")
        fh.write(json.dumps(ssh) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(incoming))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    with (out / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        plan = list(csv.DictReader(fh))
    with (out / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        fed = list(csv.DictReader(fh))
    assert_no_blank_high_critical(plan, source="poam.csv")
    assert_no_blank_high_critical(fed, source="poam_fedramp.csv")
    by_id = {r["poam_id"]: r for r in plan}
    assert "EGP-8EC6F7CA09" in by_id
    carried = by_id["EGP-8EC6F7CA09"]
    assert carried["controls"]
    assert carried["recommended_fix"]
    fed_by = {r["POAM ID"]: r for r in fed}
    assert fed_by["EGP-8EC6F7CA09"]["Controls"] == carried["controls"]
    assert fed_by["EGP-8EC6F7CA09"]["Overall Remediation Plan"] == carried["recommended_fix"]
    written = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    stored = next(it for it in written["items"].values() if it["poam_id"] == "EGP-8EC6F7CA09")
    assert stored["controls"]
    assert stored["remediation_plan"]
    assert stored["check_id"] == "nse-ftp-anon"


@pytest.mark.parametrize("ledger_path", REAL_CHAIN_LEDGERS, ids=["master", "7ebc697"])
def test_real_chain_upgrade_no_blank_high_critical_and_observed_match_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ledger_path: Path
) -> None:
    """Historical DEMO ledgers (and Metis R_dd360a2 / R_51bba3c class): no High/Critical blank.

    Observed rows after upgrade match a fresh mint for Controls and Plan.
    IDs stay. Carried-unobserved rows (if any) still have Controls and Plan.
    """
    from tests.test_poam_breakdown import _run_lab

    fresh_dir = tmp_path / "fresh"
    fresh_dir.mkdir()
    _run_lab(fresh_dir, monkeypatch)
    with (fresh_dir / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        fresh_plan = {r["poam_id"]: r for r in csv.DictReader(fh) if r.get("poam_id")}
    assert_no_blank_high_critical(list(fresh_plan.values()), source="fresh poam.csv")

    prior = json.loads(ledger_path.read_text(encoding="utf-8"))
    prior_ids = {it["poam_id"] for it in prior["items"].values()}
    up_dir = tmp_path / "upgrade"
    (up_dir / "poam").mkdir(parents=True)
    (up_dir / "poam" / "poam-ledger.json").write_text(
        json.dumps(prior, indent=2) + "\n", encoding="utf-8"
    )
    _run_lab(up_dir, monkeypatch)
    with (up_dir / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        up_rows = list(csv.DictReader(fh))
    with (up_dir / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        up_fed = list(csv.DictReader(fh))
    assert_no_blank_high_critical(up_rows, source=f"{ledger_path.name} poam.csv")
    assert_no_blank_high_critical(up_fed, source=f"{ledger_path.name} poam_fedramp.csv")
    up_plan = {r["poam_id"]: r for r in up_rows if r.get("poam_id")}
    for pid, row in up_plan.items():
        if pid not in fresh_plan:
            continue
        assert row["controls"] == fresh_plan[pid]["controls"], pid
        assert row["recommended_fix"] == fresh_plan[pid]["recommended_fix"], pid
    ledger = json.loads((up_dir / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    reseen = {it["poam_id"] for it in ledger["items"].values() if it.get("status") != "closed"}
    assert prior_ids <= reseen
