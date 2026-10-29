"""Ledger run_at / event clocks honor SOURCE_DATE_EPOCH (lazy import = real AE fail-before)."""
from __future__ import annotations

import importlib
from datetime import datetime, timezone
from pathlib import Path


def _load(modname: str):
    try:
        return importlib.import_module(modname)
    except Exception:
        return None


SDE = "1700000000"
SDE_ISO = "2023-11-14T22:13:20Z"


def _catalog():
    kev = _load("shared.kev")
    assert kev is not None, "shared.kev missing"
    KevCatalog = getattr(kev, "KevCatalog", None)
    assert KevCatalog is not None
    return KevCatalog(kev_evaluated=False)


def _rec() -> dict:
    return {
        "ref_id": "NMAP-TEST-LEDGER-SDE",
        "name": "Synthetic open port",
        "description": "prior-unit synthetic",
        "severity": "low",
        "source": "inventory_nmap",
        "asset": "10.0.0.50",
        "extra": {"port": 22, "scan_time": "2026-09-01T12:00:00Z"},
    }


def test_utc_now_follows_source_date_epoch(monkeypatch) -> None:
    io = _load("shared.io_util")
    assert io is not None, "shared.io_util missing"
    utc_now = getattr(io, "utc_now", None)
    iso_now = getattr(io, "iso_now", None)
    assert callable(utc_now), "utc_now missing (pr-ledger-sde not applied)"
    assert callable(iso_now), "iso_now missing"
    monkeypatch.setenv("SOURCE_DATE_EPOCH", SDE)
    monkeypatch.delenv("GRC_RUN_TS", raising=False)
    assert utc_now().strftime("%Y-%m-%dT%H:%M:%SZ") == SDE_ISO
    assert iso_now() == SDE_ISO


def test_apply_ledger_run_at_freezes_under_sde(monkeypatch, tmp_path: Path) -> None:
    pl = _load("shared.poam_ledger")
    assert pl is not None, "shared.poam_ledger missing"
    apply_ledger = getattr(pl, "apply_ledger", None)
    persist_ledger = getattr(pl, "persist_ledger", None)
    load_ledger_file = getattr(pl, "load_ledger_file", None)
    assert callable(apply_ledger), "apply_ledger missing"
    assert callable(persist_ledger) and callable(load_ledger_file)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", SDE)
    monkeypatch.delenv("GRC_RUN_TS", raising=False)
    cat = _catalog()
    a = apply_ledger([_rec()], catalog=cat, run_at=None)
    b = apply_ledger([_rec()], catalog=cat, run_at=None)
    assert a["run_at"] == SDE_ISO, f"run_at not frozen under SDE: {a.get('run_at')}"
    assert b["run_at"] == SDE_ISO
    assert a["run_at"] == b["run_at"]
    assert all(ev.get("at") == SDE_ISO for ev in a.get("events") or [])
    assert a["sha256"] == b["sha256"]
    out = tmp_path / "out"
    out.mkdir()
    path = persist_ledger(dict(a), out)
    doc, warnings = load_ledger_file(path)
    assert warnings == []
    assert doc.get("run_at") == SDE_ISO


def test_apply_ledger_explicit_run_at_wins_over_sde(monkeypatch) -> None:
    pl = _load("shared.poam_ledger")
    assert pl is not None
    apply_ledger = getattr(pl, "apply_ledger", None)
    assert callable(apply_ledger)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", SDE)
    clock = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    led = apply_ledger([_rec()], catalog=_catalog(), run_at=clock)
    assert led["run_at"] == "2026-01-02T03:04:05Z"


def test_apply_ledger_without_sde_uses_wall_clock_shape(monkeypatch) -> None:
    pl = _load("shared.poam_ledger")
    assert pl is not None
    apply_ledger = getattr(pl, "apply_ledger", None)
    assert callable(apply_ledger)
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    monkeypatch.delenv("GRC_RUN_TS", raising=False)
    led = apply_ledger([_rec()], catalog=_catalog(), run_at=None)
    assert led["run_at"].endswith("Z") and "T" in led["run_at"]
