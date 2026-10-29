"""prior-unit synthetic migration + testssl classify tests (no lab data)."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from shared.kev import KevCatalog
from shared.poam_ledger import (
    apply_ledger,
    empty_ledger,
    load_id_migration_map,
    payload_sha256,
)


def _item(
    *,
    fp: str,
    poam_id: str,
    status: str = "open",
    first_seen: str = "2026-10-04T12:00:00Z",
    odd: str = "2026-10-04",
) -> dict:
    return {
        "fp": fp,
        "poam_id": poam_id,
        "status": status,
        "first_seen": first_seen,
        "last_seen": first_seen,
        "original_detection_date": odd,
        "excluded_reason": "",
        "source_family": "vuln-scan",
        "asset_key": "img:demo",
        "weakness_key": f"wk:{poam_id}",
        "name": f"finding {poam_id}",
    }


def test_load_id_migration_map_empty(tmp_path: Path) -> None:
    assert load_id_migration_map(tmp_path / "missing.csv") == []


def test_load_id_migration_map_rows(tmp_path: Path) -> None:
    p = tmp_path / "poam-id-migration.csv"
    p.write_text(
        "old_id,new_id,disposition,reason\n"
        "EGP-OLD1,EGP-NEW,rolled_into_pkg_parent,pkg\n"
        "EGP-OLD2,,retired_dropped,testssl grade_drop\n",
        encoding="utf-8",
    )
    rows = load_id_migration_map(p)
    assert len(rows) == 2
    assert rows[0]["old_id"] == "EGP-OLD1"
    assert rows[1]["disposition"] == "retired_dropped"


def test_apply_ledger_migration_open_closed_mix_and_resign() -> None:
    """Open/closed mix; retired child closed + excluded_reason; parent derivation."""
    ledger = empty_ledger()
    ledger["items"] = {
        "fp-a": _item(fp="fp-a", poam_id="EGP-A", status="open", odd="2026-10-01"),
        "fp-b": _item(fp="fp-b", poam_id="EGP-B", status="closed", odd="2026-09-15"),
        "fp-g": _item(fp="fp-g", poam_id="EGP-GRADE", status="open", odd="2026-10-03"),
    }
    ledger["id_migration_map"] = [
        {
            "old_id": "EGP-A",
            "new_id": "EGP-PARENT",
            "disposition": "rolled_into_pkg_parent",
            "reason": "pkg rollup",
        },
        {
            "old_id": "EGP-B",
            "new_id": "EGP-PARENT",
            "disposition": "rolled_into_pkg_parent",
            "reason": "pkg rollup",
        },
        {
            "old_id": "EGP-GRADE",
            "new_id": "",
            "disposition": "retired_dropped",
            "reason": "testssl grade_drop",
        },
    ]
    catalog = KevCatalog(kev_evaluated=False, reason="snapshot_missing")
    out = apply_ledger([], catalog=catalog, ledger_in=ledger, prior_existed=True)
    # retired grade carried closed with explicit reason
    closed_reasons = {
        str(c.get("poam_id") or ""): str(c.get("excluded_reason") or "")
        for c in (out.get("closed") or [])
        if isinstance(c, dict)
    }
    assert closed_reasons.get("EGP-GRADE") == "retired_grade_row"
    assert any(str(c.get("excluded_reason") or "").startswith("rolled_into:") for c in out["closed"])
    # parent exists with derived open (child open) and earliest odd
    parents = [
        it
        for it in (out.get("items") or {}).values()
        if isinstance(it, dict) and str(it.get("poam_id") or "") == "EGP-PARENT"
    ]
    assert len(parents) == 1
    parent = parents[0]
    assert parent["status"] == "open"
    assert parent.get("status_derivation") == "child_open_or_reopened"
    assert parent.get("original_detection_date") == "2026-09-15"  # earliest
    assert out.get("_id_migration_applied") is True


def test_apply_ledger_migration_idempotent_rerun() -> None:
    ledger = empty_ledger()
    ledger["items"] = {
        "fp-a": _item(fp="fp-a", poam_id="EGP-A", status="open", odd="2026-10-01"),
    }
    ledger["id_migration_map"] = [
        {
            "old_id": "EGP-A",
            "new_id": "EGP-PARENT",
            "disposition": "rolled_into_pkg_parent",
            "reason": "pkg",
        }
    ]
    catalog = KevCatalog(kev_evaluated=False, reason="snapshot_missing")
    once = apply_ledger([], catalog=catalog, ledger_in=deepcopy(ledger), prior_existed=True)
    twice = apply_ledger([], catalog=catalog, ledger_in=deepcopy(once), prior_existed=True)
    # flag stays; no double-close explosion beyond first apply
    assert once.get("_id_migration_applied") is True
    assert twice.get("_id_migration_applied") is True
    parents_once = [
        it for it in once["items"].values() if str(it.get("poam_id") or "") == "EGP-PARENT"
    ]
    parents_twice = [
        it for it in twice["items"].values() if str(it.get("poam_id") or "") == "EGP-PARENT"
    ]
    assert len(parents_once) == 1
    assert len(parents_twice) == 1
    assert parents_once[0].get("original_detection_date") == parents_twice[0].get(
        "original_detection_date"
    )


def test_migration_map_generator_determinism(tmp_path: Path) -> None:
    """build_migration_map is deterministic on synthetic rows."""
    import sys

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "scripts"))
    from fixstack.build_migration_map import build_migration_map, write_migration_map

    old_rows = [
        {
            "poam_id": "EGP-1",
            "detector_source": "trivy",
            "asset": "example/db:1.0",
            "weakness": "CVE-2024-1 openssl",
            "weakness_source_id": "CVE-2024-1",
            "finding_ref_id": "ref-1",
        },
        {
            "poam_id": "EGP-2",
            "detector_source": "testssl",
            "asset": "10.0.0.1",
            "weakness": "Overall grade T",
            "weakness_source_id": "overall_grade",
            "finding_ref_id": "ref-g",
        },
    ]
    new_rows = [
        {
            "poam_id": "EGP-PKG",
            "detector_source": "trivy",
            "asset": "example/db:1.0",
            "weakness": "openssl package rollup",
            "weakness_source_id": "pkg:openssl",
            "finding_ref_id": "ref-pkg",
        }
    ]
    a = build_migration_map(old_rows, new_rows, [], {})
    b = build_migration_map(old_rows, new_rows, [], {})
    assert a == b
    out = tmp_path / "map.csv"
    write_migration_map(out, a)
    loaded = load_id_migration_map(out)
    assert [r["old_id"] for r in loaded] == [r["old_id"] for r in a]


def test_classify_testssl_cve_beats_posture_and_fail_ids() -> None:
    import sys

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "scripts"))
    from fixstack.testssl_fix import FAIL_IDS, classify_testssl

    assert "secure_renego" not in FAIL_IDS
    assert "fallback_scsv" not in FAIL_IDS
    # CVE beats posture-looking name
    assert (
        classify_testssl("cert_chain_of_trust", "cert issue CVE-2024-1234", "desc")
        == "keep_real"
    )
    assert classify_testssl("overall_grade", "Overall grade T", "") == "grade_drop"
    assert (
        classify_testssl("scanproblem", "couldn't connect to host", "check failed")
        == "failed_drop"
    )


def test_shared_testssl_emit_drops_grade_and_marks_failed_connect() -> None:
    from shared.testssl import _emit

    assert _emit({"id": "overall_grade", "severity": "high", "finding": "Overall grade T"}, "h") is None
    failed = _emit(
        {"id": "scanproblem", "severity": "high", "finding": "couldn't connect to host"},
        "h",
    )
    assert failed is not None
    assert "coverage-gap" in (failed.get("labels") or [])
    cve = _emit(
        {"id": "heartbleed", "severity": "critical", "finding": "CVE-2014-0160 heartbleed", "cve": "CVE-2014-0160"},
        "h",
        "1.2.3.4",
    )
    assert cve is not None
    assert cve.get("cve") == "CVE-2014-0160"


def test_payload_sha256_changes_when_items_change() -> None:
    a = empty_ledger()
    a["items"] = {"fp": _item(fp="fp", poam_id="EGP-1")}
    b = deepcopy(a)
    b["items"]["fp"]["status"] = "closed"
    assert payload_sha256(a) != payload_sha256(b)


def test_fixstack_apply_migration_resigns(tmp_path: Path) -> None:
    """apply_migration_to_ledger writes sha256 (not unsigned)."""
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[1]
    path = root / "scripts" / "fixstack_apply.py"
    spec = importlib.util.spec_from_file_location("fixstack_apply_prior-unit", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    ledger_path = tmp_path / "poam-ledger.json"
    doc = empty_ledger()
    doc["items"] = {
        "fp-a": _item(fp="fp-a", poam_id="EGP-A", status="open", odd="2026-10-01"),
        "fp-g": _item(fp="fp-g", poam_id="EGP-G", status="open", odd="2026-10-02"),
    }
    doc["sha256"] = payload_sha256(doc)
    ledger_path.write_text(json.dumps(doc), encoding="utf-8")
    map_rows = [
        {
            "old_id": "EGP-A",
            "new_id": "EGP-P",
            "disposition": "rolled_into_pkg_parent",
            "reason": "pkg",
        },
        {
            "old_id": "EGP-G",
            "new_id": "",
            "disposition": "retired_dropped",
            "reason": "testssl grade_drop",
        },
    ]
    report: dict = {}
    mod.apply_migration_to_ledger(ledger_path, map_rows, {"EGP-P"}, report)
    out = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert out.get("sha256")
    assert out["sha256"] == payload_sha256(out)
    assert report.get("ledger", {}).get("retired_closed_seen") == 1


def test_fixstack_apply_migration_idempotent_prior_out_no_closed_reappend(tmp_path: Path) -> None:
    """prior-unit: re-apply map on a post-migration ledger must not grow closed (prior-out path)."""
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[1]
    path = root / "scripts" / "fixstack_apply.py"
    spec = importlib.util.spec_from_file_location("fixstack_apply_prior-unit", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    ledger_path = tmp_path / "poam-ledger.json"
    doc = empty_ledger()
    doc["items"] = {
        "fp-a": _item(fp="fp-a", poam_id="EGP-A", status="open", odd="2026-10-01"),
        "fp-b": _item(fp="fp-b", poam_id="EGP-B", status="open", odd="2026-09-01"),
        "fp-g": _item(fp="fp-g", poam_id="EGP-G", status="open", odd="2026-10-02"),
    }
    doc["sha256"] = payload_sha256(doc)
    ledger_path.write_text(json.dumps(doc), encoding="utf-8")
    map_rows = [
        {
            "old_id": "EGP-A",
            "new_id": "EGP-P",
            "disposition": "rolled_into_pkg_parent",
            "reason": "pkg",
        },
        {
            "old_id": "EGP-B",
            "new_id": "EGP-P",
            "disposition": "rolled_into_pkg_parent",
            "reason": "pkg",
        },
        {
            "old_id": "EGP-G",
            "new_id": "",
            "disposition": "retired_dropped",
            "reason": "testssl grade_drop",
        },
    ]
    report1: dict = {}
    mod.apply_migration_to_ledger(ledger_path, map_rows, {"EGP-P"}, report1)
    once = json.loads(ledger_path.read_text(encoding="utf-8"))
    closed_once = len(once.get("closed") or [])
    mig_once = len(once.get("fp_migrations") or [])
    assert closed_once >= 3  # A, B rolled + G retired
    # Simulate run2 prior-out: parent stays in items; closed already has children;
    # map re-applied (fresh prove may reintroduce nothing — still re-run map).
    report2: dict = {}
    mod.apply_migration_to_ledger(ledger_path, map_rows, {"EGP-P"}, report2)
    twice = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert len(twice.get("closed") or []) == closed_once
    assert len(twice.get("fp_migrations") or []) == mig_once
    assert report2.get("ledger", {}).get("skipped_already_closed", 0) >= 1
    # Third apply still stable
    mod.apply_migration_to_ledger(ledger_path, map_rows, {"EGP-P"}, {})
    thrice = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert len(thrice.get("closed") or []) == closed_once


def test_apply_ledger_migration_skips_already_closed_old_ids() -> None:
    """prior-unit apply_ledger path: closed old IDs never re-appended when map re-runs."""
    ledger = empty_ledger()
    parent_fp = hashlib.sha256(b"mig-parent|EGP-PARENT").hexdigest()
    ledger["items"] = {
        parent_fp: _item(fp=parent_fp, poam_id="EGP-PARENT", status="open", odd="2026-09-15"),
    }
    closed_child = _item(fp="fp-a", poam_id="EGP-A", status="closed", odd="2026-10-01")
    closed_child["excluded_reason"] = "rolled_into:EGP-PARENT"
    ledger["closed"] = [closed_child]
    ledger["id_migration_map"] = [
        {
            "old_id": "EGP-A",
            "new_id": "EGP-PARENT",
            "disposition": "rolled_into_pkg_parent",
            "reason": "pkg",
        }
    ]
    # Also put a live twin in items (fresh prove re-mint) — still must not double closed
    ledger["items"]["fp-a-live"] = _item(fp="fp-a-live", poam_id="EGP-A", status="open", odd="2026-10-05")
    catalog = KevCatalog(kev_evaluated=False, reason="snapshot_missing")
    out = apply_ledger([], catalog=catalog, ledger_in=deepcopy(ledger), prior_existed=True)
    closed_a = [
        c
        for c in (out.get("closed") or [])
        if isinstance(c, dict) and str(c.get("poam_id") or "") == "EGP-A"
    ]
    assert len(closed_a) == 1


def test_classify_testssl_strips_prefix_and_detects_wsid() -> None:
    import sys

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "scripts"))
    from fixstack.testssl_fix import classify_testssl, is_testssl_poam

    assert classify_testssl("testssl:cipher-tls1_2_xc028", "Cipher-tls1 2 xc028", "") == "posture_roll"
    assert classify_testssl("testssl:overall_grade", "Overall grade", "") == "grade_drop"
    assert is_testssl_poam(
        {
            "detector_source": "vuln-scan",
            "weakness_source_id": "testssl:cipherlist_STRONG_FS",
            "weakness": "Cipherlist STRONG FS",
        }
    )
    assert not is_testssl_poam(
        {"detector_source": "vuln-scan (trivy)", "weakness_source_id": "CVE-2024-1", "weakness": "x"}
    )
