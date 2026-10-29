"""Fail-before/pass-after: s7b Trivy image-scope rename carries IDs as renames.

s7b renamed container-image language/binary Targets from "Node.js" to
"<image> :: Node.js". Across that upgrade a carried ledger must show those
items as renamed (one-time old->new map), not removed and re-added.
Synthetic images only.
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from shared.asset_ledger import make_asset_uid
from shared.kev import KevCatalog
from shared.poam_ledger import apply_ledger, empty_ledger
from shared.trivy_image_scope import (
    RENAME_DISPOSITION,
    RENAME_REASON,
    classify_drift,
    legacy_asset_uid,
    legacy_pkg_poam_id,
)
from scripts import fixstack_apply

IMAGES = ("example/app:1.0", "example/web:2.0")


def _finding(target: str, image: str | None, vid: str) -> dict:
    name = f"{image} :: {target}" if image else target
    from shared.schema import make_ref

    return {
        "kind": "finding",
        "source": "vuln-scan",
        "ref_id": make_ref("vuln-scan", f"{vid}-{name}"),
        "name": f"example-lib: {vid}",
        "description": "synthetic",
        "severity": "high",
        "status": "open",
        "category": "vulnerability",
        "assets": [name],
        "labels": [],
        "collected_at": "2026-10-01T00:00:00Z",
        # pre-s7b (j3 shape) the bare Target was the image_ref anchor
        "extra": {
            "cve": vid,
            "ids": {"image_ref": name},
            "asset_uid": make_asset_uid("image_ref", name),
            "scan_time": "2026-10-01T00:00:00Z",
        },
    }


def _run(findings: list[dict], ledger_in: dict | None, day: int) -> dict:
    return apply_ledger(
        findings,
        catalog=KevCatalog({}),
        run_at=datetime(2026, 10, day, tzinfo=timezone.utc),
        ledger_in=ledger_in,
    )


def _live(ledger: dict) -> dict[str, dict]:
    return {str(i["poam_id"]): i for i in ledger["items"].values()}


def test_legacy_ids_derive_from_bare_target() -> None:
    assert legacy_asset_uid("example/app:1.0 :: Node.js") == make_asset_uid("image_ref", "Node.js")
    assert legacy_asset_uid("example/app:1.0 (debian 12)") == ""
    want = "EGP-" + hashlib.sha256(b"trivy-pkg-v1|Node.js|example-lib").hexdigest()[:10].upper()
    assert legacy_pkg_poam_id("example/app:1.0 :: Node.js", "example-lib") == want


def test_ledger_carries_poam_ids_across_rename() -> None:
    old = [_finding("Node.js", None, "CVE-2024-0001")]
    new = [_finding("Node.js", IMAGES[0], "CVE-2024-0001")]
    l1 = _run(old, None, 1)
    l2 = _run(new, l1, 2)
    before, after = _live(l1), _live(l2)
    drift = classify_drift(before, after)
    assert drift == {"added": [], "removed": [], "renamed": []}, drift
    (pid,) = after
    assert after[pid]["first_seen"] == before[pid]["first_seen"]
    assert l2["closed"] == []
    reasons = {m["reason"] for m in l2["fp_migrations"]}
    assert RENAME_REASON in reasons
    kinds = {(r["kind"], r["old_id"], r["new_id"]) for r in l2["id_renames"]}
    assert ("vuln_ref", old[0]["ref_id"], new[0]["ref_id"]) in kinds
    assert (
        "asset_key",
        make_asset_uid("image_ref", "Node.js"),
        make_asset_uid("image_ref", f"{IMAGES[0]} :: Node.js"),
    ) in kinds


def test_first_run_has_no_rename_records() -> None:
    l1 = _run([_finding("Node.js", IMAGES[0], "CVE-2024-0001")], None, 1)
    assert not l1.get("id_renames")
    assert all(m.get("reason") != RENAME_REASON for m in l1["fp_migrations"])


def _parent(pid: str, asset: str, pkg: str) -> dict[str, str]:
    return {
        "poam_id": pid,
        "asset": asset,
        "weakness_source_id": f"pkg:{pkg}",
        "finding_ref_id": f"VULN-pkg-{pkg}-{fixstack_apply._slug(asset)}"[:180],
        "detector_source": "vuln-scan (trivy) [pkg-rollup]",
    }


def test_fixstack_pkg_parent_renamed_not_removed(tmp_path: Path) -> None:
    pkg = "example-lib"
    new_rows = []
    old_ids: dict[str, str] = {}
    for img in IMAGES:
        scoped = f"{img} :: Node.js"
        new_id = "EGP-" + hashlib.sha256(f"trivy-pkg-v1|{scoped}|{pkg}".encode()).hexdigest()[:10].upper()
        new_rows.append(_parent(new_id, scoped, pkg))
        old_ids[new_id] = legacy_pkg_poam_id(scoped, pkg)
    old_pid = next(iter(old_ids.values()))
    assert len(set(old_ids.values())) == 1  # pre-s7b both images shared one asset
    ledger = empty_ledger()
    ledger["items"] = {
        "fp-old-parent": {
            "fp": "fp-old-parent",
            "poam_id": old_pid,
            "status": "open",
            "first_seen": "2026-09-01T00:00:00Z",
            "original_detection_date": "2026-09-01",
            "excluded_reason": "",
        }
    }
    lp = tmp_path / "poam-ledger.json"
    lp.write_text(json.dumps(ledger), encoding="utf-8")
    prior_live = {old_pid}

    mig, ren = fixstack_apply.image_scope_rename_rows(new_rows, lp)
    assert {(m["old_id"], m["new_id"], m["disposition"]) for m in mig} == {
        (old_pid, nid, RENAME_DISPOSITION) for nid in old_ids
    }
    report: dict = {}
    fixstack_apply.apply_migration_to_ledger(lp, mig, set(old_ids), report)
    doc = json.loads(lp.read_text(encoding="utf-8"))
    live = {i["poam_id"]: i for i in doc["items"].values()}
    assert set(live) == set(old_ids)
    assert doc["closed"] == []  # a rename is not a closure
    for item in live.values():
        assert item["original_detection_date"] == "2026-09-01"
        assert item["renamed_from"] == [old_pid]
    drift = classify_drift(prior_live, set(live), mig)
    assert drift["removed"] == [] and drift["added"] == []
    assert {n for _o, n in drift["renamed"]} <= set(old_ids)
    assert any(r["kind"] == "vuln_ref" for r in ren)

    out = tmp_path / "id-rename-map.csv"
    fixstack_apply._write_rename_map(out, lp, ren, {})
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert {r["kind"] for r in rows} == {"poam_id", "vuln_ref"}


def test_fixstack_no_prior_parent_no_map(tmp_path: Path) -> None:
    lp = tmp_path / "poam-ledger.json"
    lp.write_text(json.dumps(empty_ledger()), encoding="utf-8")
    rows = [_parent("EGP-0000000001", f"{IMAGES[0]} :: Node.js", "example-lib")]
    assert fixstack_apply.image_scope_rename_rows(rows, lp) == ([], [])
    out = tmp_path / "id-rename-map.csv"
    fixstack_apply._write_rename_map(out, lp, [], {})
    assert not out.exists()


def test_ledger_rename_when_stored_fp_is_older_scheme() -> None:
    """Stored fp from an older key scheme: match on stored asset_key + weakness_key."""
    old = [_finding("usr/local/bin/example", None, "CVE-2024-0005")]
    l1 = _run(old, None, 1)
    (fp, item), = l1["items"].items()
    l1["items"] = {"fp-older-scheme": {**item, "fp": "fp-older-scheme"}}
    l2 = _run([_finding("usr/local/bin/example", IMAGES[1], "CVE-2024-0005")], l1, 2)
    assert set(_live(l2)) == {item["poam_id"]}
    assert any(m.get("reason") == RENAME_REASON for m in l2["fp_migrations"])
    assert l2["closed"] == []
