"""prior-unit behavior: pr-b fixstack fields via tip-existing vuln_scan.parse_file + fixstack_apply.

Fail-before on tip 6a82705 = AssertionError (not ImportError):
  - trivy FixedVersion must land in finding.extra["fixed_version_hint"]
  - post-prove fixstack_apply must rewrite parent original_detection_date from open kids
"""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
from pathlib import Path

from collectors import vuln_scan

ROOT = Path(__file__).resolve().parents[1]


def _trivy_payload() -> dict:
    return {
        "SchemaVersion": 2,
        "CreatedAt": "2026-10-01T12:00:00Z",
        "ArtifactName": "app.example.com/api:1.2.3",
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "app.example.com/api:1.2.3",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-BEH001",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "FixedVersion": "3.0.13",
                        "Severity": "HIGH",
                        "Title": "openssl buffer issue",
                        "Description": "Upgrade openssl to 3.0.13 to remediate CVE-2024-BEH001.",
                        "Status": "fixed",
                    }
                ],
            }
        ],
    }


def test_trivy_fixed_version_hint_on_finding_extra(tmp_path: Path) -> None:
    """Collector path: FixedVersion must appear as extra.fixed_version_hint (pr-b vuln_scan)."""
    p = tmp_path / "trivy-beh001.json"
    p.write_text(json.dumps(_trivy_payload()), encoding="utf-8")
    recs = vuln_scan.parse_file(p)
    finds = [r for r in recs if r.get("kind") == "finding"]
    assert finds, "expected trivy findings from synthetic payload"
    # Prefer CVE row
    hit = None
    for r in finds:
        extra = r.get("extra") or {}
        blob = f"{r.get('name')} {r.get('description')} {extra}"
        if "CVE-2024-BEH001" in blob or "openssl" in blob.lower():
            hit = r
            break
    if hit is None:
        hit = finds[0]
    extra = hit.get("extra") if isinstance(hit.get("extra"), dict) else {}
    hint = str(extra.get("fixed_version_hint") or extra.get("fixed_version") or "")
    assert hint and "3.0.13" in hint, (
        f"expected fixed_version_hint containing 3.0.13 on finding extra; "
        f"got extra={extra!r} name={hit.get('name')!r} "
        f"(tip lacks pr-b vuln_scan FixedVersion→hint insertion)"
    )


def _load_fixstack_apply():
    path = ROOT / "scripts" / "fixstack_apply.py"
    assert path.is_file(), "fixstack_apply.py missing (pr-b)"
    spec = importlib.util.spec_from_file_location("fixstack_apply_beh001", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def _item(pid: str, status: str, odd: str, name: str = "pkg") -> dict:
    return {
        "poam_id": pid,
        "fp": f"fp-{pid}",
        "name": name,
        "description": name,
        "status": status,
        "original_detection_date": odd,
        "first_seen": odd,
        "status_date": "2026-10-07",
        "asset_key": "10.0.0.90",
        "display_asset": "parent-date.example.com",
        "source_family": "vuln-scan",
        "weakness_key": name,
        "original_risk_rating": "High",
        "current_scanner_rating": "high",
        "cves": [],
        "framework_refs": "",
        "remediation_plan": "Upgrade openssl to 3.0.13",
        "vendor_dependency": "No",
    }


def test_fixstack_apply_parent_keeps_earliest_open_child_date(tmp_path: Path) -> None:
    """fixstack_apply migration: parent original_detection_date = earliest OPEN child.

    Without pr-b apply_migration / open-aware earliest merge this assert fails.
    """
    mod = _load_fixstack_apply()
    assert hasattr(mod, "apply_migration_to_ledger"), "apply_migration_to_ledger missing"

    parent = "EGP-PARENT-BEH001"
    preclosed = "EGP-OLD-PRECLOSED"
    open_a = "EGP-OLD-OPEN-A"
    open_b = "EGP-OLD-OPEN-B"
    items = {
        parent: _item(parent, "open", "2026-09-01", "parent"),
        open_a: _item(open_a, "open", "2026-03-01", "child-a"),
        open_b: _item(open_b, "open", "2026-04-01", "child-b"),
    }
    # Some ledgers key by fp; support both shapes via items values list rewrite
    # Prefer id-keyed as used by apply_migration
    closed = [
        {
            **_item(preclosed, "closed", "2025-12-01", "preclosed"),
            "excluded_reason": "preexisting_closed",
        }
    ]
    map_rows = [
        {
            "old_id": preclosed,
            "new_id": parent,
            "disposition": "rolled_into_pkg_parent",
            "reason": "synthetic",
        },
        {
            "old_id": open_a,
            "new_id": parent,
            "disposition": "rolled_into_pkg_parent",
            "reason": "synthetic",
        },
        {
            "old_id": open_b,
            "new_id": parent,
            "disposition": "rolled_into_pkg_parent",
            "reason": "synthetic",
        },
    ]
    lp = tmp_path / "poam-ledger.json"
    # Build ledger in shape expected by shared.poam_ledger consumers
    try:
        from shared.poam_ledger import payload_sha256
    except Exception:  # noqa: BLE001
        payload_sha256 = None

    doc = {
        "items": copy.deepcopy(items),
        "closed": copy.deepcopy(closed),
        "schema": "poam-ledger-v1",
    }
    if payload_sha256:
        try:
            doc["payload_sha256"] = payload_sha256(doc)
        except Exception:  # noqa: BLE001
            doc["payload_sha256"] = "0" * 64
    else:
        doc["payload_sha256"] = "0" * 64
    lp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report: dict = {}
    mod.apply_migration_to_ledger(
        lp,
        map_rows,
        new_poam_ids={parent},
        report=report,
    )
    after = json.loads(lp.read_text(encoding="utf-8"))
    # locate parent item
    parent_item = None
    items_after = after.get("items") or {}
    if isinstance(items_after, dict):
        for k, v in items_after.items():
            if isinstance(v, dict) and (
                v.get("poam_id") == parent or k == parent or v.get("poam_id") == parent
            ):
                parent_item = v
                break
        if parent_item is None and parent in items_after:
            parent_item = items_after[parent]
    elif isinstance(items_after, list):
        for v in items_after:
            if isinstance(v, dict) and v.get("poam_id") == parent:
                parent_item = v
                break
    assert parent_item is not None, f"parent {parent} missing after migration; keys={list(items_after)[:20] if isinstance(items_after, dict) else 'list'}"
    odd = str(parent_item.get("original_detection_date") or "")
    # earliest OPEN child is 2026-03-01 — must NOT keep preclosed 2025-12-01 or parent 2026-09-01 alone
    assert "2026-03-01" in odd, (
        f"expected parent original_detection_date from earliest OPEN child 2026-03-01; got {odd!r} "
        f"report={report!r}"
    )
    # status derivation when all remaining mapped kids considered
    if hasattr(mod, "_derive_parent_status"):
        st, der = mod._derive_parent_status(
            [
                {"status": "closed", "poam_id": "x"},
                {"status": "closed", "poam_id": "y"},
            ]
        )
        assert st == "closed", (st, der)
        assert "all_children_closed" in str(der)


def test_lab_drop_invokes_fixstack_apply_hook() -> None:
    """lab_drop must call fixstack_apply after prove (hook present + module file)."""
    sh = (ROOT / "scripts" / "lab_drop_to_sor.sh").read_text(encoding="utf-8")
    assert "fixstack_apply" in sh, "lab_drop missing fixstack_apply invocation"
    assert (ROOT / "scripts" / "fixstack_apply.py").is_file()
    assert (ROOT / "scripts" / "fixstack" / "rollup.py").is_file() or (
        ROOT / "scripts" / "fixstack"
    ).is_dir()
