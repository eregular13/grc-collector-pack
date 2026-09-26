"""Fail-closed export accounting: every parsed finding/excluded lands once.

Custodian unknown → POA&M needs-review. kind:excluded (Custodian cost +
osquery unmapped) lands in excluded.csv with id + reason. Prowler FAIL on
placeholder resources stays under account:<uid or unknown>. An e546db1
ledger upgrade keeps every carried POA&M ID. SAMPLE/DEMO ≠ client KEEP.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from collectors import cloud_prowler, host_wazuh
from collectors.grc_loader import _dedupe, load
from shared.ciso_shape import (
    EXCLUDED_HEADER,
    EXCLUDED_FIELDS,
    RegisterShapeError,
    assert_input_export_accounting,
)
from shared.control_map import map_finding, poam_decision
from shared.finding_types import dedupe_weaknesses
from shared.hardening_dedup import dedupe_hardening
from shared.io_util import out_dir, write_canonical
from shared.kev import KevCatalog
from shared.poam_ledger import apply_ledger, empty_ledger, fp_v1
from shared.schema import make_record, make_ref

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _deduped(recs: list[dict]) -> list[dict]:
    return dedupe_hardening(dedupe_weaknesses(_dedupe(recs)))


def test_excluded_csv_header_has_id_column() -> None:
    assert "id" in EXCLUDED_FIELDS
    assert EXCLUDED_HEADER.startswith("id,")


def test_kind_excluded_custodian_cost_lands_in_excluded_csv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recs = cloud_prowler.parse_file(
        SAMPLES / "cloud" / "stop-underutilized-azure-vms" / "resources.json"
    )
    excluded = [r for r in recs if r.get("kind") == "excluded"]
    assert len(excluded) == 8
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    write_canonical("cloud-prowler", recs)
    summary = load()
    path = out_dir() / "poam" / "excluded.csv"
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert path.read_text(encoding="utf-8").splitlines()[0] == EXCLUDED_HEADER
    by_id = {row["id"]: row for row in rows}
    for rec in excluded:
        hit = by_id[rec["ref_id"]]
        assert hit["finding_ref_id"] == rec["ref_id"]
        assert hit["excluded_reason"] == "not_a_weakness"
        assert hit["excluded_reason"] != "NOT_A_WEAKNESS"
        assert hit["id"]
    assert summary["kind_excluded"] == 8
    assert summary["excluded"] >= 8


def test_osquery_unmapped_is_same_class_and_lands_in_excluded_csv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real-sample osquery unmapped rows were the same silent kind:excluded drop.

    Cold review cited 21 vanishing osquery records; after collapse the
    public corpus emits 14 unmapped (11 results + 3 snapshots). Same class.
    """
    parsed: list[dict] = []
    for name in (
        "osqueryd.results.sample.log",
        "osqueryd.results.darwin.log",
        "msticpy.osqueryd.results.log",
        "msticpy.osqueryd.snapshots.log",
    ):
        parsed.extend(host_wazuh.parse_file(SAMPLES / "osquery" / name))
    unmapped = [r for r in parsed if r.get("kind") == "excluded"]
    assert len(unmapped) == 14, [r.get("ref_id") for r in unmapped]
    assert all((r.get("extra") or {}).get("exclude_reason") == "unmapped" for r in unmapped)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    write_canonical("host-wazuh", parsed)
    summary = load()
    with (out_dir() / "poam" / "excluded.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    ids = {row["id"] for row in rows}
    missing = [r["ref_id"] for r in unmapped if r["ref_id"] not in ids]
    assert missing == [], missing
    assert all(
        next(row for row in rows if row["id"] == rec["ref_id"])["excluded_reason"]
        == "unmapped"
        for rec in unmapped
    )
    assert summary["kind_excluded"] == 14


def test_real_sample_accounting_every_record_in_exactly_one_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed: list[dict] = []
    parsed.extend(
        cloud_prowler.parse_file(SAMPLES / "cloud" / "security-context-pods" / "resources.json")
    )
    parsed.extend(
        cloud_prowler.parse_file(
            SAMPLES / "cloud" / "stop-underutilized-azure-vms" / "resources.json"
        )
    )
    parsed.extend(
        cloud_prowler.parse_file(
            SAMPLES / "cloud" / "stop-underutilized-aws-instances" / "resources.json"
        )
    )
    parsed.extend(
        cloud_prowler.parse_file(
            SAMPLES / "cloud" / "check-ebs-snapshot-public" / "resources.json"
        )
    )
    parsed.extend(host_wazuh.parse_file(SAMPLES / "osquery" / "msticpy.osqueryd.results.log"))
    parsed.extend(host_wazuh.parse_file(SAMPLES / "osquery" / "msticpy.osqueryd.snapshots.log"))
    parsed.extend(host_wazuh.parse_file(SAMPLES / "osquery" / "osqueryd.results.sample.log"))
    parsed.extend(host_wazuh.parse_file(SAMPLES / "osquery" / "osqueryd.results.darwin.log"))
    parsed.extend(cloud_prowler.parse_file(SAMPLES / "prowler" / "example_output_aws.ocsf.json"))
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    write_canonical("mixed-samples", parsed)
    load()
    with (out_dir() / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        poam = list(csv.DictReader(fh))
    with (out_dir() / "poam" / "excluded.csv").open(encoding="utf-8", newline="") as fh:
        excluded = list(csv.DictReader(fh))
    records = _deduped(parsed)
    assert_input_export_accounting(
        [r for r in records if r.get("kind") in {"finding", "excluded"}],
        poam,
        excluded,
    )


def test_accounting_fails_loudly_with_missing_keys() -> None:
    recs = [
        make_record(
            kind="finding",
            source="cloud-prowler",
            ref_id="CLD-missing-1",
            name="vanished",
            severity="high",
            assets=["acct"],
        )
    ]
    with pytest.raises(RegisterShapeError, match="ACCOUNTING_FAIL missing record keys"):
        assert_input_export_accounting(recs, [], [])


def test_prowler_placeholder_fail_uses_account_unknown() -> None:
    recs = cloud_prowler.parse_file(SAMPLES / "prowler" / "example_output_aws.ocsf.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert all((r.get("assets") or [""])[0] == "account:unknown" for r in findings)
    assert all(poam_decision(r)["include"] is True for r in findings)
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "account:unknown" in assets


def test_e546db1_ledger_upgrade_keeps_every_carried_id() -> None:
    """New needs-review rows may add IDs; every e546db1 carried ID stays."""
    carried = [
        make_record(
            kind="finding",
            source="cloud-prowler",
            ref_id=make_ref("cloud-prowler", "s3-encryption-missing-bucket-a"),
            name="Cloud Custodian s3-encryption-missing",
            description="encryption missing",
            severity="medium",
            category="cloud-misconfiguration",
            assets=["arn:aws:s3:::bucket-a"],
            extra={"check_id": "s3-encryption-missing", "status": "FAIL"},
        ),
        make_record(
            kind="finding",
            source="cloud-prowler",
            ref_id=make_ref("cloud-prowler", "security-context-pods-test-pod"),
            name="Cloud Custodian security-context-pods",
            description="privileged pod",
            severity="medium",
            category="cloud-misconfiguration",
            assets=["test/test-pod-1"],
            extra={"check_id": "security-context-pods", "status": "FAIL"},
        ),
    ]
    seeded = empty_ledger()
    old_ids: list[str] = []
    for i, rec in enumerate(carried, start=1):
        fp = fp_v1(rec)
        pid = f"EGP-E546{i:04d}XX"
        old_ids.append(pid)
        seeded["items"][fp] = {
            "poam_id": pid,
            "fp": fp,
            "source_family": rec["source"],
            "weakness_key": rec["name"],
            "asset_key": (rec.get("assets") or [""])[0],
            "ref_id": rec["ref_id"],
            "name": rec["name"],
            "original_detection_date": "2026-09-01",
            "first_seen": "2026-09-01T00:00:00Z",
            "status": "open",
            "severity": rec["severity"],
            "missed_covered_runs": 0,
            "kev_comments": [],
        }
    newcomer = make_record(
        kind="finding",
        source="cloud-prowler",
        ref_id=make_ref("cloud-prowler", "rds-publicly-accessible-db-1"),
        name="Cloud Custodian rds-publicly-accessible",
        description="RDS publicly accessible",
        severity="medium",
        category="cloud-misconfiguration",
        assets=["db-1"],
        extra={
            "check_id": "rds-publicly-accessible",
            "status": "FAIL",
            "needs_review": True,
            "classification": "needs-review",
        },
    )
    assert poam_decision(newcomer)["include"] is True
    assert poam_decision(newcomer)["reason"] == "needs_review"
    assert map_finding(newcomer)["include_poam"] is True
    out = apply_ledger(
        carried + [newcomer],
        catalog=_unevaluated(),
        ledger_in=seeded,
        prior_existed=True,
    )
    open_items = [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]
    reseen = {it["poam_id"] for it in open_items}
    assert set(old_ids) <= reseen
    created = [e for e in (out.get("events_this_run") or []) if e.get("kind") == "created"]
    assert created, "needs-review newcomer must mint a new ID"
    assert all(e.get("poam_id") not in old_ids for e in created)


def _unknown_policy_payload(name: str, resources: list[dict]) -> dict:
    return {
        "name": name,
        "resource": "aws.ec2",
        "description": "stage label or age window",
        "filters": [],
        "resources": resources,
    }


def test_two_unknown_policies_on_200_resources_are_two_egr_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Needs-review rolls up per policy+account (EGR-), not per resource.

    Two unknown tagging/age policies × 200 resources used to mint 200
    needs-review rows (over the 50/100-asset budget). One POA&M row per
    unknown policy; known security stays per resource.
    """
    from shared.poam_ledger import egr_key, assign_poam_id

    account = "111122223333"
    names = ("require-owner-tag", "snapshot-age-days")
    for name in names:
        assert cloud_prowler._custodian_classify(
            name, {"description": "stage label or age window", "resource": "aws.ec2"}
        ) == "unknown"

    def _resources(prefix: str, order: range) -> list[dict]:
        return [
            {"InstanceId": f"i-{prefix}{i:04d}", "AccountId": account} for i in order
        ]

    payload = {
        "policies": [
            _unknown_policy_payload(names[0], _resources("tag", range(200))),
            _unknown_policy_payload(names[1], _resources("age", range(200))),
        ]
    }
    src = tmp_path / "unknown-rollups.json"
    src.write_text(json.dumps(payload), encoding="utf-8")
    recs = cloud_prowler.parse_file(src)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert len(findings) == 2, [r.get("ref_id") for r in findings]
    by_check = {(r.get("extra") or {}).get("check_id"): r for r in findings}
    assert set(by_check) == set(names)
    for name, hit in by_check.items():
        extra = hit.get("extra") or {}
        assert extra.get("needs_review") is True
        assert extra.get("rollup") is True
        assert extra.get("poam_prefix") == "EGR-"
        assert extra.get("affected_count") == 200
        assert len(extra.get("resources") or []) == 200
        assert extra["resources"] == sorted(extra["resources"])
        assert hit["assets"] == [f"account:{account}"]
        assert f"matched 200 resources" in (hit.get("description") or "")
        assert extra["resources"][0] in (hit.get("description") or "")

    sec = cloud_prowler._custodian_findings(
        {
            "name": "s3-encryption-missing",
            "resource": "aws.s3",
            "description": "unencrypted buckets",
            "filters": [],
            "resources": [
                {"Name": "bucket-a", "AccountId": account},
                {"Name": "bucket-b", "AccountId": account},
            ],
        }
    )
    assert len(sec) == 2
    assert all(not r.get("NeedsReview") and not r.get("Rollup") for r in sec)
    assert [r["ResourceId"] for r in sec] == ["bucket-a", "bucket-b"]

    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out-a"))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    write_canonical("cloud-prowler", recs)
    summary = load()
    with (out_dir() / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        poam = list(csv.DictReader(fh))
    assert len(poam) == 2
    ids = [row["poam_id"] for row in poam]
    assert all(pid.startswith("EGR-") for pid in ids)
    assert len(set(ids)) == 2
    expected = {
        names[0]: assign_poam_id(egr_key(names[0], account), {}, prefix="EGR-"),
        names[1]: assign_poam_id(egr_key(names[1], account), {}, prefix="EGR-"),
    }
    for name, pid in expected.items():
        hit = next(
            row
            for row in poam
            if name in (row.get("weakness_source_id") or row.get("weakness") or "")
        )
        assert hit["poam_id"] == pid
        detail = " ".join(
            str(hit.get(k) or "")
            for k in ("weakness_description", "weakness", "recommended_fix", "comments")
        )
        assert "200" in detail
    assert summary["poam"] == 2

    shuffled = {
        "policies": [
            _unknown_policy_payload(names[0], _resources("tag", range(199, -1, -1))),
            _unknown_policy_payload(names[1], _resources("age", range(199, -1, -1))),
        ]
    }
    src2 = tmp_path / "unknown-rollups-shuffled.json"
    src2.write_text(json.dumps(shuffled), encoding="utf-8")
    recs2 = cloud_prowler.parse_file(src2)
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out-b"))
    write_canonical("cloud-prowler", recs2)
    load()
    with (out_dir() / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        poam2 = list(csv.DictReader(fh))
    assert {row["poam_id"] for row in poam2} == set(ids)


def test_demo_ledger_upgrade_keeps_e546_carried_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Upgrade the frozen DEMO ledger: every prior ID is still present or aliased."""
    from tests.test_poam_breakdown import _run_lab

    prior = json.loads(
        ROOT.joinpath("tests", "fixtures", "demo-poam-ledger-master.json").read_text(
            encoding="utf-8"
        )
    )
    prior_ids = {it["poam_id"] for it in prior["items"].values()}
    assert prior_ids
    (tmp_path / "poam").mkdir(parents=True, exist_ok=True)
    (tmp_path / "poam" / "poam-ledger.json").write_text(
        json.dumps(prior, indent=2) + "\n", encoding="utf-8"
    )
    _run_lab(tmp_path, monkeypatch)
    ledger = json.loads((tmp_path / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    open_items = [
        it for it in ledger["items"].values() if str(it.get("status") or "") != "closed"
    ]
    reseen = {it["poam_id"] for it in open_items}
    aliases = {x for it in open_items for x in (it.get("aliased_poam_ids") or [])}
    ghosts = prior_ids - reseen - aliases
    assert ghosts == set(), f"e546db1 carried IDs dropped: {sorted(ghosts)}"
    assert prior_ids <= (reseen | aliases)
