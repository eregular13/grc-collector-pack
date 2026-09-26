"""Metis flood-guard: classify/build, named reasons, G0, stable EGP-."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from collectors.grc_loader import _dedupe, load
from shared.ciso_shape import EXCLUDED_HEADER, assert_flood_guard, csv_rows
from shared.control_map import (
    POAM_EXCLUDE_REASONS,
    REASON_CODES,
    iter_poam_decisions,
    poam_decision,
)
from shared.io_util import write_canonical
from shared.kev import KevCatalog
from shared.poam_fedramp import write_fedramp_poam
from shared.poam_ledger import apply_ledger, apply_rollups, fp_v1
from shared.poam_rollup import (
    REASON_CODES as ROLLUP_CODES,
    budget_source_cap,
    budget_target,
    classify,
    escalate_budget,
    extra_exclude_token,
    flood_guard_summary,
    reason_code_of,
)
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]


def _finding(**kwargs):
    defaults = dict(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-x",
        name="finding",
        description="finding",
        severity="low",
        category="exposure",
        assets=["box"],
        extra={"port": "22", "service": "ssh"},
    )
    defaults.update(kwargs)
    extra = defaults.get("extra")
    if isinstance(extra, dict):
        defaults["extra"] = dict(extra)
    return make_record(**defaults)


def test_reason_codes_cover_spec_minimum() -> None:
    needed = {
        "DUPLICATE_INSTANCE",
        "INFO_ONLY",
        "TELEMETRY",
        "NOT_A_WEAKNESS",
        "FALSE_POSITIVE_CANDIDATE",
        "MANUAL_CHECK",
        "MUTED",
        "HONEYPOT",
        "LIGHTER_LOW",
        "LIGHTER_MEDIUM",
        "ACCEPTED_RISK",
        "UNVERIFIED_BANNER_CVE",
        "NOT_YET_LATE",
    }
    assert needed <= REASON_CODES
    assert needed <= ROLLUP_CODES
    assert needed <= POAM_EXCLUDE_REASONS
    assert reason_code_of("severity_info") == "INFO_ONLY"
    assert reason_code_of("telemetry") == "TELEMETRY"
    assert reason_code_of("telemetry_duplicate") == "DUPLICATE_INSTANCE"
    assert reason_code_of("honeypot") == "HONEYPOT"
    assert reason_code_of("severity_low") == "LIGHTER_LOW"
    assert reason_code_of("severity_low", include=True) == "severity_low"
    assert reason_code_of("severity_medium_not_key") == "LIGHTER_MEDIUM"
    assert reason_code_of("") == "UNEXPLAINED"
    # Vocab only — E4 never assigned.
    assert reason_code_of("NOT_YET_LATE") == "NOT_YET_LATE"


def test_classify_extra_exclude_tokens() -> None:
    muted = _finding(extra={"port": "22", "exclude_reason": "MUTED"})
    assert extra_exclude_token(muted) == "MUTED"
    assert classify(muted)[0] == "muted"
    assert poam_decision(muted)["include"] is False
    assert poam_decision(muted)["reason"] == "MUTED"

    naw = _finding(extra={"exclude_reason": "NOT_A_WEAKNESS"})
    assert classify(naw)[0] == "not_a_weakness"
    # Wire reason stays the #150/#156 name; canonical code is NOT_A_WEAKNESS.
    assert poam_decision(naw)["reason"] == "not_a_weakness"
    assert poam_decision(naw)["reason_code"] == "NOT_A_WEAKNESS"

    fp = _finding(extra={"false_positive": True})
    assert poam_decision(fp)["reason"] == "FALSE_POSITIVE_CANDIDATE"

    manual = _finding(extra={"exclude_reason": "MANUAL_CHECK"})
    assert poam_decision(manual)["reason"] == "MANUAL_CHECK"

    info = _finding(severity="info", extra={"port": "80"})
    assert classify(info)[0] == "info"
    assert poam_decision(info)["reason"] == "severity_info"
    assert poam_decision(info)["reason_code"] == "INFO_ONLY"


def test_e1_telemetry_collapse_is_rollup_rule() -> None:
    alerts = [
        _finding(
            source="host-wazuh",
            ref_id=f"WAZ-{i}",
            name="sshd brute",
            severity="low",
            category="incident",
            assets=["web-01"],
            labels=["wazuh", "alert"],
            extra={"rule_id": "5710", "telemetry": True, "rule_level": 12},
        )
        for i in range(3)
    ]
    pairs = iter_poam_decisions(alerts, lighter=False)
    included = [d for _r, d in pairs if d.get("include")]
    excluded = [d for _r, d in pairs if not d.get("include")]
    assert len(included) == 1
    assert len(excluded) == 2
    assert {d["reason"] for d in excluded} == {"telemetry_duplicate"}
    assert {d["reason_code"] for d in excluded} == {"DUPLICATE_INSTANCE"}
    assert all(d.get("rolled_into_ref") == "WAZ-0" for d in excluded)


def test_build_rejects_e4_late_only() -> None:
    from shared.poam_rollup import build

    rec = _finding()
    with pytest.raises(ValueError, match="late-only"):
        build([(rec, poam_decision(rec))], profile="late-only", assets_n=1)


def test_escalate_budget_is_report_only_spec_t() -> None:
    assert budget_target(10) == 25
    assert budget_target(80) == 40
    assert budget_target(150) == 75
    assert budget_source_cap(10) == 10
    assert budget_source_cap(80) == 12
    assert budget_source_cap(150) == 23
    assert escalate_budget("full", 10) == 25
    assert escalate_budget("full", 80) == 40


def test_budget_does_not_remove_rows() -> None:
    from shared.poam_rollup import build

    rows = [_finding(ref_id=f"NMAP-{i}", extra={"port": str(22 + i), "check_id": f"p{i}"}) for i in range(30)]
    pairs = [(rec, poam_decision(rec)) for rec in rows]
    out = build(pairs, profile="full", assets_n=10)
    assert sum(1 for _r, d in out if d.get("include")) == 30
    assert all(d.get("budget_status") == "exceeded" for _r, d in out)


def test_dedupe_returns_merges() -> None:
    a = _finding(ref_id="NMAP-1", extra={"port": "22", "check_id": "ssh"})
    b = _finding(ref_id="NMAP-1-dup", extra={"port": "22", "check_id": "ssh"})
    # same identity + asset
    a["extra"]["id"] = "ssh-open"
    b["extra"]["id"] = "ssh-open"
    kept = _dedupe([a, b])
    merges = getattr(kept, "merges", [])
    assert len([r for r in kept if r.get("kind") == "finding"]) == 1
    assert len(merges) == 1
    assert merges[0]["reason_code"] == "DUPLICATE_INSTANCE"
    assert merges[0]["rolled_into"] == "NMAP-1"


def test_apply_rollups_leaves_fp_v1(tmp_path: Path) -> None:
    rec = _finding(ref_id="NMAP-keep", severity="high", extra={"port": "445", "service": "microsoft-ds"})
    catalog = KevCatalog(kev_evaluated=False, reason="snapshot_missing")
    ledger = apply_ledger([rec], catalog=catalog, run_at=datetime(2026, 9, 1, tzinfo=timezone.utc))
    fps = {fp: dict(item) for fp, item in ledger["items"].items()}
    pairs = iter_poam_decisions([rec], lighter=False, ledger=ledger)
    apply_rollups(ledger, pairs, included_ids={next(iter(fps.values()))["poam_id"]})
    assert set(ledger["items"]) == set(fps)
    for fp, item in ledger["items"].items():
        assert item["fp"] == fp == fps[fp]["fp"] == fp_v1(rec)
        assert item["poam_id"] == fps[fp]["poam_id"]
        assert item["include"] is True


def test_loader_g0_and_flood_guard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    recs = [
        _finding(
            ref_id="NMAP-22",
            name="SSH exposed",
            description="box has open TCP/22 (ssh).",
            extra={"port": "22", "service": "ssh"},
        ),
        _finding(
            ref_id="NMAP-info",
            name="Host discovered",
            severity="info",
            extra={"port": "80"},
        ),
        _finding(
            source="honeypot",
            ref_id="HPOT-1",
            name="Deception-sensor stage-1 hit",
            description="deception-sensor evidence / an agent-behavior signal.",
            severity="high",
            category="deception-sensor",
            extra={"honesty": "deception-sensor", "stage": 1},
        ),
        _finding(
            extra={"exclude_reason": "NOT_A_WEAKNESS", "check_id": "cost-policy"},
            ref_id="CLD-cost",
            source="cloud-prowler",
            name="Stop underutilized VM",
            severity="medium",
            category="cloud-misconfiguration",
        ),
    ]
    write_canonical("mixed", recs)
    summary = load()
    assert summary["flood_guard"]["UNEXPLAINED"] == 0
    assert_flood_guard(tmp_path, summary)
    excluded = tmp_path / "poam" / "excluded.csv"
    assert excluded.read_text(encoding="utf-8").splitlines()[0] == EXCLUDED_HEADER
    with excluded.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    by_ref = {row["finding_ref_id"]: row for row in rows}
    assert by_ref["NMAP-info"]["excluded_reason"] == "severity_info"
    assert by_ref["NMAP-info"]["reason_code"] == "INFO_ONLY"
    assert by_ref["HPOT-1"]["reason_code"] == "HONEYPOT"
    assert by_ref["HPOT-1"]["excluded_reason"] == "honeypot"
    assert by_ref["CLD-cost"]["reason_code"] == "NOT_A_WEAKNESS"
    assert (tmp_path / "poam" / "poam_members.csv").is_file()
    with (tmp_path / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        poam_ids = {r["poam_id"] for r in csv.DictReader(fh) if r.get("poam_id")}
    with (tmp_path / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        fed_ids = {r["POAM ID"] for r in csv.DictReader(fh) if r.get("POAM ID")}
    assert poam_ids == fed_ids
    assert "NMAP-22" in {r["finding_ref_id"] for r in csv_rows(tmp_path / "poam" / "poam.csv")}


def test_egp_stable_across_reruns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    recs = [
        _finding(
            ref_id="NMAP-445",
            name="SMB exposed",
            description="box has open TCP/445 (microsoft-ds).",
            severity="medium",
            extra={"port": "445", "service": "microsoft-ds", "scan_time": "2026-09-01T00:00:00Z"},
        )
    ]

    def _run(out: Path) -> set[str]:
        monkeypatch.setenv("OUT_DIR", str(out))
        monkeypatch.setenv("IN_DIR", str(out / "empty-in"))
        (out / "empty-in").mkdir(parents=True, exist_ok=True)
        write_canonical("inventory-nmap", recs)
        load()
        with (out / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
            return {r["poam_id"] for r in csv.DictReader(fh) if r.get("poam_id")}

    first = _run(tmp_path / "a")
    second = _run(tmp_path / "b")
    assert first == second
    assert all(pid.startswith("EGP-") for pid in first)


def test_g0_includes_poam_fallback_ids_not_in_ledger(tmp_path: Path) -> None:
    from shared.poam_fedramp import item_from_poam_row, write_fedramp_poam

    header = ["poam_id", "weakness", "asset", "weakness_description", "detector_source"]
    rows = [
        ["EGP-AAAAAAAAAA", "SMB", "box", "smb", "inventory-nmap"],
        ["POAM-orphan", "Jamf diskenc", "laptop", "diskenc", "host-wazuh"],
    ]
    items = [item_from_poam_row(row, header) for row in rows]
    dest = tmp_path / "poam"
    write_fedramp_poam(dest, {"items": {}, "closed": []}, open_items=items)
    with (dest / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        ids = [r["POAM ID"] for r in csv.DictReader(fh)]
    assert ids == ["EGP-AAAAAAAAAA", "POAM-orphan"]


def test_write_fedramp_respects_included_ids(tmp_path: Path) -> None:
    rec = _finding(ref_id="NMAP-keep", severity="high")
    other = _finding(ref_id="NMAP-drop", severity="info", extra={"port": "80"})
    catalog = KevCatalog(kev_evaluated=False, reason="snapshot_missing")
    ledger = apply_ledger(
        [rec, other],
        catalog=catalog,
        run_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )
    keep_id = next(
        item["poam_id"]
        for item in ledger["items"].values()
        if item.get("ref_id") == "NMAP-keep"
    )
    dest = tmp_path / "poam"
    write_fedramp_poam(dest, ledger, included_ids={keep_id})
    with (dest / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["POAM ID"] for r in rows] == [keep_id]


def test_flood_guard_summary_counts_unexplained() -> None:
    rec = _finding()
    pairs = [(rec, {"include": False, "reason": "", "reason_code": "UNEXPLAINED"})]
    fg = flood_guard_summary(pairs, profile="full", assets_n=1)
    assert fg["UNEXPLAINED"] == 1
    assert fg["excluded_by_code"]["UNEXPLAINED"] == 1
    assert set(fg) >= {
        "findings_in",
        "duplicates_merged",
        "poam_rows",
        "poam_members",
        "excluded",
        "excluded_by_code",
        "rollup_level_by_source",
        "budget",
        "profile",
        "lighter",
    }
    assert fg["budget"]["status"] in {"ok", "exceeded"}
    assert fg["e4_late_only"] is False


def test_c5_merges_land_in_excluded_and_reconcile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    a = _finding(ref_id="NMAP-keep", extra={"port": "22", "check_id": "ssh", "id": "ssh-open"})
    b = _finding(ref_id="NMAP-dup", extra={"port": "22", "check_id": "ssh", "id": "ssh-open"})
    write_canonical("inventory-nmap", [a, b])
    summary = load()
    fg = summary["flood_guard"]
    assert fg["duplicates_merged"] == 1
    assert fg["findings_in"] == fg["poam_members"] + fg["excluded"]
    assert summary["excluded_by_reason"].get("DUPLICATE_INSTANCE") == 1
    excluded = csv_rows(tmp_path / "poam" / "excluded.csv")
    assert any(row["finding_ref_id"] == "NMAP-dup" and row["reason_code"] == "DUPLICATE_INSTANCE" for row in excluded)
    members = csv_rows(tmp_path / "poam" / "poam_members.csv")
    assert any(row["finding_ref_id"] == "NMAP-keep" for row in members)
    assert all(row["finding_ref_id"] != "NMAP-dup" for row in members)
    assert_flood_guard(tmp_path, summary)


def test_accepted_risk_and_unverified_banner_codes() -> None:
    ao = _finding(extra={"exclude_reason": "ACCEPTED_RISK", "port": "22"})
    assert extra_exclude_token(ao) == "ACCEPTED_RISK"
    assert poam_decision(ao)["include"] is False
    assert poam_decision(ao)["reason_code"] == "ACCEPTED_RISK"

    banner = _finding(extra={"exclude_reason": "UNVERIFIED_BANNER_CVE", "port": "22"})
    assert poam_decision(banner)["reason_code"] == "UNVERIFIED_BANNER_CVE"
