"""Metis flood-guard: classify/build, named reasons, G0, stable EGP-."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from collectors.grc_loader import _dedupe, load
from collectors import code_secrets
from shared.ciso_shape import (
    EXCLUDED_HEADER,
    assert_count_consistency,
    assert_flood_guard,
    assert_register_no_double_treatment,
    csv_rows,
)
from shared.control_map import (
    POAM_EXCLUDE_REASONS,
    REASON_CODES,
    is_poam_exclude_reason,
    iter_poam_decisions,
    map_finding,
    poam_decision,
)
from shared.egp_collapse import is_merged_into_reason
from shared.io_util import write_canonical
from shared.kev import KevCatalog
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

    accepted = _finding(extra={"accepted_risk": True, "port": "22"})
    assert extra_exclude_token(accepted) == "ACCEPTED_RISK"
    assert classify(accepted)[0] == "accepted_risk"

    unverified = _finding(extra={"exclude_reason": "UNVERIFIED_BANNER_CVE", "port": "22"})
    assert extra_exclude_token(unverified) == "UNVERIFIED_BANNER_CVE"
    assert classify(unverified)[0] == "unverified_banner"

    honeypot = _finding(
        source="honeypot",
        extra={"honesty": "deception-sensor", "stage": 1, "port": "22"},
        category="deception-sensor",
    )
    assert classify(honeypot)[0] == "honeypot"

    muted_flag = _finding(extra={"muted": True, "port": "22"})
    assert extra_exclude_token(muted_flag) == "MUTED"
    assert classify(muted_flag)[0] == "muted"
    assert map_finding(muted_flag)["include_poam"] is False

    port_only = _finding(
        name="Open port 80/tcp",
        extra={"port": "80", "proto": "tcp", "service": ""},
    )
    assert classify(port_only)[0] == "port_only"

    high = _finding(
        source="cloud-prowler",
        severity="high",
        category="cloud-misconfiguration",
        extra={"check_id": "s3_public"},
    )
    pairs = iter_poam_decisions([high], lighter=False)
    assert pairs[0][1].get("include") is True
    assert pairs[0][1].get("reason") == "severity_high_critical"
    assert classify(high)[0] == "weakness"
    from shared.poam_rollup import build

    stamped = build(
        [(high, {"include": True, "reason": "", "severity": "high"})],
        profile="full",
        assets_n=1,
    )
    assert stamped[0][1]["reason"] == "escalate"
    assert stamped[0][1]["budget_status"] in {"ok", "exceeded"}


def _wazuh_e1_alerts(n: int = 3, host: str = "web-01.invalid") -> list[dict]:
    return [
        _finding(
            source="host-wazuh",
            ref_id=f"WAZ-{i}",
            name="sshd brute",
            severity="low",
            category="incident",
            assets=[host],
            labels=["wazuh", "alert"],
            extra={"rule_id": "5710", "telemetry": True, "rule_level": 12},
        )
        for i in range(n)
    ]


def test_e1_telemetry_collapse_is_rollup_rule() -> None:
    """Same-EGP E1 twins are #192 aliases (merged_into), not register accept."""
    alerts = _wazuh_e1_alerts()
    pairs = iter_poam_decisions(alerts, lighter=False)
    included = [d for _r, d in pairs if d.get("include")]
    excluded = [d for _r, d in pairs if not d.get("include")]
    assert len(included) == 1
    assert len(excluded) == 2
    assert all(is_merged_into_reason(str(d["reason"])) for d in excluded)
    assert {d["reason_code"] for d in excluded} == {"DUPLICATE_INSTANCE"}
    assert {d.get("flood_guard_origin") for d in excluded} == {"telemetry_duplicate"}
    assert all("E1 same rule+asset" in str(d.get("detail") or "") for d in excluded)


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


def test_flood_guard_summary_counts_unexplained() -> None:
    rec = _finding()
    pairs = [(rec, {"include": False, "reason": "", "reason_code": "UNEXPLAINED"})]
    fg = flood_guard_summary(pairs, profile="full", assets_n=1)
    assert fg["UNEXPLAINED"] == 1
    assert fg["excluded_by_code"]["UNEXPLAINED"] == 1
    assert set(fg) >= {
        "findings_in",
        "duplicates_merged",
        "c5_skipped",
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
    assert all(row.get("estate") for row in members)
    assert_flood_guard(tmp_path, summary)


def test_accepted_risk_and_unverified_banner_codes() -> None:
    ao = _finding(extra={"exclude_reason": "ACCEPTED_RISK", "port": "22"})
    assert extra_exclude_token(ao) == "ACCEPTED_RISK"
    assert poam_decision(ao)["include"] is False
    assert poam_decision(ao)["reason_code"] == "ACCEPTED_RISK"

    banner = _finding(extra={"exclude_reason": "UNVERIFIED_BANNER_CVE", "port": "22"})
    assert poam_decision(banner)["reason_code"] == "UNVERIFIED_BANNER_CVE"


def _asset(name: str, ref: str | None = None) -> dict:
    return make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id=ref or f"AST-{name}",
        name=name,
        description=name,
        severity="",
        category="host",
        assets=[name],
        extra={},
    )


def _load_recs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recs: list[dict]) -> dict:
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    write_canonical("mixed", recs)
    return load()


def test_e1_same_egp_twins_one_scenario_no_double_treatment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = "web-01.invalid"
    recs = [_asset(host)] + _wazuh_e1_alerts(3, host)
    summary = _load_recs(tmp_path, monkeypatch, recs)
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    assert len(scenarios) == 1
    assert scenarios[0]["treatment"] == "mitigate"
    excluded = csv_rows(tmp_path / "poam" / "excluded.csv")
    twins = [row for row in excluded if is_merged_into_reason(row.get("excluded_reason") or "")]
    assert len(twins) == 2
    assert {row["reason_code"] for row in twins} == {"DUPLICATE_INSTANCE"}
    assert all("E1 same rule+asset" in (row.get("detail") or "") for row in twins)
    overlap = assert_register_no_double_treatment(tmp_path)
    assert overlap["ok"] is True
    assert not overlap["title_host_overlap"]
    assert summary["flood_guard"]["findings_in"] == (
        summary["flood_guard"]["poam_members"] + summary["flood_guard"]["excluded"]
    )


def test_port_fold_same_egp_twins_one_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = "10.0.0.5"
    port = _finding(
        ref_id="NMAP-445-bare",
        name="Open port 445/tcp",
        description="Open port 445/tcp",
        severity="medium",
        category="exposure",
        assets=[host],
        extra={"port": "445", "proto": "tcp", "service": ""},
    )
    twin = _finding(
        ref_id="NMAP-445-keep",
        name="Open port 445/tcp",
        description="Open port 445/tcp",
        severity="medium",
        category="exposure",
        assets=[host],
        extra={"port": "445", "proto": "tcp", "service": "microsoft-ds", "check_id": "nmap-port-445"},
    )
    pairs = iter_poam_decisions([port, twin], lighter=False)
    by_ref = {r["ref_id"]: d for r, d in pairs}
    kept = [d for d in by_ref.values() if d.get("include")]
    dropped = [d for d in by_ref.values() if not d.get("include")]
    assert len(kept) == 1
    assert len(dropped) == 1
    assert is_merged_into_reason(str(dropped[0]["reason"]))
    assert dropped[0]["reason_code"] == "DUPLICATE_INSTANCE"
    # leftover include codes (key_medium on 445) must not become origin
    assert dropped[0].get("flood_guard_origin") not in {
        "key_medium",
        "severity_medium",
        "severity_high_critical",
    }
    summary = _load_recs(tmp_path, monkeypatch, [_asset(host)] + [port, twin])
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    assert len(scenarios) == 1
    overlap = assert_register_no_double_treatment(tmp_path)
    assert overlap["ok"] is True
    assert not overlap["title_host_overlap"]
    assert summary["flood_guard"]["UNEXPLAINED"] == 0


def test_trivy_same_ref_two_targets_counts_findings_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {
        "Results": [
            {
                "Target": "svc_a/requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-3651",
                        "Title": "idna mishandles domain labels",
                        "Severity": "HIGH",
                        "PkgName": "idna",
                        "Description": "idna",
                    }
                ],
            },
            {
                "Target": "svc-a/requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-3651",
                        "Title": "idna mishandles domain labels",
                        "Severity": "HIGH",
                        "PkgName": "idna",
                        "Description": "idna",
                    }
                ],
            },
        ]
    }
    dest = tmp_path / "trivy.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    parsed = code_secrets.parse_file(dest)
    findings = [r for r in parsed if r.get("kind") == "finding"]
    refs = {r["ref_id"] for r in findings}
    assert len(findings) == 2
    assert len(refs) == 1
    assets = [_asset(str((r.get("assets") or ["t"])[0])) for r in findings]
    summary = _load_recs(tmp_path, monkeypatch, assets + findings)
    fg = summary["flood_guard"]
    assert fg["findings_in"] == fg["poam_members"] + fg["excluded"]
    assert fg["poam_members"] == 2
    assert fg["findings_in"] == 2
    assert_flood_guard(tmp_path, summary)


def test_c5_skip_when_ref_already_on_register(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    y = _finding(
        ref_id="NMAP-Y",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    x_same = _finding(
        ref_id="NMAP-X",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    x_other = _finding(
        ref_id="NMAP-X",
        assets=["10.0.0.6"],
        extra={"port": "445", "check_id": "smb", "id": "smb-open"},
    )
    summary = _load_recs(
        tmp_path,
        monkeypatch,
        [_asset("10.0.0.5"), _asset("10.0.0.6"), y, x_same, x_other],
    )
    poam = csv_rows(tmp_path / "poam" / "poam.csv")
    excluded = csv_rows(tmp_path / "poam" / "excluded.csv")
    poam_refs = {row.get("finding_ref_id") for row in poam}
    ex_refs = {row.get("finding_ref_id") for row in excluded}
    assert "NMAP-X" in poam_refs
    assert "NMAP-X" not in ex_refs
    assert summary["flood_guard"]["c5_skipped"] >= 1
    assert summary["flood_guard"]["findings_in"] == (
        summary["flood_guard"]["poam_members"] + summary["flood_guard"]["excluded"]
    )
    assert_flood_guard(tmp_path, summary)


def test_c5_skip_when_ref_already_on_excluded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ref already listed as info must not also land as a C5 extra."""
    y = _finding(
        ref_id="NMAP-Y",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    x_dup = _finding(
        ref_id="NMAP-X",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    x_info = _finding(
        ref_id="NMAP-X",
        name="Host discovered",
        severity="info",
        assets=["10.0.0.9"],
        extra={"port": "80"},
    )
    summary = _load_recs(
        tmp_path,
        monkeypatch,
        [_asset("10.0.0.5"), _asset("10.0.0.9"), y, x_dup, x_info],
    )
    poam = csv_rows(tmp_path / "poam" / "poam.csv")
    excluded = csv_rows(tmp_path / "poam" / "excluded.csv")
    poam_refs = {row.get("finding_ref_id") for row in poam}
    x_ex = [row for row in excluded if row.get("finding_ref_id") == "NMAP-X"]
    assert "NMAP-X" not in poam_refs
    assert len(x_ex) == 1
    assert x_ex[0]["excluded_reason"] == "severity_info"
    assert summary["flood_guard"]["findings_in"] == (
        summary["flood_guard"]["poam_members"] + summary["flood_guard"]["excluded"]
    )
    assert_flood_guard(tmp_path, summary)


def test_merged_into_reason_code_is_duplicate_instance() -> None:
    rows = _wazuh_e1_alerts()
    pairs = iter_poam_decisions(rows, lighter=False)
    dropped = [d for _r, d in pairs if not d.get("include")]
    assert dropped
    assert all(is_merged_into_reason(str(d["reason"])) for d in dropped)
    assert {d["reason_code"] for d in dropped} == {"DUPLICATE_INSTANCE"}
    assert reason_code_of(dropped[0]["reason"]) == "DUPLICATE_INSTANCE"


def test_map_finding_exclude_class_forces_include_poam_false() -> None:
    muted = _finding(extra={"exclude_reason": "MUTED"})
    assert classify(muted)[0] == "muted"
    assert map_finding(muted)["include_poam"] is False
    fp = _finding(extra={"false_positive": True})
    assert map_finding(fp)["include_poam"] is False
    accepted = _finding(extra={"exclude_reason": "ACCEPTED_RISK"})
    assert map_finding(accepted)["include_poam"] is False


def test_prowler_muted_kind_excluded_is_register_accept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = _finding(
        source="cloud-prowler",
        ref_id="CLD-live",
        name="S3 public",
        severity="high",
        category="cloud-misconfiguration",
        extra={"check_id": "s3_public"},
    )
    muted = {
        "kind": "excluded",
        "source": "cloud-prowler",
        "ref_id": "CLD-muted-1",
        "name": "Muted check",
        "description": "muted",
        "severity": "medium",
        "category": "excluded",
        "assets": ["acct"],
        "labels": ["muted"],
        "extra": {"exclude_reason": "MUTED", "check_id": "muted-check", "status": "MUTED"},
    }
    summary = _load_recs(tmp_path, monkeypatch, [_asset("acct"), live, muted])
    excluded = csv_rows(tmp_path / "poam" / "excluded.csv")
    muted_rows = [row for row in excluded if row.get("finding_ref_id") == "CLD-muted-1"]
    assert muted_rows
    assert muted_rows[0]["excluded_reason"] == "MUTED"
    assert muted_rows[0]["reason_code"] == "MUTED"
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    by_name = {row.get("name"): row.get("treatment") for row in scenarios}
    assert by_name.get("S3 public") == "mitigate"
    assert by_name.get("Muted check") == "accept"
    muted_scenario = next(row for row in scenarios if row.get("name") == "Muted check")
    assert "muted in Prowler" in (muted_scenario.get("threats") or "")
    assert "muted in Prowler" in (muted_scenario.get("description") or "")
    assert summary["kind_excluded"] == 1
    assert summary["flood_guard"]["excluded_by_code"].get("MUTED") == 1


def test_muted_label_is_source_specific(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = _finding(
        source="host-wazuh",
        ref_id="WAZ-live",
        name="sshd brute",
        severity="high",
        extra={"rule_id": "5710", "rule_level": 12},
    )
    muted = {
        "kind": "excluded",
        "source": "host-wazuh",
        "ref_id": "WAZ-muted-1",
        "name": "Muted Wazuh check",
        "description": "muted",
        "severity": "critical",
        "category": "excluded",
        "assets": ["web-01"],
        "labels": ["muted"],
        "extra": {"exclude_reason": "MUTED", "status": "MUTED"},
    }
    _load_recs(tmp_path, monkeypatch, [_asset("web-01"), live, muted])
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    muted_scenario = next(row for row in scenarios if row.get("name") == "Muted Wazuh check")
    assert muted_scenario.get("treatment") == "accept"
    threats = muted_scenario.get("threats") or ""
    desc = muted_scenario.get("description") or ""
    assert "muted (operator mutelist)" in threats
    assert "muted (operator mutelist)" in desc
    assert "Prowler" not in threats
    assert "Prowler" not in desc


def _no_formula_cells(rows: list[dict]) -> None:
    from shared.io_util import is_csv_formula

    for row in rows:
        for value in row.values():
            assert not is_csv_formula(value), value


_SIGNED_DIGIT_FORMULAS = (
    "-2+3+cmd|' /C calc'!A0",
    "+1+1",
    "-1+1",
    "+1-cmd|' /C calc'!A0",
)
_SIGNED_SAFE = (
    "-",
    "-1",
    "-1.5",
    "+44 20 7946 0958",
    "+1 (555) 010-0000",
)


def test_is_csv_formula_narrow_prefixes() -> None:
    from shared.io_util import is_csv_formula, neutralize_csv_formula

    hostile = "=cmd|' /C calc'!A0"
    assert is_csv_formula(hostile)
    assert is_csv_formula("@SUM(1,1)")
    assert is_csv_formula("+cmd")
    assert is_csv_formula("-cmd|")
    assert is_csv_formula("\t=cmd")
    assert is_csv_formula("\r@SUM(A1)")
    for payload in _SIGNED_DIGIT_FORMULAS:
        assert is_csv_formula(payload), payload
        assert neutralize_csv_formula(payload) == "'" + payload
    assert not is_csv_formula("-")
    assert not is_csv_formula("-1")
    assert not is_csv_formula("-1.5")
    assert not is_csv_formula("+44 7700 900123")
    assert not is_csv_formula("+44 20 7946 0958")
    assert not is_csv_formula("+1 (555) 010-0000")
    assert not is_csv_formula("box")
    for safe in _SIGNED_SAFE:
        assert not is_csv_formula(safe), safe
        assert neutralize_csv_formula(safe) == safe
    assert neutralize_csv_formula(hostile) == "'" + hostile
    assert neutralize_csv_formula("-1") == "-1"
    assert neutralize_csv_formula("+44") == "+44"


def test_csv_formula_asset_is_neutralized_in_risk_scenarios(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the scenario; prefix the formula cell. Do not drop the row."""
    from shared.io_util import is_csv_formula

    hostile = "=cmd|' /C calc'!A0"
    assert is_csv_formula(hostile)
    live = _finding(
        ref_id="NMAP-ok",
        name="SSH exposed",
        assets=["box"],
        extra={"port": "22", "service": "ssh"},
    )
    formula = _finding(
        ref_id="NMAP-formula",
        name="Formula host",
        assets=[hostile],
        extra={"port": "22", "service": "ssh"},
    )
    summary = _load_recs(tmp_path, monkeypatch, [_asset("box"), live, formula])
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    formula_row = next(row for row in scenarios if row.get("name") == "Formula host")
    assert any(row.get("name") == "SSH exposed" for row in scenarios)
    assets = formula_row.get("assets") or ""
    assert assets.startswith("'")
    assert assets.endswith(hostile)
    assert not is_csv_formula(assets)
    _no_formula_cells(scenarios)
    assert_count_consistency(tmp_path, summary)
    for rel in ("poam/poam.csv", "poam/excluded.csv", "poam/poam_members.csv"):
        path = tmp_path / rel
        if path.is_file():
            _no_formula_cells(csv_rows(path))


def test_csv_formula_asset_on_muted_row_keeps_reconcile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Muted fixture: 1 live + 2 muted, formula on muted-2. Keep all 3 scenarios."""
    hostile = "=cmd|' /C calc'!A0"
    live = _finding(
        source="cloud-prowler",
        ref_id="CLD-live",
        name="S3 public",
        severity="high",
        category="cloud-misconfiguration",
        extra={"check_id": "s3_public"},
    )
    muted_ok = {
        "kind": "excluded",
        "source": "cloud-prowler",
        "ref_id": "CLD-muted-1",
        "name": "Muted check one",
        "description": "muted",
        "severity": "critical",
        "category": "excluded",
        "assets": ["acct"],
        "labels": ["muted"],
        "extra": {"exclude_reason": "MUTED", "check_id": "muted-1", "status": "MUTED"},
    }
    muted_formula = {
        "kind": "excluded",
        "source": "cloud-prowler",
        "ref_id": "CLD-muted-2",
        "name": "Muted check two",
        "description": "muted",
        "severity": "critical",
        "category": "excluded",
        "assets": [hostile],
        "labels": ["muted"],
        "extra": {"exclude_reason": "MUTED", "check_id": "muted-2", "status": "MUTED"},
    }
    summary = _load_recs(
        tmp_path, monkeypatch, [_asset("acct"), live, muted_ok, muted_formula]
    )
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    names = {row.get("name") for row in scenarios}
    assert names >= {"S3 public", "Muted check one", "Muted check two"}
    assert len(scenarios) == 3
    hostile_row = next(row for row in scenarios if row.get("name") == "Muted check two")
    assets = hostile_row.get("assets") or ""
    assert assets.startswith("'")
    assert assets.endswith(hostile)
    from shared.io_util import is_csv_formula

    assert not is_csv_formula(assets)
    _no_formula_cells(scenarios)
    assert_count_consistency(tmp_path, summary)
    exec_text = (tmp_path / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    assert "counts not reconciled." not in exec_text


def test_csv_formula_signed_digit_payloads_are_neutralized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Signed-digit DDE / +1+1 cells get a quote prefix on every export CSV."""
    from shared.io_util import is_csv_formula

    recs: list[dict] = [_asset("box")]
    for i, payload in enumerate(_SIGNED_DIGIT_FORMULAS):
        recs.append(
            _finding(
                ref_id=f"NMAP-signed-{i}",
                name=f"Signed formula {i}",
                assets=[payload],
                extra={"port": str(22 + i), "service": "ssh"},
            )
        )
    summary = _load_recs(tmp_path, monkeypatch, recs)
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    for i, payload in enumerate(_SIGNED_DIGIT_FORMULAS):
        row = next(r for r in scenarios if r.get("name") == f"Signed formula {i}")
        assets = row.get("assets") or ""
        assert assets == "'" + payload
        assert not is_csv_formula(assets)
    _no_formula_cells(scenarios)
    assert_count_consistency(tmp_path, summary)
    for rel in (
        "poam/poam.csv",
        "poam/excluded.csv",
        "poam/poam_members.csv",
        "simplerisk/poam.csv",
        "poam/poam_fedramp.csv",
    ):
        path = tmp_path / rel
        assert path.is_file(), rel
        _no_formula_cells(csv_rows(path))


def test_csv_formula_multi_asset_neutralizes_per_asset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One formula among several assets: only that asset is quote-prefixed."""
    from shared.io_util import is_csv_formula

    hostile = "-2+3+cmd|' /C calc'!A0"
    recs = [
        _asset("box"),
        _asset("other"),
        _finding(
            ref_id="NMAP-multi",
            name="Multi asset formula",
            assets=["box", hostile, "other"],
            extra={"port": "22", "service": "ssh"},
        ),
    ]
    summary = _load_recs(tmp_path, monkeypatch, recs)
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    row = next(r for r in scenarios if r.get("name") == "Multi asset formula")
    assets = row.get("assets") or ""
    # Payload itself contains `|`; compare the joined cell, not a split.
    assert assets == "box|" + "'" + hostile + "|other"
    assert assets.startswith("box|")
    assert assets.endswith("|other")
    assert "'" + hostile in assets
    assert not assets.startswith("'")
    assert not is_csv_formula(assets)
    _no_formula_cells(scenarios)
    assert_count_consistency(tmp_path, summary)


def test_c5_slot_dup_skip_is_reached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two same-ref+asset C5 candidates: first writes, second increments c5_skipped."""
    y = _finding(
        ref_id="NMAP-Y",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    x1 = _finding(
        ref_id="NMAP-X",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    x2 = _finding(
        ref_id="NMAP-X",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    summary = _load_recs(
        tmp_path, monkeypatch, [_asset("10.0.0.5"), y, x1, x2]
    )
    poam_refs = {
        row.get("finding_ref_id") for row in csv_rows(tmp_path / "poam" / "poam.csv")
    }
    c5 = [
        row
        for row in csv_rows(tmp_path / "poam" / "excluded.csv")
        if row.get("finding_ref_id") == "NMAP-X"
        and row.get("excluded_reason") == "DUPLICATE_INSTANCE"
    ]
    assert "NMAP-Y" in poam_refs
    assert "NMAP-X" not in poam_refs
    assert len(c5) == 1
    assert summary["flood_guard"]["c5_skipped"] == 1
    assert_flood_guard(tmp_path, summary)


def test_is_poam_exclude_reason_covers_rollup_codes() -> None:
    assert is_poam_exclude_reason("ACCEPTED_RISK")
    assert is_poam_exclude_reason("LIGHTER_LOW")
    assert is_poam_exclude_reason("MUTED")
    assert is_poam_exclude_reason("merged_into:EGP-70CD0ED0D4")
    # rollup-only token (not in POAM_EXCLUDE_REASONS) still counts
    assert is_poam_exclude_reason("escalate")
    assert "ACCEPTED_RISK" in REASON_CODES


def test_kind_excluded_counts_in_findings_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = {
        "kind": "excluded",
        "source": "cloud-prowler",
        "ref_id": "CLD-cost",
        "name": "Stop underutilized VM",
        "description": "cost",
        "severity": "medium",
        "category": "excluded",
        "assets": ["acct"],
        "labels": [],
        "extra": {"exclude_reason": "not_a_weakness", "check_id": "cost-policy"},
    }
    live = _finding(
        source="cloud-prowler",
        ref_id="CLD-live",
        name="S3 public",
        severity="high",
        extra={"check_id": "s3_public"},
    )
    summary = _load_recs(tmp_path, monkeypatch, [_asset("acct"), live, rec])
    fg = summary["flood_guard"]
    assert fg["findings_in"] == fg["poam_members"] + fg["excluded"]
    assert fg["excluded"] >= 1
    assert summary["kind_excluded"] == 1


def test_apply_rollups_persisted_fields_and_include(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = _finding(
        ref_id="NMAP-keep",
        severity="high",
        extra={"port": "445", "service": "microsoft-ds"},
    )
    info = _finding(
        ref_id="NMAP-info",
        name="Host discovered",
        severity="info",
        extra={"port": "80"},
    )
    summary = _load_recs(tmp_path, monkeypatch, [_asset("box"), rec, info])
    ledger = json.loads((tmp_path / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    items = list((ledger.get("items") or {}).values())
    assert items
    for item in items:
        assert "include" in item
        assert "poam_decision" in item
        assert "reason_code" in item
        assert "klass" in item
        assert "rollup_key" in item
        assert "band" in item
        assert "rolled_into" in item
    by_ref = {str(item.get("ref_id")): item for item in items}
    assert by_ref["NMAP-keep"]["include"] is True
    assert by_ref["NMAP-info"]["include"] is False
    assert by_ref["NMAP-info"]["reason_code"] == "INFO_ONLY"
    assert summary["flood_guard"]["UNEXPLAINED"] == 0


def test_assert_flood_guard_rejects_mismatched_findings_in(tmp_path: Path) -> None:
    (tmp_path / "poam").mkdir(parents=True, exist_ok=True)
    (tmp_path / "poam" / "excluded.csv").write_text(
        "id,finding_ref_id,weakness,asset,severity,excluded_reason,superseded_by,"
        "reason_code,rolled_into,source,detail\n",
        encoding="utf-8",
    )
    (tmp_path / "poam" / "poam_members.csv").write_text(
        "poam_id,finding_ref_id,egp_id,asset,severity,estate\n"
        "EGP-1,NMAP-1,EGP-1,box,low,DEMO: NOT A CLIENT\n",
        encoding="utf-8",
    )
    from shared.ciso_shape import RegisterShapeError

    with pytest.raises(RegisterShapeError, match="findings_in"):
        assert_flood_guard(
            tmp_path,
            {
                "flood_guard": {
                    "findings_in": 9,
                    "poam_members": 1,
                    "excluded": 0,
                    "UNEXPLAINED": 0,
                    "budget": {"status": "ok"},
                }
            },
        )
    assert_flood_guard(
        tmp_path,
        {
            "flood_guard": {
                "findings_in": 1,
                "poam_members": 1,
                "excluded": 0,
                "UNEXPLAINED": 0,
                "budget": {"status": "ok"},
            }
        },
    )


def test_c5_excluded_by_code_counts_duplicate_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = _finding(ref_id="NMAP-keep", extra={"port": "22", "check_id": "ssh", "id": "ssh-open"})
    b = _finding(ref_id="NMAP-dup", extra={"port": "22", "check_id": "ssh", "id": "ssh-open"})
    summary = _load_recs(tmp_path, monkeypatch, [_asset("box"), a, b])
    assert summary["flood_guard"]["excluded_by_code"].get("DUPLICATE_INSTANCE") == 1
    assert summary["flood_guard"]["duplicates_merged"] == 1


def test_port_fold_smbv1_specific_kills_accept_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bare 445/tcp and SMBv1-style specific share one EGP so the fold
    becomes ``merged_into``. Re-adding a port-fold override that leaves
    the folded row on the register as accept fails REGISTER_TREATMENT_FAIL
    (same EGP in mitigate and accept).
    """
    from shared.poam_ledger import fp_v1
    from shared.port_fold import SUPERSEDED_REASON, egp_id_for, is_specific_port_finding

    host = "filesrv.corp.local"
    port = _finding(
        ref_id="NMAP-445-bare",
        name="Open port 445/tcp",
        description="Open port 445/tcp",
        severity="medium",
        category="exposure",
        assets=[host],
        extra={"port": "445", "proto": "tcp", "service": ""},
    )
    smbv1 = _finding(
        source="inventory-nmap",
        ref_id="NMAP-smbv1",
        name="SMB version 1 dialect",
        description="SMBv1 dialect confirmed on 445/tcp",
        severity="high",
        category="exposure",
        assets=[host],
        labels=["nuclei", "nmap"],
        extra={
            "port": "445",
            "proto": "tcp",
            "claim": "open_port_observed",
            "tool": "nuclei",
        },
    )
    assert is_specific_port_finding(smbv1)
    assert fp_v1(port) == fp_v1(smbv1)
    assert egp_id_for(port) == egp_id_for(smbv1)
    pairs = iter_poam_decisions([port, smbv1], lighter=False)
    by_ref = {r["ref_id"]: d for r, d in pairs}
    assert by_ref["NMAP-smbv1"].get("include") is True
    folded = by_ref["NMAP-445-bare"]
    assert folded.get("include") is False
    reason = str(folded.get("reason") or "")
    assert is_merged_into_reason(reason)
    parent = reason.split(":", 1)[-1]
    assert parent == egp_id_for(smbv1)
    assert parent in str(folded.get("detail") or "")
    assert folded.get("flood_guard_origin") == SUPERSEDED_REASON
    assert folded.get("flood_guard_origin") not in {
        "key_medium",
        "severity_medium",
        "severity_high_critical",
    }
    summary = _load_recs(tmp_path, monkeypatch, [_asset(host), port, smbv1])
    scenarios = csv_rows(tmp_path / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    smbv1_rows = [row for row in scenarios if row.get("name") == "SMB version 1 dialect"]
    assert len(smbv1_rows) == 1
    assert smbv1_rows[0]["treatment"] == "mitigate"
    assert not any(row.get("name") == "Open port 445/tcp" for row in scenarios)
    overlap = assert_register_no_double_treatment(tmp_path)
    assert overlap["ok"] is True
    assert not overlap["title_host_overlap"]
    assert not overlap["egp_overlap"]
    assert summary["flood_guard"]["UNEXPLAINED"] == 0


def test_c5_double_drop_same_ref_two_assets_writes_two_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """X@.5→Y and X@.6→W must both land as C5 extras. Keying skip by
    ref alone (claimed_refs.add) silently drops the second row.
    """
    y = _finding(
        ref_id="NMAP-Y",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    w = _finding(
        ref_id="NMAP-W",
        assets=["10.0.0.6"],
        extra={"port": "445", "check_id": "smb", "id": "smb-open"},
    )
    x_a = _finding(
        ref_id="NMAP-X",
        assets=["10.0.0.5"],
        extra={"port": "22", "check_id": "ssh", "id": "ssh-open"},
    )
    x_b = _finding(
        ref_id="NMAP-X",
        assets=["10.0.0.6"],
        extra={"port": "445", "check_id": "smb", "id": "smb-open"},
    )
    summary = _load_recs(
        tmp_path,
        monkeypatch,
        [_asset("10.0.0.5"), _asset("10.0.0.6"), y, w, x_a, x_b],
    )
    excluded = csv_rows(tmp_path / "poam" / "excluded.csv")
    c5 = [
        row
        for row in excluded
        if row.get("finding_ref_id") == "NMAP-X"
        and row.get("excluded_reason") == "DUPLICATE_INSTANCE"
    ]
    assert len(c5) == 2
    assets = {row.get("asset") for row in c5}
    assert assets == {"10.0.0.5", "10.0.0.6"}
    poam_refs = {row.get("finding_ref_id") for row in csv_rows(tmp_path / "poam" / "poam.csv")}
    assert "NMAP-X" not in poam_refs
    assert summary["flood_guard"]["excluded_by_code"].get("DUPLICATE_INSTANCE") == 2
    assert_flood_guard(tmp_path, summary)


def test_assert_flood_guard_rejects_dropped_excluded_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """n12: dropping one excluded.csv row must fail the flood-guard guard."""
    from shared.ciso_shape import RegisterShapeError

    info = _finding(
        ref_id="NMAP-info",
        name="Host discovered",
        severity="info",
        extra={"port": "80"},
    )
    live = _finding(
        ref_id="NMAP-keep",
        severity="high",
        extra={"port": "445", "service": "microsoft-ds"},
    )
    naw = _finding(
        extra={"exclude_reason": "NOT_A_WEAKNESS", "check_id": "cost-policy"},
        ref_id="CLD-cost",
        source="cloud-prowler",
        name="Stop underutilized VM",
        severity="medium",
        category="cloud-misconfiguration",
    )
    summary = _load_recs(tmp_path, monkeypatch, [_asset("box"), live, info, naw])
    path = tmp_path / "poam" / "excluded.csv"
    rows = csv_rows(path)
    assert len(rows) >= 2
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows[:-1])
    with pytest.raises(RegisterShapeError, match="excluded"):
        assert_flood_guard(tmp_path, summary)


def test_manifest_rows_lists_poam_members() -> None:
    """n13: dropping poam_members.csv from the regen MANIFEST_ROWS list must fail."""
    from scripts.refresh_product_lab_drop_sinks import MANIFEST_ROWS

    assert ("poam/poam_members.csv", "poam/poam_members.csv") in MANIFEST_ROWS


def test_export_csv_rel_lists_poam_members() -> None:
    """n14: dropping poam_members.csv from EXPORT_CSV_REL must fail."""
    from shared.estate_pages import EXPORT_CSV_REL

    assert "poam/poam_members.csv" in EXPORT_CSV_REL
