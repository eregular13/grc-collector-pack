"""Metis POA&M Gap 2 — FedRAMP R3.0 Open O/P/Q Vendor Dependency."""

from __future__ import annotations

import csv
import importlib
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from shared.kev import KevCatalog, KevEntry, join_kev
from shared.poam_fedramp import item_to_row, write_fedramp_poam
from shared.poam_ledger import apply_ledger, fp_v1
from shared.vendor_dependency import (
    CHECKIN_OVERDUE_AFTER_DAYS,
    KEV_NOT_SUSPENDED_COMMENT,
    SUGGEST_COMMENT,
    VD_INVALID_OVERRIDE,
    VD_MISSING_PRODUCT,
    VD_NO,
    VD_NOTE,
    VD_NOT_CLOSED,
    VD_YES,
    VENDOR_CHECKIN_OVERDUE,
    canon_yes_no,
    format_vendor_product,
    scanner_suggests_no_fix,
)


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _run(when: str) -> datetime:
    return datetime.fromisoformat(when.replace("Z", "+00:00"))


def _rec(**kw) -> dict:
    extra = kw.pop("extra", {"id": "plugin-1", "tool": "nessus", "port": "443", "protocol": "tcp"})
    base = {
        "kind": "finding",
        "source": kw.pop("source", "vuln-scan"),
        "ref_id": kw.pop("ref_id", "VULN-1"),
        "name": kw.pop("name", "OpenSSL heartbeat"),
        "description": kw.pop("description", "fixture"),
        "severity": kw.pop("severity", "high"),
        "category": "vulnerability",
        "assets": kw.pop("assets", ["10.0.0.5"]),
        "labels": kw.pop("labels", ["vuln", "nessus"]),
        "collected_at": kw.pop("collected_at", "2026-09-01T00:00:00Z"),
        "extra": extra,
    }
    base.update(kw)
    return base


def _apply(findings, ledger=None, when="2026-09-10T00:00:00Z", overrides=None, catalog=None):
    return apply_ledger(
        findings,
        catalog=catalog or _unevaluated(),
        run_at=_run(when),
        ledger_in=ledger,
        overrides=overrides or {},
        prior_existed=True,
    )


def test_default_o_is_no_with_vd_source_default() -> None:
    rec = _rec()
    ledger = _apply([rec])
    item = next(iter(ledger["items"].values()))
    assert item["vendor_dependency"] == VD_NO
    assert item["vd_source"] == "default"
    assert item["last_vendor_checkin"] == ""
    assert item["vendor_product"] == ""
    row = item_to_row(item)
    assert row[13] == VD_NO
    assert row[14] == ""
    assert row[15] == ""


def test_never_invent_yes() -> None:
    rec = _rec(name="Microsoft Exchange unpatched", extra={"id": "ms-exch", "tool": "nessus", "vendor": "Microsoft"})
    item = next(iter(_apply([rec])["items"].values()))
    assert item["vendor_dependency"] == VD_NO
    assert item["vd_source"] == "default"


def test_scanner_no_fix_is_suggestion_only() -> None:
    rec = _rec(extra={"id": "plugin-1", "tool": "nessus", "no_fix_available": True})
    assert scanner_suggests_no_fix(rec)
    item = next(iter(_apply([rec])["items"].values()))
    assert item["vendor_dependency"] == VD_NO
    assert item["vd_source"] == "suggested"
    assert SUGGEST_COMMENT in item["vd_comments"]
    assert item["vendor_product"] == ""


def test_override_yes_requires_product_and_formats_en_dash() -> None:
    rec = _rec()
    first = _apply([rec])
    pid = next(iter(first["items"].values()))["poam_id"]
    second = _apply(
        [rec],
        ledger=first,
        overrides={
            pid: {
                "poam_id": pid,
                "vendor_dependency": "yes",
                "last_vendor_checkin": "2026-09-08",
                "vendor_product": "Microsoft - Exchange Server",
            }
        },
    )
    item = next(iter(second["items"].values()))
    assert item["vendor_dependency"] == VD_YES
    assert item["vd_source"] == "operator"
    assert item["last_vendor_checkin"] == "2026-09-08"
    assert item["vendor_product"] == "Microsoft – Exchange Server"
    row = item_to_row(item)
    assert row[13] == VD_YES
    assert row[14] == "2026-09-08"
    assert row[15] == "Microsoft – Exchange Server"


def test_override_yes_persists_across_later_runs_without_file() -> None:
    rec = _rec()
    run1 = _apply([rec], when="2026-09-10T00:00:00Z")
    pid = next(iter(run1["items"].values()))["poam_id"]
    run2 = _apply(
        [rec],
        ledger=run1,
        when="2026-09-11T00:00:00Z",
        overrides={
            pid: {
                "vendor_dependency": "Yes",
                "last_vendor_checkin": "2026-09-10",
                "vendor_product": "Vendor XYZ – Product",
            }
        },
    )
    run3 = _apply([rec], ledger=run2, when="2026-09-12T00:00:00Z", overrides={})
    item = next(iter(run3["items"].values()))
    assert item["vendor_dependency"] == VD_YES
    assert item["vd_source"] == "operator"
    assert item["vendor_product"] == "Vendor XYZ – Product"
    assert item["last_vendor_checkin"] == "2026-09-10"


def test_override_no_persists_across_later_runs_without_file() -> None:
    """Operator No must persist like Yes: run 3 without overrides.csv keeps operator."""
    rec = _rec()
    run1 = _apply([rec], when="2026-09-10T00:00:00Z")
    item1 = next(iter(run1["items"].values()))
    pid = item1["poam_id"]
    assert item1["vendor_dependency"] == VD_NO
    assert item1["vd_source"] == "default"
    run2 = _apply(
        [rec],
        ledger=run1,
        when="2026-09-11T00:00:00Z",
        overrides={pid: {"vendor_dependency": "No"}},
    )
    item2 = next(iter(run2["items"].values()))
    assert item2["vendor_dependency"] == VD_NO
    assert item2["vd_source"] == "operator"
    run3 = _apply([rec], ledger=run2, when="2026-09-12T00:00:00Z", overrides={})
    item3 = next(iter(run3["items"].values()))
    assert item3["vendor_dependency"] == VD_NO
    assert item3["vd_source"] == "operator"
    assert item3["last_vendor_checkin"] == ""
    assert item3["vendor_product"] == ""


def test_vendor_field_change_updates_status_date_and_writes_event() -> None:
    """Spec §3.4 step 3: any O/P/Q (or vd_source) change sets status_date + field_changed."""
    rec = _rec()
    run1 = _apply([rec], when="2026-09-10T00:00:00Z")
    item1 = next(iter(run1["items"].values()))
    pid = item1["poam_id"]
    fp = item1["fp"]
    assert item1["status_date"] == "2026-09-10"
    assert item1["vd_source"] == "default"

    run2 = _apply(
        [rec],
        ledger=run1,
        when="2026-09-11T00:00:00Z",
        overrides={pid: {"vendor_dependency": "No"}},
    )
    item2 = next(iter(run2["items"].values()))
    assert item2["vendor_dependency"] == VD_NO
    assert item2["vd_source"] == "operator"
    assert item2["status_date"] == "2026-09-11"
    vd_events = [
        e
        for e in run2["events"]
        if e.get("kind") == "field_changed"
        and e.get("poam_id") == pid
        and (e.get("detail") or {}).get("after", {}).get("vd_source") == "operator"
    ]
    assert vd_events, run2["events"]
    before = vd_events[-1]["detail"]["before"]
    after = vd_events[-1]["detail"]["after"]
    assert before["vd_source"] == "default"
    assert after["vd_source"] == "operator"
    assert before["vendor_dependency"] == VD_NO
    assert after["vendor_dependency"] == VD_NO

    run3 = _apply(
        [rec],
        ledger=run2,
        when="2026-09-12T00:00:00Z",
        overrides={
            pid: {
                "vendor_dependency": "Yes",
                "last_vendor_checkin": "2026-09-12",
                "vendor_product": "Vendor – Product",
            }
        },
    )
    item3 = next(iter(run3["items"].values()))
    assert item3["vendor_dependency"] == VD_YES
    assert item3["status_date"] == "2026-09-12"
    yes_events = [
        e
        for e in run3["events"]
        if e.get("kind") == "field_changed"
        and e.get("poam_id") == pid
        and (e.get("detail") or {}).get("after", {}).get("vendor_dependency") == VD_YES
    ]
    assert yes_events, run3["events"]
    assert yes_events[-1]["detail"]["before"]["vendor_dependency"] == VD_NO
    assert yes_events[-1]["detail"]["after"]["last_vendor_checkin"] == "2026-09-12"
    assert yes_events[-1]["detail"]["after"]["vendor_product"] == "Vendor – Product"
    assert item3["poam_id"] == pid
    assert item3["fp"] == fp
    assert fp_v1(rec) == fp


def test_pre_gap2_ledger_upgrade_does_not_churn_status_date() -> None:
    """First run over a pre-#160 ledger backfills No/default without touching N."""
    rec = _rec()
    other = _rec(
        extra={"id": "other", "tool": "nessus", "port": "80", "protocol": "tcp"},
        assets=["10.0.0.9"],
        name="other",
        ref_id="VULN-other",
    )
    run1 = _apply([rec, other], when="2026-09-01T00:00:00Z")
    prior = deepcopy(run1)
    for item in prior["items"].values():
        item["status_date"] = "2026-09-01"
        for key in (
            "vendor_dependency",
            "vd_source",
            "last_vendor_checkin",
            "vendor_product",
            "vd_comments",
            "vd_flags",
        ):
            item.pop(key, None)
    dates = {it["status_date"] for it in prior["items"].values()}
    assert dates == {"2026-09-01"}

    run2 = _apply([rec, other], ledger=prior, when="2026-09-20T00:00:00Z")
    for item in run2["items"].values():
        assert item["vendor_dependency"] == VD_NO
        assert item["vd_source"] == "default"
        assert item["status_date"] == "2026-09-01"
    new_events = [e for e in run2["events"] if str(e.get("at") or "").startswith("2026-09-20")]
    assert not any(e.get("kind") == "field_changed" for e in new_events), new_events
    assert {it["poam_id"] for it in run2["items"].values()} == {
        it["poam_id"] for it in run1["items"].values()
    }

    unseen = _apply([rec], ledger=prior, when="2026-09-20T00:00:00Z")
    for item in unseen["items"].values():
        assert item["status_date"] == "2026-09-01"
        assert item["vendor_dependency"] == VD_NO
        assert item["vd_source"] == "default"
    unseen_new = [e for e in unseen["events"] if str(e.get("at") or "").startswith("2026-09-20")]
    assert not any(e.get("kind") == "field_changed" for e in unseen_new), unseen_new


def test_invalid_override_maybe_warns() -> None:
    rec = _rec()
    first = _apply([rec])
    pid = next(iter(first["items"].values()))["poam_id"]
    second = _apply(
        [rec],
        ledger=first,
        overrides={pid: {"vendor_dependency": "Maybe"}},
    )
    item = next(iter(second["items"].values()))
    assert item["vendor_dependency"] == VD_NO
    assert item["vd_source"] == "default"
    assert any(str(w).startswith(f"{VD_INVALID_OVERRIDE}:{pid}:Maybe") for w in second["warnings"])


def test_vd_yes_not_listed_on_closed_csv(tmp_path: Path) -> None:
    rec = _rec()
    first = _apply([rec])
    pid = next(iter(first["items"].values()))["poam_id"]
    confirmed = _apply(
        [rec],
        ledger=first,
        overrides={
            pid: {
                "vendor_dependency": "Yes",
                "last_vendor_checkin": "2026-09-10",
                "vendor_product": "Vendor – Product",
                "status": "closed",
                "evidence_ref": "ticket-1",
            }
        },
    )
    item = next(iter(confirmed["items"].values()))
    assert item["status"] != "closed"
    assert any(str(w).startswith(f"{VD_NOT_CLOSED}:{pid}") for w in confirmed["warnings"])

    leaked = dict(item)
    leaked["status"] = "closed"
    leaked["closed_date"] = "2026-09-11"
    write_fedramp_poam(
        tmp_path,
        {"items": {item["fp"]: leaked}, "closed": [leaked]},
    )
    with (tmp_path / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        open_rows = list(csv.DictReader(fh))
    with (tmp_path / "poam_fedramp_closed.csv").open(encoding="utf-8", newline="") as fh:
        closed_rows = list(csv.DictReader(fh))
    assert any(r.get("POAM ID") == pid and r.get("Vendor Dependency") == VD_YES for r in open_rows)
    assert not any(r.get("Vendor Dependency") == VD_YES for r in closed_rows)
    assert not any(r.get("POAM ID") == pid for r in closed_rows)


def test_yes_without_product_flags_vd_missing_product() -> None:
    rec = _rec()
    first = _apply([rec])
    pid = next(iter(first["items"].values()))["poam_id"]
    second = _apply(
        [rec],
        ledger=first,
        overrides={pid: {"vendor_dependency": "Yes", "vendor_product": "N/A"}},
    )
    item = next(iter(second["items"].values()))
    assert item["vendor_dependency"] == VD_YES
    assert item["vendor_product"] == ""
    assert VD_MISSING_PRODUCT in item["vd_flags"]
    assert any(str(w).startswith(VD_MISSING_PRODUCT) for w in second["warnings"])


def test_vendor_checkin_overdue_fires_at_32_not_31() -> None:
    rec = _rec()
    first = _apply([rec], when="2026-09-01T00:00:00Z")
    pid = next(iter(first["items"].values()))["poam_id"]
    ov = {
        pid: {
            "vendor_dependency": "Yes",
            "last_vendor_checkin": "2026-09-01",
            "vendor_product": "Vendor – Product",
        }
    }
    at_31 = _apply([rec], ledger=first, when="2026-10-02T00:00:00Z", overrides=ov)
    item_31 = next(iter(at_31["items"].values()))
    assert (datetime(2026, 10, 2) - datetime(2026, 9, 1)).days == CHECKIN_OVERDUE_AFTER_DAYS
    assert VENDOR_CHECKIN_OVERDUE not in item_31["vd_flags"]

    at_32 = _apply([rec], ledger=first, when="2026-10-03T00:00:00Z", overrides=ov)
    item_32 = next(iter(at_32["items"].values()))
    assert VENDOR_CHECKIN_OVERDUE in item_32["vd_flags"]


def test_blank_p_when_yes_is_overdue() -> None:
    rec = _rec()
    first = _apply([rec])
    pid = next(iter(first["items"].values()))["poam_id"]
    second = _apply(
        [rec],
        ledger=first,
        overrides={pid: {"vendor_dependency": "Yes", "vendor_product": "Vendor – Product"}},
    )
    item = next(iter(second["items"].values()))
    assert item["last_vendor_checkin"] == ""
    assert VENDOR_CHECKIN_OVERDUE in item["vd_flags"]


def test_no_never_emits_na_or_none() -> None:
    rec = _rec()
    item = next(iter(_apply([rec])["items"].values()))
    row = item_to_row(item)
    assert row[13] == VD_NO
    assert row[14] == ""
    assert row[15] == ""
    assert row[14].lower() not in {"n/a", "none"}
    assert row[15].lower() not in {"n/a", "none"}


def test_vd_does_not_suspend_kev_due() -> None:
    catalog = KevCatalog(
        kev_evaluated=True,
        catalog_version="2026.09.01",
        sha256="abc123def456",
        by_cve={
            "CVE-2024-0001": KevEntry(
                cve_id="CVE-2024-0001",
                date_added="2026-06-01",
                due_date="2026-09-05",
                forensic_triage="No",
                ransomware="Unknown",
                raw={},
            )
        },
    )
    rec = _rec(extra={"id": "plugin-1", "tool": "nessus", "cve": "CVE-2024-0001"})
    joined = join_kev(["CVE-2024-0001"], catalog)
    first = _apply([rec], catalog=catalog)
    item = next(iter(first["items"].values()))
    due_before = item["effective_due"]
    kev_due = item["kev_due"]
    assert kev_due == "2026-09-05"
    assert due_before
    candidates = [d for d in (item.get("template_due"), kev_due) if d]
    assert due_before == min(candidates)
    pid = item["poam_id"]
    second = _apply(
        [rec],
        ledger=first,
        catalog=catalog,
        overrides={
            pid: {
                "vendor_dependency": "Yes",
                "last_vendor_checkin": "2026-09-10",
                "vendor_product": "Vendor – Product",
            }
        },
    )
    yes = next(iter(second["items"].values()))
    assert yes["vendor_dependency"] == VD_YES
    assert yes["effective_due"] == due_before
    assert yes["kev_due"] == kev_due
    assert yes["template_due"] == item["template_due"]
    row = item_to_row(yes)
    assert row[11] == ""  # col M blank regardless of O
    assert KEV_NOT_SUSPENDED_COMMENT in yes["vd_comments"]
    assert joined["kev_due"].isoformat() == kev_due


def test_vd_yes_stays_open_when_not_observed() -> None:
    rec = _rec()
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    pid = next(iter(first["items"].values()))["poam_id"]
    confirmed = _apply(
        [rec],
        ledger=first,
        when="2026-09-11T00:00:00Z",
        overrides={
            pid: {
                "vendor_dependency": "Yes",
                "last_vendor_checkin": "2026-09-11",
                "vendor_product": "Vendor – Product",
            }
        },
    )
    other = _rec(extra={"id": "other", "tool": "nessus", "port": "80", "protocol": "tcp"}, assets=["10.0.0.9"])
    later = _apply([other], ledger=confirmed, when="2026-09-20T00:00:00Z")
    vd_item = later["items"][next(iter(confirmed["items"]))]
    assert vd_item["vendor_dependency"] == VD_YES
    assert vd_item["status"] == "open"
    assert vd_item["status"] != "pending_verification"


def test_poam_md_states_default_is_not_verified(tmp_path: Path, monkeypatch) -> None:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    rec = _rec()
    rec["kind"] = "finding"
    with (out / "canonical" / "x.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    (tmp_path / "in").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "Vendor Dependency = No is a default, not a verified determination" in md
    assert VD_NOTE in md
    with (out / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    assert all(r["Vendor Dependency"] in {VD_YES, VD_NO} for r in rows)
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    for item in ledger["items"].values():
        assert item["vd_source"] in {"default", "operator", "suggested"}


def test_format_and_canon_helpers() -> None:
    assert format_vendor_product("N/A") == ""
    assert format_vendor_product("None") == ""
    assert format_vendor_product("Acme - Widget") == "Acme – Widget"
    assert canon_yes_no("YES") == VD_YES
    assert canon_yes_no("maybe") is None
