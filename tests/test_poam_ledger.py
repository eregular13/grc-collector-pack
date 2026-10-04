"""Gap 3 §3.5 test cases (numbering maps 1:1) plus the name→asset-id+port migration map."""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path

from shared.asset_key import (
    asset_key,
    legacy_asset_id_port_key,
    legacy_name_asset_key,
    legacy_port_only_asset_key,
)
from shared.ciso_shape import POAM_HEADER
from shared.kev import KevCatalog
from shared.poam_fedramp import FEDRAMP_OPEN_HEADERS
from shared.poam_fields import local_run_date
from shared.poam_ledger import (
    LEDGER_CHAIN_BROKEN,
    LEDGER_LOST,
    LEDGER_LOST_FIRST_RUN_NOTE,
    apply_ledger,
    assign_poam_id,
    empty_ledger,
    fan_out_instances,
    format_ledger_warning_line,
    fp_v1,
    ledger_run_delta,
    load_ledger_file,
    payload_sha256,
    weakness_key,
)
from shared.schema import slug

ROOT = Path(__file__).resolve().parents[1]

# Golden fp_v1 vectors — accidental re-keying must fail this test.
GOLDEN_NESSUS = {
    "source": "vuln-scan",
    "name": "Microsoft Windows SMB Shares Unprivileged Access",
    "assets": ["http://10.0.0.20"],
    "labels": ["nessus"],
    "extra": {"id": "42411", "tool": "nessus", "port": "445", "protocol": "tcp"},
}


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


def _apply(findings, ledger=None, when="2026-09-10T00:00:00Z", overrides=None, prior_existed=True):
    return apply_ledger(
        findings,
        catalog=_unevaluated(),
        run_at=_run(when),
        ledger_in=ledger,
        overrides=overrides or {},
        prior_existed=prior_existed,
    )


def test_3_5_1_stable_id() -> None:
    """§3.5.1 Stable ID: same fixture twice (ledger carried) → same poam_id and original_detection_date; status_date unchanged; last_seen updated."""
    rec = _rec()
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    item = next(iter(first["items"].values()))
    pid, odd, status_date = item["poam_id"], item["original_detection_date"], item["status_date"]
    second = _apply([rec], ledger=first, when="2026-09-11T12:00:00Z")
    item2 = next(iter(second["items"].values()))
    assert item2["poam_id"] == pid
    assert item2["original_detection_date"] == odd
    assert item2["status_date"] == status_date
    assert item2["last_seen"].startswith("2026-09-11")


def test_3_5_2_volatile_fields_ignored() -> None:
    """§3.5.2 Volatile fields ignored: severity/description/plugin output change keeps ID; rating change updates status_date; original_risk_rating stays."""
    rec = _rec(severity="high")
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    item = next(iter(first["items"].values()))
    rec2 = _rec(severity="medium", description="rewritten plugin output", name=rec["name"])
    rec2["extra"] = dict(rec["extra"])
    second = _apply([rec2], ledger=first, when="2026-09-12T00:00:00Z")
    item2 = next(iter(second["items"].values()))
    assert item2["poam_id"] == item["poam_id"]
    assert item2["original_risk_rating"] == item["original_risk_rating"] == "High"
    assert item2["current_scanner_rating"] == "medium"
    assert item2["status_date"] == local_run_date(_run("2026-09-12T00:00:00Z")).isoformat()
    assert any(e["kind"] == "field_changed" for e in second["events"])


def test_3_5_3_dedupe_bug_covered() -> None:
    """§3.5.3 Dedupe bug covered: one Trivy CVE on two targets → 2 instances and 2 IDs."""
    rec = {
        "kind": "finding",
        "source": "vuln-scan",
        "ref_id": "VULN-CVE-2023-44270",
        "name": "CVE-2023-44270",
        "description": "trivy",
        "severity": "high",
        "category": "vulnerability",
        "assets": ["alpine:3.19", "debian:12"],
        "labels": ["trivy"],
        "collected_at": "2026-09-01T00:00:00Z",
        "extra": {"cve": "CVE-2023-44270"},
    }
    instances = fan_out_instances([rec])
    assert len(instances) == 2
    ledger = _apply([rec])
    assert len(ledger["items"]) == 2
    ids = {i["poam_id"] for i in ledger["items"].values()}
    assets = {i["asset_key"] for i in ledger["items"].values()}
    assert len(ids) == 2
    assert len(assets) == 2
    assert all(k.startswith("EGA-") for k in assets)


def test_3_5_4_port_distinguishes() -> None:
    """§3.5.4 Port distinguishes: same Nessus plugin on host:443 and host:8443 → 2 IDs."""
    a = _rec(extra={"id": "156032", "tool": "nessus", "port": "443", "protocol": "tcp"})
    b = _rec(extra={"id": "156032", "tool": "nessus", "port": "8443", "protocol": "tcp"})
    ledger = _apply([a, b])
    assert len(ledger["items"]) == 2
    assert {i["poam_id"] for i in ledger["items"].values()}.__len__() == 2


def test_ledger_lost_clears_when_ledger_supplied() -> None:
    """Argus B11: LEDGER_LOST is this-run only; a supplied ledger clears it."""
    rec = _rec()
    first = _apply([rec], when="2026-09-10T00:00:00Z", prior_existed=False)
    assert LEDGER_LOST in first["warnings"]
    second = _apply([rec], ledger=first, when="2026-09-11T00:00:00Z", prior_existed=True)
    assert LEDGER_LOST not in second["warnings"]


def test_3_5_5_lost_ledger() -> None:
    """§3.5.5 Lost ledger: run 2 without a ledger regenerates the same IDs; detection_date_basis flagged; original_detection_date resets (warning)."""
    rec = _rec(collected_at="2026-09-01T00:00:00Z")
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    pid = next(iter(first["items"].values()))["poam_id"]
    second = _apply([rec], ledger=None, when="2026-09-20T00:00:00Z", prior_existed=False)
    item = next(iter(second["items"].values()))
    assert item["poam_id"] == pid
    assert "ledger_lost" in item["detection_date_basis"]
    assert LEDGER_LOST in second["warnings"]
    # collected_at is not a scan timestamp — missing artifact time is 'not recorded'
    assert item["original_detection_date"] == "not recorded"


def test_3_5_6_no_coverage_no_closure() -> None:
    """§3.5.6 No coverage, no closure: family didn't run → stays open (not_observed_no_coverage)."""
    rec = _rec(source="vuln-scan")
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    other = _rec(
        source="inventory-nmap",
        extra={"id": "nse-ftp-anon", "tool": "nmap", "port": "21"},
        assets=["10.0.0.9"],
        name="ftp-anon",
    )
    second = _apply([other], ledger=first, when="2026-09-11T00:00:00Z")
    orig_fp = next(iter(first["items"]))
    item = second["items"][orig_fp]
    assert item["status"] == "open"
    assert any(e["kind"] == "not_observed_no_coverage" and e["fp"] == orig_fp for e in second["events"])


def test_3_5_7_pending_not_closed() -> None:
    """§3.5.7 Pending, not closed: absent in 2 covered runs → pending_verification, still Open, not Closed."""
    rec = _rec(assets=["10.0.0.5"], extra={"id": "A", "tool": "nessus", "port": "443", "protocol": "tcp"})
    cover = _rec(
        assets=["10.0.0.5"],
        extra={"id": "B", "tool": "nessus", "port": "80", "protocol": "tcp"},
        name="other",
        ref_id="VULN-B",
    )
    first = _apply([rec, cover], when="2026-09-10T00:00:00Z")
    fp_a = next(fp for fp, it in first["items"].items() if it["weakness_key"].endswith(":A"))
    second = _apply([cover], ledger=first, when="2026-09-11T00:00:00Z")
    assert second["items"][fp_a]["status"] == "open"
    third = _apply([cover], ledger=second, when="2026-09-12T00:00:00Z")
    item = third["items"][fp_a]
    assert item["status"] == "pending_verification"
    assert item["status"] != "closed"
    assert "closed" not in {i["status"] for i in third["items"].values() if i["fp"] == fp_a}


def test_3_5_8_operator_closure() -> None:
    """§3.5.8 Operator closure: override status=closed + evidence_ref → Closed; Status Date = override date."""
    rec = _rec()
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    pid = next(iter(first["items"].values()))["poam_id"]
    second = _apply(
        [rec],
        ledger=first,
        when="2026-09-11T00:00:00Z",
        overrides={pid: {"poam_id": pid, "status": "closed", "evidence_ref": "clean-scan.nessus sha256:abc", "status_date": "2026-09-09"}},
    )
    item = next(iter(second["items"].values()))
    assert item["status"] == "closed"
    assert item["status_date"] == "2026-09-09"
    assert item["closed_date"] == "2026-09-09"
    assert "clean-scan.nessus sha256:abc" in item["closure_evidence"]


def test_3_5_9_reopen_after_closure() -> None:
    """§3.5.9 Reopen after closure: fp reappears → ID …-R1, new detection date; old row still Closed; Comment links both."""
    rec = _rec(
        collected_at="2026-09-01T00:00:00Z",
        extra={"id": "plugin-1", "tool": "nessus", "port": "443", "protocol": "tcp", "scan_time": "2026-09-01T00:00:00Z"},
    )
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    pid = next(iter(first["items"].values()))["poam_id"]
    closed = _apply(
        [rec],
        ledger=first,
        when="2026-09-11T00:00:00Z",
        overrides={pid: {"status": "closed", "evidence_ref": "ticket-1", "status_date": "2026-09-11"}},
    )
    rec2 = _rec(
        collected_at="2026-09-20T00:00:00Z",
        extra={"id": "plugin-1", "tool": "nessus", "port": "443", "protocol": "tcp", "scan_time": "2026-09-20T00:00:00Z"},
    )
    reopened = _apply([rec2], ledger=closed, when="2026-09-20T00:00:00Z")
    item = next(iter(reopened["items"].values()))
    assert item["poam_id"] == f"{pid}-R1"
    assert item["original_detection_date"] == "2026-09-20"
    assert item["prior_poam_id"] == pid
    assert any(c["poam_id"] == pid and c["status"] == "closed" for c in reopened["closed"])
    assert any("Reopened from" in c for c in item["kev_comments"])


def test_3_5_10_flap_before_closure() -> None:
    """§3.5.10 Flap before closure: pending_verification then seen again → same ID, original date kept."""
    rec = _rec(assets=["10.0.0.5"], extra={"id": "A", "tool": "nessus", "port": "443", "protocol": "tcp"})
    cover = _rec(
        assets=["10.0.0.5"],
        extra={"id": "B", "tool": "nessus", "port": "80", "protocol": "tcp"},
        name="other",
        ref_id="VULN-B",
    )
    first = _apply([rec, cover], when="2026-09-10T00:00:00Z")
    fp_a = next(fp for fp, it in first["items"].items() if it["weakness_key"].endswith(":A"))
    pid = first["items"][fp_a]["poam_id"]
    odd = first["items"][fp_a]["original_detection_date"]
    mid = _apply([cover], ledger=first, when="2026-09-11T00:00:00Z")
    pending = _apply([cover], ledger=mid, when="2026-09-12T00:00:00Z")
    assert pending["items"][fp_a]["status"] == "pending_verification"
    back = _apply([rec, cover], ledger=pending, when="2026-09-13T00:00:00Z")
    item = back["items"][fp_a]
    assert item["poam_id"] == pid
    assert item["original_detection_date"] == odd
    assert item["status"] == "open"


def test_3_5_11_collision() -> None:
    """§3.5.11 Collision: forced 10-hex prefix collision → newcomer gets a 12-hex ID; old ID unchanged."""
    used = {"EGP-AAAAAAAAAA": "ffff" + "0" * 60}
    newcomer = "aaaaaaaaaa" + "b" * 54
    pid = assign_poam_id(newcomer, used)
    assert pid == "EGP-" + newcomer[:12].upper()
    assert assign_poam_id("aaaaaaaaaa" + "c" * 54, {"EGP-AAAAAAAAAA": "aaaaaaaaaa" + "c" * 54}) == "EGP-AAAAAAAAAA"


def test_3_5_12_truncation() -> None:
    """§3.5.12 Truncation: two long nikto keys that collide under slug's 48-char cut get distinct fp_v1."""
    prefix = "nikto-OSVDB-3233-apache-tomcat-default-docs-example-"  # long shared prefix
    a = _rec(
        extra={"id": prefix + "host-aaaa.example.internal-/manager/html", "tool": "nikto"},
        assets=["host-a"],
        name="nikto-a",
    )
    b = _rec(
        extra={"id": prefix + "host-bbbb.example.internal-/manager/html", "tool": "nikto"},
        assets=["host-a"],
        name="nikto-b",
    )
    assert slug(a["extra"]["id"], 48) == slug(b["extra"]["id"], 48)
    assert weakness_key(a) != weakness_key(b)
    assert fp_v1(a) != fp_v1(b)


def test_3_5_13_header_fidelity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """§3.5.13 Header fidelity: FedRAMP CSV = S1 row 5 B..AB exactly; existing poam.csv contract still passes."""
    from shared.ciso_shape import POAM_HEADER as locked

    assert tuple(FEDRAMP_OPEN_HEADERS) == (
        "POAM ID",
        "Controls",
        "Weakness Name",
        "Weakness Description",
        "Weakness Detector Source",
        "Weakness Source Identifier",
        "Asset Identifier",
        "Point of Contact",
        "Resources Required",
        "Overall Remediation Plan",
        "Original Detection Date",
        "Scheduled Completion Date",
        "Status Date",
        "Vendor Dependency",
        "Last Vendor Check-in Date",
        "Vendor Dependent Product Name",
        "Original Risk Rating",
        "Adjusted Risk Rating",
        "Risk Adjustment",
        "False Positive",
        "Operational Requirement",
        "Deviation Rationale",
        "Supporting Documents",
        "Comments",
        "Binding Operational Directive 22-01 tracking",
        "Binding Operational Directive 22-01 Due Date",
        "CVE",
    )
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
    poam_header = (out / "poam" / "poam.csv").read_text(encoding="utf-8").splitlines()[0].strip()
    assert poam_header == locked
    from shared.poam_fedramp import FEDRAMP_CSV_HEADERS

    fed = (out / "poam" / "poam_fedramp.csv").read_text(encoding="utf-8").splitlines()[0]
    cols = tuple(fed.split(","))
    assert cols[: len(FEDRAMP_OPEN_HEADERS)] == FEDRAMP_OPEN_HEADERS
    assert cols == FEDRAMP_CSV_HEADERS


def test_3_5_14_integrity() -> None:
    """§3.5.14 Integrity: ledger prev_sha256 chain is verified; a tampered prior ledger emits LEDGER_CHAIN_BROKEN."""
    rec = _rec()
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    assert first["sha256"] == payload_sha256(first)
    tampered = json.loads(json.dumps(first))
    next(iter(tampered["items"].values()))["remediation_plan"] = "tampered"
    # stored sha256 left pointing at the pre-tamper payload
    path = Path("/tmp/not-used")
    # verify via load_ledger_file after writing
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "poam-ledger.json"
        p.write_text(json.dumps(tampered), encoding="utf-8")
        _doc, warnings = load_ledger_file(p)
        assert LEDGER_CHAIN_BROKEN in warnings


def test_load_ledger_file_skips_non_dict_items(tmp_path: Path) -> None:
    """A valid JSON ledger with None / string / list items must not crash."""
    rec = _rec()
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    fp, item = next(iter(first["items"].items()))
    first["items"]["bad-none"] = None
    first["items"]["bad-str"] = "oops"
    first["items"]["bad-list"] = ["not", "a", "dict"]
    first["closed"] = [None, "oops", [], dict(item)]
    path = tmp_path / "poam-ledger.json"
    path.write_text(json.dumps(first), encoding="utf-8")
    doc, warnings = load_ledger_file(path)
    assert LEDGER_CHAIN_BROKEN in warnings
    assert fp in doc["items"]
    assert "bad-none" not in doc["items"]
    assert "bad-str" not in doc["items"]
    assert "bad-list" not in doc["items"]
    assert all(isinstance(row, dict) for row in doc["closed"])
    # apply_ledger must not AttributeError on the sanitized prior.
    second = apply_ledger(
        [rec],
        catalog=KevCatalog(kev_evaluated=False, reason="snapshot_missing"),
        run_at=datetime(2026, 9, 11, tzinfo=timezone.utc),
        ledger_in=doc,
        prior_existed=True,
    )
    assert fp in second["items"]

    listed = {"sha256": "", "items": [{"poam_id": "EGP-LIST0001"}], "closed": "nope"}
    listed_path = tmp_path / "listed-ledger.json"
    listed_path.write_text(json.dumps(listed), encoding="utf-8")
    listed_doc, listed_warn = load_ledger_file(listed_path)
    assert LEDGER_CHAIN_BROKEN in listed_warn
    assert listed_doc["items"] == {}
    assert listed_doc["closed"] == []
    apply_ledger(
        [rec],
        catalog=KevCatalog(kev_evaluated=False, reason="snapshot_missing"),
        run_at=datetime(2026, 9, 11, tzinfo=timezone.utc),
        ledger_in=listed_doc,
        prior_existed=True,
    )


def _resign(doc: dict) -> dict:
    doc["sha256"] = payload_sha256(doc)
    return doc


def _cover_rec() -> dict:
    return _rec(
        ref_id="VULN-cover",
        name="cover peer",
        extra={"id": "plugin-cover", "tool": "nessus", "port": "80", "protocol": "tcp"},
    )


def test_load_ledger_file_flags_each_corruption_on_resigned_ledger(tmp_path: Path) -> None:
    """L2/L3/L4/L6: one corruption at a time on a re-signed ledger still flags."""
    rec = _rec()
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    fp, item = next(iter(first["items"].items()))
    pid = str(item.get("poam_id") or "")

    l2 = json.loads(json.dumps(first))
    l2["items"]["bad-none"] = None
    _resign(l2)
    l2_path = tmp_path / "l2.json"
    l2_path.write_text(json.dumps(l2), encoding="utf-8")
    l2_doc, l2_warn = load_ledger_file(l2_path)
    assert LEDGER_CHAIN_BROKEN in l2_warn
    assert fp in l2_doc["items"]
    assert "bad-none" not in l2_doc["items"]

    l3 = {"items": [dict(item)], "closed": []}
    _resign(l3)
    l3_path = tmp_path / "l3.json"
    l3_path.write_text(json.dumps(l3), encoding="utf-8")
    l3_doc, l3_warn = load_ledger_file(l3_path)
    assert LEDGER_CHAIN_BROKEN in l3_warn
    assert l3_doc["items"] == {}
    assert pid in l3_doc["dropped_poam_ids"]

    l4 = json.loads(json.dumps(first))
    l4["closed"] = "nope"
    _resign(l4)
    l4_path = tmp_path / "l4.json"
    l4_path.write_text(json.dumps(l4), encoding="utf-8")
    l4_doc, l4_warn = load_ledger_file(l4_path)
    assert LEDGER_CHAIN_BROKEN in l4_warn
    assert l4_doc["closed"] == []
    assert fp in l4_doc["items"]

    l6 = json.loads(json.dumps(first))
    l6["closed"] = [None]
    _resign(l6)
    l6_path = tmp_path / "l6.json"
    l6_path.write_text(json.dumps(l6), encoding="utf-8")
    l6_doc, l6_warn = load_ledger_file(l6_path)
    assert LEDGER_CHAIN_BROKEN in l6_warn
    assert l6_doc["closed"] == []
    assert fp in l6_doc["items"]


def test_dropped_unseen_open_id_is_listed_not_closed() -> None:
    """Unseen OPEN row whose item was dropped is named in the warning, not closed."""
    rec = _rec()
    cover = _cover_rec()
    first = _apply([rec, cover], when="2026-09-10T00:00:00Z")
    rec_fp = next(
        fp
        for fp, it in first["items"].items()
        if "plugin-1" in str(it.get("weakness_key") or "")
    )
    rec_pid = str(first["items"][rec_fp].get("poam_id") or "")
    listed = {
        "items": [dict(it) for it in first["items"].values()],
        "closed": [],
    }
    _resign(listed)
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "listed.json"
        path.write_text(json.dumps(listed), encoding="utf-8")
        doc, warns = load_ledger_file(path)
    assert LEDGER_CHAIN_BROKEN in warns
    assert rec_pid in doc["dropped_poam_ids"]
    second = _apply([cover], ledger=doc, when="2026-09-11T00:00:00Z")
    assert LEDGER_CHAIN_BROKEN in second["warnings"]
    assert rec_pid in second["dropped_poam_ids"]
    assert rec_pid not in {str(it.get("poam_id") or "") for it in second["items"].values()}
    assert rec_pid not in {str(it.get("poam_id") or "") for it in second["closed"]}
    third = _apply([cover], ledger=second, when="2026-09-12T00:00:00Z")
    assert LEDGER_CHAIN_BROKEN in third["warnings"]
    assert rec_pid in third["dropped_poam_ids"]
    clean = _apply([cover], ledger=first, when="2026-09-13T00:00:00Z")
    assert LEDGER_CHAIN_BROKEN not in clean["warnings"]
    assert rec_pid not in clean.get("dropped_poam_ids", [])


def test_format_ledger_warning_line_first_run_note() -> None:
    assert format_ledger_warning_line([LEDGER_LOST], estate_kind="DEMO") == (
        f"{LEDGER_LOST} ({LEDGER_LOST_FIRST_RUN_NOTE})"
    )
    assert format_ledger_warning_line(
        [LEDGER_LOST], estate_kind="DEMO", first_run=False
    ) == LEDGER_LOST
    assert format_ledger_warning_line([LEDGER_LOST], estate_kind="CLIENT") == LEDGER_LOST
    assert "EGP-AAA" in format_ledger_warning_line(
        [LEDGER_CHAIN_BROKEN], ["EGP-AAA"], estate_kind="DEMO"
    )


def test_ledger_warning_reaches_exec_and_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Broken prior: dropped ID on exec + summary.json; row stays off the plan."""
    from collectors.grc_loader import load
    from shared.io_util import write_canonical

    rec = _rec()
    cover = _cover_rec()
    first = _apply([rec, cover], when="2026-09-10T00:00:00Z")
    rec_fp = next(
        fp
        for fp, it in first["items"].items()
        if "plugin-1" in str(it.get("weakness_key") or "")
    )
    rec_pid = str(first["items"][rec_fp].get("poam_id") or "")
    listed = {
        "items": [dict(it) for it in first["items"].values()],
        "closed": [],
    }
    _resign(listed)
    incoming = tmp_path / "empty-in"
    incoming.mkdir()
    (incoming / "poam").mkdir()
    (incoming / "poam" / "poam-ledger.json").write_text(
        json.dumps(listed), encoding="utf-8"
    )
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(incoming))
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    write_canonical("mixed", [cover, _rec_as_asset(cover)])
    summary = load()
    assert LEDGER_CHAIN_BROKEN in summary["ledger_warnings"]
    assert rec_pid in summary["ledger_dropped_poam_ids"]
    exec_text = (tmp_path / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    assert "Ledger warning:" in exec_text
    assert LEDGER_CHAIN_BROKEN in exec_text
    assert rec_pid in exec_text
    poam_md = (tmp_path / "poam" / "poam.md").read_text(encoding="utf-8")
    assert rec_pid in poam_md
    from shared.ciso_shape import csv_rows

    poam = csv_rows(tmp_path / "poam" / "poam.csv")
    assert rec_pid not in {row.get("poam_id") for row in poam}
    closed = json.loads((tmp_path / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    assert rec_pid not in {str(it.get("poam_id") or "") for it in closed.get("closed") or []}


def _rec_as_asset(rec: dict) -> dict:
    host = (rec.get("assets") or ["10.0.0.5"])[0]
    return {
        "kind": "asset",
        "source": "inventory-nmap",
        "ref_id": f"AST-{host}",
        "name": host,
        "description": host,
        "severity": "",
        "category": "host",
        "assets": [host],
        "labels": [],
        "extra": {},
    }


def test_load_ledger_file_carry_sticks_through_pipeline_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two real loader runs: corrupt, then out/ fallback with no valid prior.

    Removing ``_integrity_flags(doc)`` in ``load_ledger_file`` clears the
    warning on the fallback run; this test must fail that mutant.
    """
    from collectors.grc_loader import load
    from shared.io_util import write_canonical

    rec = _rec()
    cover = _cover_rec()
    first = _apply([rec, cover], when="2026-09-10T00:00:00Z")
    rec_fp = next(
        fp
        for fp, it in first["items"].items()
        if "plugin-1" in str(it.get("weakness_key") or "")
    )
    rec_pid = str(first["items"][rec_fp].get("poam_id") or "")
    listed = {
        "items": [dict(it) for it in first["items"].values()],
        "closed": [],
    }
    _resign(listed)
    incoming = tmp_path / "empty-in"
    incoming.mkdir()
    (incoming / "poam").mkdir()
    corrupt = incoming / "poam" / "poam-ledger.json"
    corrupt.write_text(json.dumps(listed), encoding="utf-8")
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(incoming))
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    write_canonical("mixed", [cover, _rec_as_asset(cover)])
    first_load = load()
    assert LEDGER_CHAIN_BROKEN in first_load["ledger_warnings"]
    assert rec_pid in first_load["ledger_dropped_poam_ids"]
    recovered = json.loads((tmp_path / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    assert LEDGER_CHAIN_BROKEN in recovered.get("warnings", [])
    corrupt.unlink()
    second_load = load()
    assert LEDGER_CHAIN_BROKEN in second_load["ledger_warnings"]
    exec_text = (tmp_path / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    assert LEDGER_CHAIN_BROKEN in exec_text
    (incoming / "poam" / "poam-ledger.json").write_text(
        json.dumps(first), encoding="utf-8"
    )
    third_load = load()
    assert LEDGER_CHAIN_BROKEN not in third_load["ledger_warnings"]
    assert rec_pid not in (third_load.get("ledger_dropped_poam_ids") or [])


def test_dropped_id_back_on_plan_is_not_listed() -> None:
    """Seen-again row remints the same ID; it is not listed as dropped."""
    rec = _rec()
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    item = next(iter(first["items"].values()))
    rec_pid = str(item.get("poam_id") or "")
    listed = {"items": [dict(item)], "closed": []}
    _resign(listed)
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "listed.json"
        path.write_text(json.dumps(listed), encoding="utf-8")
        doc, warns = load_ledger_file(path)
    assert LEDGER_CHAIN_BROKEN in warns
    assert rec_pid in doc["dropped_poam_ids"]
    second = _apply([rec], ledger=doc, when="2026-09-11T00:00:00Z")
    assert LEDGER_CHAIN_BROKEN in second["warnings"]
    live = {str(it.get("poam_id") or "") for it in second["items"].values()}
    assert rec_pid in live
    assert rec_pid not in second["dropped_poam_ids"]


def test_ledger_lost_after_history_is_not_first_run_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collectors.grc_loader import load
    from shared.io_util import write_canonical

    rec = _rec()
    incoming = tmp_path / "empty-in"
    incoming.mkdir()
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(incoming))
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    write_canonical("mixed", [rec, _rec_as_asset(rec)])
    first = load()
    assert LEDGER_LOST in first["ledger_warnings"]
    assert LEDGER_LOST_FIRST_RUN_NOTE in (
        tmp_path / "EXECUTIVE_SUMMARY.md"
    ).read_text(encoding="utf-8")
    (tmp_path / "poam" / "poam-ledger.json").unlink()
    (incoming / "poam" / "poam-ledger.json").unlink(missing_ok=True)
    second = load()
    assert LEDGER_LOST in second["ledger_warnings"]
    exec_text = (tmp_path / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    poam_md = (tmp_path / "poam" / "poam.md").read_text(encoding="utf-8")
    assert LEDGER_LOST in exec_text
    assert LEDGER_LOST_FIRST_RUN_NOTE not in exec_text
    assert LEDGER_LOST in poam_md
    assert LEDGER_LOST_FIRST_RUN_NOTE not in poam_md


def test_first_run_ledger_lost_is_a_note_on_sample_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collectors.grc_loader import load
    from shared.io_util import write_canonical

    rec = _rec()
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)
    write_canonical("mixed", [rec, _rec_as_asset(rec)])
    summary = load()
    assert LEDGER_LOST in summary["ledger_warnings"]
    exec_text = (tmp_path / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    poam_md = (tmp_path / "poam" / "poam.md").read_text(encoding="utf-8")
    assert LEDGER_LOST in exec_text
    assert LEDGER_LOST_FIRST_RUN_NOTE in exec_text
    assert LEDGER_LOST in poam_md
    assert LEDGER_LOST_FIRST_RUN_NOTE in poam_md


def test_migration_map_name_to_asset_id_port_keeps_id_and_earliest_date() -> None:
    """Fingerprint inputs change (name-based → asset-ID+port): keep existing ID and earliest detection date."""
    rec = {
        "kind": "finding",
        "source": "cloud-prowler",
        "ref_id": "CLD-s3",
        "name": "S3 public",
        "description": "public ACL",
        "severity": "high",
        "category": "cloud-misconfiguration",
        "assets": ["arn:aws:s3:::Demo-Public-Assets"],
        "labels": ["prowler"],
        "collected_at": "2026-07-01T00:00:00Z",
        "extra": {"check_id": "s3_bucket_public_access", "arn": "arn:aws:s3:::Demo-Public-Assets"},
    }
    old_fp = fp_v1(rec, asset_key_fn=legacy_name_asset_key)
    mid_fp = fp_v1(rec, asset_key_fn=legacy_asset_id_port_key)
    new_fp = fp_v1(rec)
    assert old_fp != new_fp
    assert mid_fp != new_fp
    assert "demo-public-assets" in legacy_asset_id_port_key(rec)
    assert asset_key(rec).startswith("EGA-")
    assert "arn:aws:s3:::demo-public-assets" == legacy_name_asset_key(rec)

    # Seed a name-based ledger item (as if produced before the key change).
    seeded = _apply([rec], when="2026-07-02T00:00:00Z")
    # Rewrite the only item onto the legacy fp to simulate a prior name-based run.
    item = next(iter(seeded["items"].values()))
    seeded["items"] = {old_fp: {**item, "fp": old_fp, "asset_key": legacy_name_asset_key(rec)}}
    seeded["sha256"] = payload_sha256(seeded)
    pid = item["poam_id"]
    odd = item["original_detection_date"]

    migrated = _apply([rec], ledger=seeded, when="2026-09-01T00:00:00Z")
    assert new_fp in migrated["items"]
    assert old_fp not in migrated["items"]
    got = migrated["items"][new_fp]
    assert got["poam_id"] == pid
    assert got["original_detection_date"] == odd
    assert any(m["from"] == old_fp and m["to"] == new_fp for m in migrated["fp_migrations"])


def test_migration_nmap_title_to_check_id_keeps_id_and_date() -> None:
    """Old 'Open port 161/snmp' title → nmap-port-161/udp check_id keeps EGP- and date."""
    old = _rec(
        source="inventory-nmap",
        ref_id="NMAP-10-11-1-22-161",
        name="Open port 161/snmp",
        assets=["10.11.1.22"],
        labels=["nmap", "inventory"],
        extra={
            "port": "161",
            "service": "snmp",
            "protocol": "udp",
            "ip": "10.11.1.22",
            "tool": "nmap",
        },
    )
    new = {
        **old,
        "name": "SNMP 161/udp exposed",
        "ref_id": "NMAP-10-11-1-22-161-udp",
        "extra": {**old["extra"], "check_id": "nmap-port-161/udp"},
    }
    from shared.poam_ledger import legacy_title_weakness_key

    old_fp = fp_v1(old, weakness_key_fn=legacy_title_weakness_key)
    new_fp = fp_v1(new)
    assert old_fp != new_fp
    assert legacy_title_weakness_key(old).startswith("name:")
    assert weakness_key(new) == "nmap:nmap-port-161/udp"

    seeded = empty_ledger()
    first = _apply([old], when="2026-07-02T00:00:00Z")
    item = next(iter(first["items"].values()))
    seeded["items"] = {
        old_fp: {
            **item,
            "fp": old_fp,
            "weakness_key": legacy_title_weakness_key(old),
        }
    }
    seeded["sha256"] = payload_sha256(seeded)
    pid = item["poam_id"]
    odd = item["original_detection_date"]

    migrated = _apply([new], ledger=seeded, when="2026-09-01T00:00:00Z")
    assert new_fp in migrated["items"]
    assert old_fp not in migrated["items"]
    got = migrated["items"][new_fp]
    assert got["poam_id"] == pid
    assert got["original_detection_date"] == odd
    assert got["status"] != "pending_verification"
    assert not any(i.get("status") == "pending_verification" for i in migrated["items"].values())
    assert any(
        m["from"] == old_fp and m["to"] == new_fp and m.get("reason") == "nmap_title_to_check_id"
        for m in migrated["fp_migrations"]
    )


def test_migration_port_only_to_port_proto_keeps_id_and_date() -> None:
    """Pre-#140 host:22 → host:22/tcp: same EGP- ID, earliest date, not pending_verification."""
    old = _rec(
        source="inventory-nmap",
        ref_id="NMAP-host-22",
        name="SSH exposed",
        assets=["filesrv.corp.local"],
        labels=["nmap"],
        extra={"id": "port-22", "tool": "nmap", "port": "22"},
    )
    new = {
        **old,
        "extra": {"id": "port-22", "tool": "nmap", "port": "22", "protocol": "tcp"},
    }
    old_fp = fp_v1(old, asset_key_fn=legacy_port_only_asset_key)
    new_fp = fp_v1(new)
    assert old_fp != new_fp
    assert legacy_port_only_asset_key(old) == "filesrv.corp.local:22"
    assert legacy_asset_id_port_key(new) == "filesrv.corp.local:22/TCP"
    assert asset_key(new).startswith("EGA-")
    assert asset_key(new).endswith(":22/TCP")
    assert legacy_port_only_asset_key(new) == "filesrv.corp.local:22"

    seeded = _apply([old], when="2026-07-02T00:00:00Z")
    item = next(iter(seeded["items"].values()))
    seeded["items"] = {old_fp: {**item, "fp": old_fp, "asset_key": legacy_port_only_asset_key(old)}}
    seeded["sha256"] = payload_sha256(seeded)
    pid = item["poam_id"]
    odd = item["original_detection_date"]

    migrated = _apply([new], ledger=seeded, when="2026-09-01T00:00:00Z")
    assert new_fp in migrated["items"]
    assert old_fp not in migrated["items"]
    got = migrated["items"][new_fp]
    assert got["poam_id"] == pid
    assert got["original_detection_date"] == odd
    assert got["status"] != "pending_verification"
    assert not any(i.get("status") == "pending_verification" for i in migrated["items"].values())
    assert any(
        m["from"] == old_fp and m["to"] == new_fp and m.get("reason") == "port_only_to_port_proto"
        for m in migrated["fp_migrations"]
    )


def test_fp_v1_golden_vector() -> None:
    """#131 golden stays the asset-id+port vector; current key is EGA- + port."""
    golden = json.loads((ROOT / "tests" / "fixtures" / "poam" / "fp_v1_golden.json").read_text(encoding="utf-8"))
    expected = hashlib.sha256(
        (
            "v1|vuln-scan|nessus:42411|"
            + legacy_asset_id_port_key(GOLDEN_NESSUS)
        ).encode("utf-8")
    ).hexdigest()
    assert fp_v1(GOLDEN_NESSUS, asset_key_fn=legacy_asset_id_port_key) == expected == golden["fp_v1"]
    assert legacy_asset_id_port_key(GOLDEN_NESSUS) == golden["asset_key"] == "http://10.0.0.20:445/TCP"
    current = asset_key(GOLDEN_NESSUS)
    assert current.startswith("EGA-")
    assert current.endswith(":445/TCP")
    assert fp_v1(GOLDEN_NESSUS) != golden["fp_v1"]
    assert asset_key.__doc__ and "EGA-" in asset_key.__doc__


def _seed_item(fp: str, poam_id: str, rec: dict, odd: str, first_seen: str) -> dict:
    return {
        "poam_id": poam_id,
        "fp": fp,
        "source_family": rec["source"],
        "weakness_key": weakness_key(rec),
        "asset_key": legacy_asset_id_port_key(rec),
        "original_detection_date": odd,
        "first_seen": first_seen,
        "status": "open",
        "missed_covered_runs": 0,
        "kev_comments": [],
    }


def test_ega_merge_same_weakness_keeps_older_id_and_aliases_other() -> None:
    """Two old asset keys → one EGA- asset, same weakness: older EGP- wins; other is a map alias."""
    extra = {"id": "42411", "tool": "nessus", "port": "445", "protocol": "tcp"}
    ip_rec = _rec(assets=["10.0.0.30"], extra=dict(extra), name="SMB shares")
    host_rec = _rec(assets=["web-01"], extra=dict(extra), name="SMB shares")
    assert weakness_key(ip_rec) == weakness_key(host_rec)
    old_ip = fp_v1(ip_rec, asset_key_fn=legacy_asset_id_port_key)
    old_host = fp_v1(host_rec, asset_key_fn=legacy_asset_id_port_key)
    assert old_ip != old_host

    seeded = empty_ledger()
    seeded["items"] = {
        old_ip: _seed_item(old_ip, "EGP-OLDER0001", ip_rec, "2026-01-01", "2026-01-01T00:00:00Z"),
        old_host: _seed_item(old_host, "EGP-NEWER0002", host_rec, "2026-06-01", "2026-06-01T00:00:00Z"),
    }

    merged = _rec(
        assets=["web-01.corp.local"],
        extra={
            **extra,
            "asset_uid": "EGA-MERGED001",
            "ids": {"fqdn": "web-01.corp.local", "ip": ["10.0.0.30"], "hostname": "web-01"},
            "also_names": ["10.0.0.30", "web-01"],
        },
        name="SMB shares",
    )
    new_fp = fp_v1(merged)
    assert new_fp not in {old_ip, old_host}
    assert asset_key(merged).startswith("EGA-MERGED001")

    out = _apply([merged], ledger=seeded, when="2026-09-01T00:00:00Z")
    assert new_fp in out["items"]
    assert old_ip not in out["items"]
    assert old_host not in out["items"]
    got = out["items"][new_fp]
    assert got["poam_id"] == "EGP-OLDER0001"
    assert got["original_detection_date"] == "2026-01-01"
    assert "EGP-NEWER0002" in (got.get("aliased_poam_ids") or [])
    mapped_ids = {m.get("poam_id") for m in out["fp_migrations"]}
    assert "EGP-OLDER0001" in mapped_ids
    assert "EGP-NEWER0002" in mapped_ids
    assert any(
        m.get("poam_id") == "EGP-NEWER0002" and m.get("alias_of") == "EGP-OLDER0001"
        for m in out["fp_migrations"]
    )


def test_ega_merge_different_weaknesses_keep_both_ids() -> None:
    """Merged hosts with different weaknesses keep both EGP- IDs as separate items."""
    extra_smb = {"id": "42411", "tool": "nessus", "port": "445", "protocol": "tcp"}
    extra_ssl = {"id": "20007", "tool": "nessus", "port": "443", "protocol": "tcp"}
    ip_rec = _rec(assets=["10.0.0.30"], extra=dict(extra_smb), name="SMB shares")
    host_rec = _rec(assets=["web-01"], extra=dict(extra_ssl), name="SSL cert")
    assert weakness_key(ip_rec) != weakness_key(host_rec)
    old_smb = fp_v1(ip_rec, asset_key_fn=legacy_asset_id_port_key)
    old_ssl = fp_v1(host_rec, asset_key_fn=legacy_asset_id_port_key)

    seeded = empty_ledger()
    seeded["items"] = {
        old_smb: _seed_item(old_smb, "EGP-SMB000001", ip_rec, "2026-01-01", "2026-01-01T00:00:00Z"),
        old_ssl: _seed_item(old_ssl, "EGP-SSL000002", host_rec, "2026-02-01", "2026-02-01T00:00:00Z"),
    }

    aliases = {
        "asset_uid": "EGA-MERGED001",
        "ids": {"fqdn": "web-01.corp.local", "ip": ["10.0.0.30"], "hostname": "web-01"},
        "also_names": ["10.0.0.30", "web-01"],
    }
    merged_smb = _rec(assets=["web-01.corp.local"], extra={**extra_smb, **aliases}, name="SMB shares")
    merged_ssl = _rec(assets=["web-01.corp.local"], extra={**extra_ssl, **aliases}, name="SSL cert")
    out = _apply([merged_smb, merged_ssl], ledger=seeded, when="2026-09-01T00:00:00Z")
    ids = {i["poam_id"] for i in out["items"].values()}
    assert ids == {"EGP-SMB000001", "EGP-SSL000002"}
    assert len(out["items"]) == 2
    assert {i["original_detection_date"] for i in out["items"].values()} == {"2026-01-01", "2026-02-01"}


def test_ega_swap_rescan_is_idempotent_no_new_ids() -> None:
    """Rescan after the EGA- swap remints nothing — IDs and dates stay put."""
    extra = {"id": "42411", "tool": "nessus", "port": "445", "protocol": "tcp"}
    ip_rec = _rec(assets=["10.0.0.30"], extra=dict(extra), name="SMB shares")
    host_rec = _rec(assets=["web-01"], extra=dict(extra), name="SMB shares")
    old_ip = fp_v1(ip_rec, asset_key_fn=legacy_asset_id_port_key)
    old_host = fp_v1(host_rec, asset_key_fn=legacy_asset_id_port_key)
    seeded = empty_ledger()
    seeded["items"] = {
        old_ip: _seed_item(old_ip, "EGP-OLDER0001", ip_rec, "2026-01-01", "2026-01-01T00:00:00Z"),
        old_host: _seed_item(old_host, "EGP-NEWER0002", host_rec, "2026-06-01", "2026-06-01T00:00:00Z"),
    }
    merged = _rec(
        assets=["web-01.corp.local"],
        extra={
            **extra,
            "asset_uid": "EGA-MERGED001",
            "ids": {"fqdn": "web-01.corp.local", "ip": ["10.0.0.30"], "hostname": "web-01"},
            "also_names": ["10.0.0.30", "web-01"],
        },
        name="SMB shares",
    )
    first = _apply([merged], ledger=seeded, when="2026-09-01T00:00:00Z")
    new_fp = fp_v1(merged)
    pid = first["items"][new_fp]["poam_id"]
    odd = first["items"][new_fp]["original_detection_date"]
    mapped = list(first["fp_migrations"])

    second = _apply([merged], ledger=first, when="2026-09-02T00:00:00Z")
    assert set(second["items"]) == set(first["items"])
    assert second["items"][new_fp]["poam_id"] == pid == "EGP-OLDER0001"
    assert second["items"][new_fp]["original_detection_date"] == odd == "2026-01-01"
    assert {i["poam_id"] for i in second["items"].values()} == {pid}
    assert not any(e["kind"] == "created" for e in second["events"])
    assert {(m.get("from"), m.get("to"), m.get("poam_id")) for m in second["fp_migrations"]} == {
        (m.get("from"), m.get("to"), m.get("poam_id")) for m in mapped
    }


def test_existing_poam_csv_header_constant_unchanged() -> None:
    assert POAM_HEADER.startswith("weakness,asset,severity,framework_refs,recommended_fix,owner,due,status,estate")


def test_ledger_run_delta_counts_this_run_only() -> None:
    """EXECUTIVE one-liner: open includes pending when no plan_ids; new/reopened/closed are this-run events."""
    same_second = "2026-09-15T00:00:00Z"
    ledger = {
        "run_at": same_second,
        "items": {
            "a": {"status": "open", "poam_id": "EGP-A"},
            "b": {"status": "pending_verification", "poam_id": "EGP-B"},
            "c": {"status": "reopened", "poam_id": "EGP-C-R1"},
            "d": {"status": "closed", "poam_id": "EGP-D"},
        },
        "events": [
            {"at": same_second, "kind": "created"},
            {"at": same_second, "kind": "created"},
            {"at": same_second, "kind": "created"},
            {"at": same_second, "kind": "created"},
            {"at": same_second, "kind": "reopened"},
        ],
        "events_this_run": [
            {"at": same_second, "kind": "created"},
            {"at": same_second, "kind": "reopened"},
        ],
    }
    delta = ledger_run_delta(ledger)
    assert delta["open"] == 3
    assert delta["ledger_open"] == 3
    assert delta["new"] == 1
    assert delta["pending_verification"] == 1
    assert delta["reopened"] == 1
    assert delta["closed"] == 0


def test_ledger_run_delta_open_follows_plan_ids() -> None:
    """Headline open is poam.csv; ledger_open still counts excluded items."""
    ledger = {
        "run_at": "2026-09-15T00:00:00Z",
        "items": {
            "on-plan": {"status": "open", "poam_id": "EGP-PLAN"},
            "excluded": {"status": "open", "poam_id": "EGP-X"},
            "closed": {"status": "closed", "poam_id": "EGP-C"},
        },
        "events_this_run": [],
    }
    delta = ledger_run_delta(ledger, plan_ids={"EGP-PLAN"})
    assert delta["open"] == 1
    assert delta["ledger_open"] == 2


def test_ledger_run_delta_same_second_runs_do_not_inflate_new() -> None:
    """Back-to-back apply_ledger calls with the same run_at must not recount prior created events."""
    rec = _rec()
    cover = _rec(
        extra={"id": "B", "tool": "nessus", "port": "80", "protocol": "tcp"},
        name="other",
        ref_id="VULN-B",
    )
    first = _apply([rec], when="2026-09-10T00:00:00Z")
    assert ledger_run_delta(first)["new"] == 1
    second = _apply([rec, cover], ledger=first, when="2026-09-10T00:00:00Z")
    delta = ledger_run_delta(second)
    assert delta["new"] == 1
    assert delta["open"] == 2
    assert delta["ledger_open"] == 2
