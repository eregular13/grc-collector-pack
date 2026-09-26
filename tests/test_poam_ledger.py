"""Gap 3 §3.5 test cases (numbering maps 1:1) plus the name→asset-id+port migration map."""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path

from shared.asset_key import asset_key, legacy_asset_id_port_key, legacy_name_asset_key
from shared.ciso_shape import POAM_HEADER
from shared.kev import KevCatalog
from shared.poam_fedramp import FEDRAMP_OPEN_HEADERS
from shared.poam_ledger import (
    LEDGER_CHAIN_BROKEN,
    LEDGER_LOST,
    apply_ledger,
    assign_poam_id,
    empty_ledger,
    fan_out_instances,
    fp_v1,
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
    assert item2["status_date"] == "2026-09-12"
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
    fed = (out / "poam" / "poam_fedramp.csv").read_text(encoding="utf-8").splitlines()[0]
    assert tuple(fed.split(",")) == FEDRAMP_OPEN_HEADERS


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
