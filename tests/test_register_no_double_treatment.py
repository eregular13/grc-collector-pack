"""No EGP/title-host appears as both mitigate and accept.

Collapsed pack_drop twins are merged_into:<survivor EGP> aliases, not
accepted risk. DEMO / farm / real samples. SAMPLE/DEMO/LAB != client KEEP.
Never POST /api/risks.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from collectors import identity_ad, inventory_nmap
from collectors.grc_loader import load
from shared.ciso_shape import (
    assert_count_consistency,
    assert_register_no_double_treatment,
    csv_rows,
)
from shared.egp_collapse import (
    MERGED_INTO_PREFIX,
    bind_alias_targets_to_ledger,
    is_merged_into_reason,
    merged_into_reason,
)
from shared.io_util import out_dir, write_canonical
from shared.poam_ledger import payload_sha256
from shared.schema import CISO_REF_MAX

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
COLLECTORS = (
    "collectors.cloud_prowler",
    "collectors.inventory_nmap",
    "collectors.vuln_scan",
    "collectors.host_wazuh",
    "collectors.identity_ad",
    "collectors.easm",
    "collectors.k8s_kubescape",
    "collectors.code_secrets",
    "collectors.saas_idp",
    "collectors.dns_email",
    "collectors.honeypot",
)


def _assert_register(out: Path, *, poam: int | None = None) -> dict:
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    counts = assert_count_consistency(out, summary)
    overlap = assert_register_no_double_treatment(out)
    scenarios = csv_rows(out / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    refs = [row["ref_id"] for row in scenarios]
    assert len(set(refs)) == len(refs)
    assert max(len(ref) for ref in refs) <= CISO_REF_MAX
    ctl = [row["ref_id"] for row in csv_rows(out / "ciso-assistant" / "applied_controls.csv")]
    assert len(set(ctl)) == len(ctl)
    if ctl:
        assert max(len(ref) for ref in ctl) <= CISO_REF_MAX
    assert overlap["mitigate"] == counts["mitigate"] == counts["poam"] - int(summary.get("pending_carried") or 0)
    assert overlap["accept"] == overlap["non_merged_excluded"]
    assert overlap["controls"] == overlap["mitigate"]
    if poam is not None:
        assert counts["poam"] == poam
    excluded = csv_rows(out / "poam" / "excluded.csv")
    merged = [row for row in excluded if is_merged_into_reason(str(row.get("excluded_reason") or ""))]
    for row in merged:
        assert str(row["excluded_reason"]).startswith(MERGED_INTO_PREFIX)
        assert str(row.get("superseded_by") or "").startswith("EGP-")
    for row in scenarios:
        assert (row.get("existing_controls") or "") == ""
    _assert_alias_targets_exist(out)
    return {**counts, **overlap, "summary": summary}


def _known_poam_ids(out: Path) -> set[str]:
    poam_ids = {
        str(row.get("poam_id") or "")
        for row in csv_rows(out / "poam" / "poam.csv")
        if row.get("poam_id")
    }
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    ledger_ids = {
        str(item.get("poam_id") or "")
        for item in (ledger.get("items") or {}).values()
        if item.get("poam_id")
    }
    ledger_ids.update(
        str(item.get("poam_id") or "")
        for item in (ledger.get("closed") or [])
        if item.get("poam_id")
    )
    return {pid for pid in (poam_ids | ledger_ids) if pid}


def _assert_alias_targets_exist(out: Path) -> dict[str, int]:
    """Every merged_into / superseded_by pointer must resolve to a live ID."""
    known = _known_poam_ids(out)
    excluded = csv_rows(out / "poam" / "excluded.csv")
    missing: list[tuple[str, str, str]] = []
    merged_n = 0
    superseded_n = 0
    for row in excluded:
        reason = str(row.get("excluded_reason") or "")
        ref = str(row.get("id") or row.get("finding_ref_id") or "")
        if is_merged_into_reason(reason):
            merged_n += 1
            target = reason[len(MERGED_INTO_PREFIX) :]
            if target not in known:
                missing.append((ref, "merged_into", target))
        target = str(row.get("superseded_by") or "").strip()
        if target:
            superseded_n += 1
            if target not in known:
                missing.append((ref, "superseded_by", target))
    assert not missing, (
        "alias target missing from poam.csv/ledger: " + "; ".join(
            f"{ref} {kind}={target}" for ref, kind, target in missing[:8]
        )
    )
    return {"merged": merged_n, "superseded_by": superseded_n, "known": len(known)}


def _legacy_remap_ledger(ledger: dict) -> dict:
    """Rewrite EGP IDs so they cannot match a first-seen content hash."""
    doc = json.loads(json.dumps(ledger))
    mapping: dict[str, str] = {}
    seq = 0

    def remap(pid: str) -> str:
        nonlocal seq
        text = str(pid or "")
        if not text.startswith("EGP-"):
            return text
        if text in mapping:
            return mapping[text]
        seq += 1
        mapping[text] = f"EGP-900{seq:07d}"
        return mapping[text]

    for item in (doc.get("items") or {}).values():
        if not isinstance(item, dict):
            continue
        item["poam_id"] = remap(str(item.get("poam_id") or ""))
        if item.get("prior_poam_id"):
            item["prior_poam_id"] = remap(str(item.get("prior_poam_id") or ""))
        aliases = item.get("aliased_poam_ids") or []
        if aliases:
            item["aliased_poam_ids"] = [remap(str(alias)) for alias in aliases]
    for item in doc.get("closed") or []:
        if isinstance(item, dict) and item.get("poam_id"):
            item["poam_id"] = remap(str(item.get("poam_id") or ""))
    for event in doc.get("events") or []:
        if not isinstance(event, dict):
            continue
        if event.get("poam_id"):
            event["poam_id"] = remap(str(event.get("poam_id") or ""))
        detail = event.get("detail")
        if isinstance(detail, dict):
            for key in ("prior_poam_id", "alias_poam_id"):
                if detail.get(key):
                    detail[key] = remap(str(detail.get(key) or ""))
    for row in doc.get("fp_migrations") or []:
        if isinstance(row, dict) and row.get("poam_id"):
            row["poam_id"] = remap(str(row.get("poam_id") or ""))
    doc["sha256"] = payload_sha256(doc)
    assert mapping, "farm ledger must contain EGP ids to remap"
    assert all(old != new for old, new in mapping.items())
    return doc


def test_demo_register_has_no_mitigate_accept_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    import importlib

    for name in COLLECTORS:
        importlib.import_module(name).main()
    load()
    report = _assert_register(tmp_path)
    assert not report["title_host_overlap"]
    assert not report["egp_overlap"]


def test_farm_register_has_no_mitigate_accept_overlap(tmp_path: Path) -> None:
    work = tmp_path / "farm-work"
    out = _run_farm_drop(work)
    report = _assert_register(out, poam=73)
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    open_items = [
        it for it in (ledger.get("items") or {}).values() if str(it.get("status") or "") != "closed"
    ]
    assert len(open_items) == 109
    telnet = [
        row
        for row in csv_rows(out / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
        if (row.get("name") or "") == "Telnet exposed"
    ]
    assert any(
        row.get("treatment") == "mitigate" and row.get("assets") == "telnet-legacy.corp.local"
        for row in telnet
    )
    assert all(row.get("treatment") != "accept" for row in telnet)
    assert report["merged_aliases"] >= 1
    assert not report["title_host_overlap"]
    assert not report["egp_overlap"]


def test_sample_to_sor_register_has_no_mitigate_accept_overlap(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "sample_to_sor.sh"
    work = tmp_path / "sample-work"
    proc = subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=False,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
            "DROPBOX_LIVE": "0",
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    report = _assert_register(work / "out")
    assert not report["title_host_overlap"]
    assert not report["egp_overlap"]


def test_real_sample_filesrv_writable_share_is_not_accepted_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fixtures/samples smbmap FILESRV C$ must not be mitigate+accept."""
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir()
    recs: list[dict] = []
    recs.extend(inventory_nmap.parse_file(SAMPLES / "smbmap.txt"))
    recs.extend(inventory_nmap.parse_file(SAMPLES / "nbtscan.txt"))
    recs.extend(identity_ad.parse_file(SAMPLES / "enum4linux" / "enum4linux-ng.json"))
    write_canonical("inventory-nmap", [r for r in recs if r.get("source") == "inventory-nmap"])
    write_canonical("identity-ad", [r for r in recs if r.get("source") == "identity-ad"])
    load()
    report = _assert_register(out_dir())
    scenarios = csv_rows(out_dir() / "ciso-assistant" / "risk_scenarios.csv", delimiter=";")
    writable = [
        row
        for row in scenarios
        if "writable smb share c$" in (row.get("name") or "").lower()
    ]
    assert writable, "real-sample smbmap must emit Writable SMB share C$ on FILESRV"
    assert all(row.get("treatment") == "mitigate" for row in writable), writable
    assert all((row.get("existing_controls") or "") == "" for row in writable)
    hosts = {(row.get("name") or "", row.get("assets") or "") for row in writable}
    assert len(hosts) == len(writable)
    assert not report["title_host_overlap"]
    assert not report["egp_overlap"]


def test_bind_alias_targets_uses_survivor_ledger_id() -> None:
    """merged_into and superseded_by follow the live ledger poam_id, not egp_id_for."""
    winner = {"ref_id": "NMAP-telnet-legacy-corp-local-23-tcp", "name": "Telnet exposed"}
    twin = {"ref_id": "NMAP-nmap-20-telnet-23", "name": "Telnet exposed"}
    port_only = {"ref_id": "NMAP-web-80-tcp", "name": "Open TCP/80 observed"}
    specific = {"ref_id": "NMAP-web-http-80", "name": "Open http on TCP/80"}
    content = "EGP-3ACA3100FE"
    legacy = "EGP-900D9358AC"
    http_content = "EGP-1111111111"
    http_legacy = "EGP-9000000002"
    pairs = [
        (winner, {"include": True, "reason": "severity_high_critical"}),
        (
            twin,
            {
                "include": False,
                "reason": merged_into_reason(content),
                "superseded_by": content,
                "superseded_by_ref": winner["ref_id"],
            },
        ),
        (specific, {"include": True, "reason": "severity_low"}),
        (
            port_only,
            {
                "include": False,
                "reason": "superseded_by_specific",
                "superseded_by": http_content,
                "superseded_by_ref": specific["ref_id"],
            },
        ),
    ]
    items = {
        winner["ref_id"]: {"poam_id": legacy},
        specific["ref_id"]: {"poam_id": http_legacy},
    }
    bind_alias_targets_to_ledger(pairs, lambda rec: items.get(str(rec.get("ref_id") or "")))
    assert pairs[1][1]["reason"] == merged_into_reason(legacy)
    assert pairs[1][1]["superseded_by"] == legacy
    assert pairs[3][1]["reason"] == "superseded_by_specific"
    assert pairs[3][1]["superseded_by"] == http_legacy


def _run_farm_drop(work: Path) -> Path:
    script = ROOT / "scripts" / "farm_drop_to_sor.sh"
    proc = subprocess.run(
        ["bash", str(script), "--work", str(work)],
        check=False,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "DRY_RUN": "1",
            "GRC_LIVE_SCAN": "0",
            "CISO_PUSH": "0",
            "RISKREADY_PUSH": "0",
            "DROPBOX_LIVE": "0",
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return work / "out"


def test_farm_upgraded_ledger_alias_targets_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Upgraded farm ledger: every merged_into / superseded_by target is live."""
    work = tmp_path / "farm-upgrade"
    out = _run_farm_drop(work)
    prior = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    remapped = _legacy_remap_ledger(prior)
    remapped_ids = {
        str(item.get("poam_id") or "")
        for item in (remapped.get("items") or {}).values()
        if str(item.get("poam_id") or "").startswith("EGP-900")
    }
    assert remapped_ids
    dest_in = work / "in"
    (dest_in / "poam").mkdir(parents=True, exist_ok=True)
    (dest_in / "poam" / "poam-ledger.json").write_text(
        json.dumps(remapped, indent=2) + "\n", encoding="utf-8"
    )
    monkeypatch.setenv("IN_DIR", str(dest_in))
    monkeypatch.setenv("OUT_DIR", str(out))
    load()
    report = _assert_register(out, poam=73)
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    open_items = [
        item
        for item in (ledger.get("items") or {}).values()
        if str(item.get("status") or "") != "closed"
    ]
    assert len(open_items) == 109
    assert report["mitigate"] == 73
    assert report["accept"] == 36
    assert report["merged_aliases"] == 65
    targets = _assert_alias_targets_exist(out)
    assert targets["merged"] == 65
    live_ids = _known_poam_ids(out)
    assert remapped_ids & live_ids, "upgrade must keep remapped legacy EGP ids"
    excluded = csv_rows(out / "poam" / "excluded.csv")
    merged_targets = {
        str(row.get("excluded_reason") or "")[len(MERGED_INTO_PREFIX) :]
        for row in excluded
        if is_merged_into_reason(str(row.get("excluded_reason") or ""))
    }
    assert merged_targets <= live_ids
    assert merged_targets & remapped_ids, merged_targets
    telnet = [
        row
        for row in excluded
        if "telnet" in str(row.get("weakness") or "").lower()
        and is_merged_into_reason(str(row.get("excluded_reason") or ""))
    ]
    assert telnet
    for row in telnet:
        target = str(row["excluded_reason"])[len(MERGED_INTO_PREFIX) :]
        assert target in remapped_ids | live_ids
        assert target == str(row.get("superseded_by") or "")
        assert target.startswith("EGP-900") or target in remapped_ids
