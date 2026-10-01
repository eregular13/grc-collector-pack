"""CR6-1: excluded ledger rows must not resurrect as open POA&M.

Argus cold-review-6: every excluded weakness was written to the ledger as
status:open with no exclusion marker. After the feed disappeared, the
pending-carry loop put those rows back on poam.csv (DEMO honeypot
ssh-canary ×3).

LAB/SAMPLE/DEMO ≠ client KEEP. No POST /api/risks. RiskReady stay-out.
"""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

import pytest

from collectors import inventory_nmap
from collectors.grc_loader import load
from shared.io_util import write_canonical
from shared.kev import KevCatalog
from shared.poam_ledger import apply_ledger, excluded_reason_for, item_is_excluded, fp_v1
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
NMAP_DROP = ROOT / "fixtures" / "pack_drop" / "nmap"

CANARY = "ssh-canary-01"
HPOT_ROWS = (
    (
        "HPOT-ssh-canary-01-sess-canary-001-s1-2026-09-08t00-01-00z-whoami",
        "Deception-sensor stage-1 hit on ssh-canary-01",
        "low",
    ),
    (
        "HPOT-ssh-canary-01-sess-canary-001-s2-2026-09-08t00-01-08z-cat-etc-passwd",
        "Deception-sensor stage-2 hit on ssh-canary-01",
        "medium",
    ),
    (
        "HPOT-ssh-canary-01-sess-canary-001-session",
        "Deception-sensor session sess-canary-001 on ssh-canary-01",
        "medium",
    ),
)


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _finding(**kwargs):
    extra = kwargs.pop("extra", {})
    defaults = dict(
        kind="finding",
        source=kwargs.pop("source", "inventory-nmap"),
        ref_id=kwargs.pop("ref_id", "NMAP-x"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", "finding"),
        severity=kwargs.pop("severity", "high"),
        category=kwargs.pop("category", "exposure"),
        assets=kwargs.pop("assets", ["demo-host"]),
        extra=extra,
    )
    defaults.update(kwargs)
    return make_record(**defaults)


def _honeypot(ref_id: str, name: str, severity: str) -> dict:
    return _finding(
        source="honeypot",
        ref_id=ref_id,
        name=name,
        description=(
            "This is deception-sensor evidence / an agent-behavior signal. "
            "A honeypot stage hit is not a full control failure."
        ),
        severity=severity,
        category="deception-sensor",
        assets=[CANARY],
        extra={"honesty": "deception-sensor", "tool": "palisade"},
    )


def _real_ssh() -> dict:
    return _finding(
        source="inventory-nmap",
        ref_id="NMAP-demo-host-22-tcp",
        name="SSH exposed",
        description="box has open TCP/22 (ssh).",
        severity="high",
        extra={"port": "22", "service": "ssh", "protocol": "tcp"},
    )


def _real_http() -> dict:
    return _finding(
        source="inventory-nmap",
        ref_id="NMAP-demo-host-80-tcp",
        name="HTTP exposed",
        description="box has open TCP/80.",
        severity="high",
        extra={"port": "80", "service": "http", "protocol": "tcp"},
    )


def test_excluded_reason_for_honeypot_info_telemetry_not_a_weakness() -> None:
    hpot = _honeypot(*HPOT_ROWS[0])
    assert excluded_reason_for(hpot) == "honeypot"
    info = _finding(
        ref_id="NMAP-info",
        name="Host discovered",
        severity="info",
        extra={"port": "80"},
    )
    assert excluded_reason_for(info) == "severity_info"
    telem = _finding(
        source="host-wazuh",
        ref_id="WAZ-alert-5710",
        name="sshd: authentication failed",
        severity="medium",
        category="telemetry",
        extra={"telemetry": True, "rule_id": "5710", "rule_level": 10},
    )
    assert excluded_reason_for(telem) == "telemetry"
    naw = _finding(
        source="cloud-prowler",
        ref_id="CLD-cost",
        name="unused eip",
        severity="low",
        extra={"not_a_weakness": True, "exclude_reason": "not_a_weakness"},
    )
    assert excluded_reason_for(naw) == "not_a_weakness"
    assert excluded_reason_for(_real_ssh()) == ""


def test_apply_ledger_persists_excluded_reason_on_honeypot() -> None:
    recs = [_honeypot(ref, name, sev) for ref, name, sev in HPOT_ROWS]
    ledger = apply_ledger(recs, catalog=_unevaluated())
    assert len(ledger["items"]) == 3
    for item in ledger["items"].values():
        assert item_is_excluded(item)
        assert item["excluded_reason"] == "honeypot"
        assert item["status"] == "open"


def test_dropped_honeypot_feed_does_not_resurrect_poam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    incoming = tmp_path / "in"
    outgoing = tmp_path / "out"
    incoming.mkdir()
    outgoing.mkdir()
    monkeypatch.setenv("IN_DIR", str(incoming))
    monkeypatch.setenv("OUT_DIR", str(outgoing))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "DEMO")
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)

    honeypots = [_honeypot(ref, name, sev) for ref, name, sev in HPOT_ROWS]
    write_canonical("inventory-nmap", [_real_ssh(), _real_http()])
    write_canonical("honeypot", honeypots)
    first = load()
    assert first["excluded"] >= 3
    poam1 = list(csv.DictReader((outgoing / "poam" / "poam.csv").open(encoding="utf-8")))
    excluded1 = list(
        csv.DictReader((outgoing / "poam" / "excluded.csv").open(encoding="utf-8"))
    )
    hpot_refs = {ref for ref, _name, _sev in HPOT_ROWS}
    assert hpot_refs <= {row["finding_ref_id"] for row in excluded1}
    assert not {row["finding_ref_id"] for row in poam1} & hpot_refs
    assert all("Deception-sensor" not in (row.get("weakness") or "") for row in poam1)
    assert all(CANARY not in (row.get("asset") or "") for row in poam1)
    ledger1 = json.loads((outgoing / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    hpot_items = [
        item
        for item in (ledger1.get("items") or {}).values()
        if str(item.get("ref_id") or "") in hpot_refs
    ]
    assert len(hpot_items) == 3
    assert all(item_is_excluded(item) and item["excluded_reason"] == "honeypot" for item in hpot_items)
    first_ids = {row["poam_id"] for row in poam1 if row.get("poam_id")}
    first_n = len(poam1)

    dest = incoming / "poam"
    dest.mkdir()
    shutil.copy(outgoing / "poam" / "poam-ledger.json", dest / "poam-ledger.json")
    (outgoing / "canonical" / "honeypot.jsonl").unlink()
    write_canonical("inventory-nmap", [_real_ssh()])

    second = load()
    poam2 = list(csv.DictReader((outgoing / "poam" / "poam.csv").open(encoding="utf-8")))
    refs2 = {row["finding_ref_id"] for row in poam2}
    names2 = " ".join(row.get("weakness") or "" for row in poam2)
    assert not refs2 & hpot_refs
    assert "Deception-sensor" not in names2
    assert CANARY not in " ".join(row.get("asset") or "" for row in poam2)
    assert "NMAP-demo-host-22-tcp" in refs2
    # The dropped real HTTP row is still an open weakness — carry is intact.
    assert "NMAP-demo-host-80-tcp" in refs2
    assert second.get("pending_carried") == 1
    assert len(poam2) == first_n
    assert first_ids <= {row["poam_id"] for row in poam2 if row.get("poam_id")}


def test_shared_egp_excluded_duplicate_does_not_mark_plan_item() -> None:
    """#180 fold: pack_drop duplicate + specific High share one EGP.

    The excluded duplicate must not stamp excluded_reason on the plan item.
    """
    specific = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-dc-445/tcp",
        "name": "SMB 445 exposed",
        "severity": "high",
        "category": "exposure",
        "assets": ["dc.corp.local"],
        "labels": ["nmap"],
        "extra": {
            "port": "445",
            "protocol": "tcp",
            "service": "microsoft-ds",
            "ip": "10.0.0.10",
            "check_id": "nmap-port-445/tcp",
            "tool": "nmap",
        },
    }
    duplicate = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-nmap-10-microsoftds-445",
        "name": "SMB 445 exposed",
        "severity": "info",
        "category": "exposure",
        "assets": ["dc.corp.local"],
        "labels": ["nmap", "covey"],
        "extra": {
            "port": "445",
            "protocol": "tcp",
            "service": "microsoft-ds",
            "ip": "10.0.0.10",
            "id": "nmap-10-microsoftds-445",
            "adapter": "nmap",
            "pack_drop": "covey",
        },
    }
    assert fp_v1(specific) == fp_v1(duplicate)
    ledger = apply_ledger([duplicate, specific], catalog=_unevaluated())
    assert len(ledger["items"]) == 1
    item = next(iter(ledger["items"].values()))
    assert not item_is_excluded(item), item.get("excluded_reason")
    assert item["excluded_reason"] == ""


def test_shared_egp_plan_item_carries_when_nmap_drops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    incoming = tmp_path / "in"
    outgoing = tmp_path / "out"
    incoming.mkdir()
    outgoing.mkdir()
    monkeypatch.setenv("IN_DIR", str(incoming))
    monkeypatch.setenv("OUT_DIR", str(outgoing))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "SAMPLE")
    monkeypatch.delenv("GRC_POAM_LIGHTER", raising=False)

    recs = []
    recs.extend(inventory_nmap.parse_file(NMAP_DROP / "assets.jsonl"))
    recs.extend(inventory_nmap.parse_file(NMAP_DROP / "findings.jsonl"))
    write_canonical("inventory-nmap", recs)
    first = load()
    poam1 = list(csv.DictReader((outgoing / "poam" / "poam.csv").open(encoding="utf-8")))
    plan_ids = {row["poam_id"] for row in poam1 if row.get("poam_id")}
    assert plan_ids
    ledger1 = json.loads((outgoing / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    marked_on_plan = [
        item
        for item in (ledger1.get("items") or {}).values()
        if str(item.get("poam_id") or "") in plan_ids and item_is_excluded(item)
    ]
    assert marked_on_plan == [], [
        (item.get("poam_id"), item.get("excluded_reason"), item.get("name"))
        for item in marked_on_plan
    ]
    assert first.get("pending_carried") == 0

    dest = incoming / "poam"
    dest.mkdir()
    shutil.copy(outgoing / "poam" / "poam-ledger.json", dest / "poam-ledger.json")
    (outgoing / "canonical" / "inventory-nmap.jsonl").unlink()
    write_canonical("honeypot", [_honeypot(*HPOT_ROWS[0])])
    second = load()
    poam2 = list(csv.DictReader((outgoing / "poam" / "poam.csv").open(encoding="utf-8")))
    plan2 = {row["poam_id"] for row in poam2 if row.get("poam_id")}
    missing = plan_ids - plan2
    assert not missing, missing
    assert second.get("pending_carried") == len(plan_ids)


def test_farm_dropped_nmap_keeps_all_plan_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Metis farm feed-drop: carried ledger + missing nmap must keep plan IDs."""
    from dropbox.orchestrator.ciso_path import run_ciso_path
    from scripts.prove_ciso import prove_ciso

    work = tmp_path / "farm"
    prove_ciso(dest=work)
    poam1 = list(csv.DictReader((work / "out" / "poam" / "poam.csv").open(encoding="utf-8")))
    plan_ids = {row["poam_id"] for row in poam1 if row.get("poam_id")}
    assert len(plan_ids) >= 70, len(plan_ids)
    ledger1 = json.loads((work / "out" / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    marked_on_plan = [
        item
        for item in (ledger1.get("items") or {}).values()
        if str(item.get("poam_id") or "") in plan_ids and item_is_excluded(item)
    ]
    assert marked_on_plan == [], [
        (item.get("poam_id"), item.get("excluded_reason"), item.get("name"))
        for item in marked_on_plan
    ]

    dest = work / "in" / "poam"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(work / "out" / "poam" / "poam-ledger.json", dest / "poam-ledger.json")
    nmap = work / "in" / "nmap"
    if nmap.exists():
        shutil.rmtree(nmap)
    canon = work / "out" / "canonical"
    if canon.exists():
        shutil.rmtree(canon)
    monkeypatch.setenv("IN_DIR", str(work / "in"))
    monkeypatch.setenv("OUT_DIR", str(work / "out"))
    run_ciso_path(work / "in", work / "out")
    poam2 = list(csv.DictReader((work / "out" / "poam" / "poam.csv").open(encoding="utf-8")))
    plan2 = {row["poam_id"] for row in poam2 if row.get("poam_id")}
    missing = plan_ids - plan2
    assert not missing, sorted(missing)
