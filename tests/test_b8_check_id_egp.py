"""Argus B8: percentages / hostnames in titles must not remint EGP IDs."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from collectors import code_secrets, easm, host_wazuh, identity_ad
from shared.kev import KevCatalog
from shared.poam_ledger import apply_ledger, fp_v1, weakness_key

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _run(when: str) -> datetime:
    return datetime.fromisoformat(when.replace("Z", "+00:00"))


def _apply(findings, ledger=None, when="2026-09-10T00:00:00Z"):
    return apply_ledger(
        findings,
        catalog=_unevaluated(),
        run_at=_run(when),
        ledger_in=ledger,
        overrides={},
        prior_existed=True,
    )


def _intune_compliance():
    recs = host_wazuh.parse_file(DEMO / "mdm" / "intune-devices.json")
    enc = next(
        r
        for r in recs
        if r.get("kind") == "finding" and "encryption compliance" in str(r.get("name") or "")
    )
    return enc


def test_intune_encryption_pct_change_keeps_egp() -> None:
    """33.3% → 50.0% in the title keeps the same fingerprint and EGP- ID."""
    enc = _intune_compliance()
    assert enc["extra"].get("check_id") == "enc-compliance-intune"
    assert "33.3" in enc["name"]
    assert not weakness_key(enc).startswith("name:")
    assert "33.3" not in weakness_key(enc)

    first = _apply([enc], when="2026-09-01T00:00:00Z")
    fp = fp_v1(enc)
    assert fp in first["items"]
    pid = first["items"][fp]["poam_id"]

    changed = deepcopy(enc)
    changed["name"] = enc["name"].replace("33.3%", "50.0%")
    changed["description"] = enc["description"].replace("33.3%", "50.0%")
    changed["extra"] = {**enc["extra"], "encryption_pct": 50.0}
    assert "50.0" in changed["name"]
    assert fp_v1(changed) == fp

    second = _apply([changed], ledger=first, when="2026-10-01T00:00:00Z")
    assert fp in second["items"]
    assert second["items"][fp]["poam_id"] == pid
    assert second["items"][fp]["status"] != "pending_verification"
    assert not any(i.get("status") == "pending_verification" for i in second["items"].values())
    assert len(second["items"]) == 1


def test_pre_check_id_intune_ledger_migrates_egp() -> None:
    """A pre-B8 title-keyed Intune row keeps its EGP- after check_id is stamped."""
    enc = _intune_compliance()
    old = deepcopy(enc)
    old["extra"] = {k: v for k, v in enc["extra"].items() if k != "check_id"}
    old_fp = fp_v1(old)
    new_fp = fp_v1(enc)
    assert old_fp != new_fp
    assert "33.3" in weakness_key(old)

    seeded = _apply([old], when="2026-09-01T00:00:00Z")
    pid = seeded["items"][old_fp]["poam_id"]
    odd = seeded["items"][old_fp]["original_detection_date"]

    migrated = _apply([enc], ledger=seeded, when="2026-09-20T00:00:00Z")
    assert new_fp in migrated["items"]
    assert old_fp not in migrated["items"]
    got = migrated["items"][new_fp]
    assert got["poam_id"] == pid
    assert got["original_detection_date"] == odd
    assert got["status"] != "pending_verification"
    assert any(
        m.get("from") == old_fp and m.get("to") == new_fp and m.get("reason") == "title_to_check_id"
        for m in migrated["fp_migrations"]
    )


def test_title_keyed_families_stamp_stable_check_id() -> None:
    """secrets / easm / wazuh posture / identity no longer key on name:."""
    families = [
        host_wazuh.parse_file(DEMO / "mdm" / "intune-devices.json"),
        host_wazuh.parse_file(DEMO / "mdm" / "jamf-computers.json"),
        host_wazuh.parse_file(DEMO / "wazuh" / "agents.json"),
        host_wazuh.parse_file(DEMO / "wazuh" / "fleet.json"),
        easm.parse_file(DEMO / "easm" / "httpx.json"),
        easm.parse_file(DEMO / "easm" / "whatweb.json"),
        easm.parse_file(DEMO / "easm" / "ffuf.json"),
        code_secrets.parse_file(DEMO / "code" / "trufflehog.jsonl"),
        code_secrets.parse_file(DEMO / "code" / "gitleaks.json"),
        identity_ad.parse_file(DEMO / "identity" / "enum4linux-ng.txt"),
        identity_ad.parse_file(DEMO / "identity" / "bloodhound.json"),
        identity_ad.parse_file(DEMO / "identity" / "bloodhound-edges.json"),
    ]
    findings = [
        r
        for recs in families
        for r in recs
        if r.get("kind") == "finding"
        and not (r.get("extra") or {}).get("telemetry")
        and r.get("category") != "incident"
    ]
    assert findings
    missing = [
        (r.get("source"), r.get("name"), r.get("extra"))
        for r in findings
        if not str((r.get("extra") or {}).get("check_id") or "").strip()
    ]
    assert not missing, missing
    for rec in findings:
        wk = weakness_key(rec)
        assert not wk.startswith("name:"), (rec.get("name"), wk)
        assert "33.3" not in wk
        assert "50.0" not in wk


def test_repeating_admin_check_ids_keep_location_discriminator() -> None:
    """httpx-admin / whatweb-admin / path-exposure stay distinct across URLs."""
    httpx = [
        r
        for r in easm.parse_file(DEMO / "easm" / "httpx.json")
        + easm.parse_file(DEMO / "easm" / "httpx.jsonl")
        if r.get("kind") == "finding"
        and str((r.get("extra") or {}).get("check_id") or "") == "httpx-admin"
        and "admin.example.com" in (r.get("assets") or [])
    ]
    assert len(httpx) >= 2
    keys = {weakness_key(r) for r in httpx}
    assert len(keys) == len(httpx), keys
    assert all("url:" in weakness_key(r) or "path:" in weakness_key(r) for r in httpx)

    whatweb = [
        r
        for r in easm.parse_file(DEMO / "easm" / "whatweb.json")
        if r.get("kind") == "finding"
        and str((r.get("extra") or {}).get("check_id") or "") == "whatweb-admin"
    ]
    if len(whatweb) >= 2:
        assert len({weakness_key(r) for r in whatweb}) == len(whatweb)

    ffuf = [
        r
        for r in easm.parse_file(DEMO / "easm" / "ffuf.json")
        if r.get("kind") == "finding"
        and str((r.get("extra") or {}).get("check_id") or "").startswith("path-exposure")
    ]
    if len(ffuf) >= 2:
        assert len({weakness_key(r) for r in ffuf}) == len(ffuf)
