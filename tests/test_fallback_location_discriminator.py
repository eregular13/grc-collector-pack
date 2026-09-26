"""Same-title fallback rows stay distinct when path/url/file/line/user/evidence differ.

Metis FOLLOW-UP from #161: DEMO easm "Exposed admin interface" on two URLs
must not share one EGP. Upgrade rematch: the sibling whose path/url/cmd
matches the stored row keeps the legacy EGP; others mint new IDs. Fall
back to first-in-record-order only when the stored row has no location.

LAB/SAMPLE/DEMO ≠ client KEEP. No POST /api/risks.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from shared.kev import KevCatalog
from shared.poam_ledger import (
    apply_ledger,
    empty_ledger,
    fingerprints_for,
    fp_v1,
    legacy_pre_location_weakness_key,
    payload_sha256,
    weakness_key,
)
from shared.schema import make_ref

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-01T00:00:00Z"


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _run(when: str) -> datetime:
    return datetime.fromisoformat(when.replace("Z", "+00:00"))


def _easm_admin(path: str, url: str, ref: str) -> dict:
    return {
        "kind": "finding",
        "source": "easm",
        "ref_id": make_ref("easm", ref),
        "name": "Exposed admin interface on admin.example.com",
        "description": f"admin.example.com presents {path or url}.",
        "severity": "high",
        "category": "exposure",
        "assets": ["admin.example.com"],
        "labels": ["easm", "admin-ui", "demo"],
        "collected_at": NOW,
        "extra": {"path": path, "url": url},
    }


def test_demo_exposed_admin_dual_url_keys_are_distinct() -> None:
    """DEMO httpx: /login and https://admin.example.com stay two weaknesses."""
    from collectors import easm

    recs = easm.parse_file(ROOT / "fixtures" / "demo" / "easm" / "httpx.json")
    recs += easm.parse_file(ROOT / "fixtures" / "demo" / "easm" / "httpx.jsonl")
    admins = [
        r
        for r in recs
        if r.get("kind") == "finding"
        and str(r.get("name") or "").startswith("Exposed admin interface on")
        and "admin.example.com" in (r.get("assets") or [])
    ]
    assert len(admins) >= 2, [r.get("ref_id") for r in admins]
    keys = {weakness_key(r) for r in admins}
    fps = {fp_v1(r) for r in admins}
    assert len(keys) == len(admins), keys
    assert len(fps) == len(admins)
    cores = {legacy_pre_location_weakness_key(r) for r in admins}
    assert len(cores) == 1, cores
    assert all("url:" in weakness_key(r) or "path:" in weakness_key(r) for r in admins)


def test_synthetic_nikto_same_title_different_urls() -> None:
    host = "legacy.corp.local"
    a = {
        "source": "vuln-scan",
        "name": "Retrieved access-control list",
        "assets": [host],
        "labels": ["nikto"],
        "extra": {
            "plugin_id": "001021",
            "url": f"https://{host}/admin/",
            "path": "/admin/",
            "tool": "nikto",
        },
    }
    b = {
        "source": "vuln-scan",
        "name": "Retrieved access-control list",
        "assets": [host],
        "labels": ["nikto"],
        "extra": {
            "plugin_id": "001021",
            "url": f"https://{host}/login",
            "path": "/login",
            "tool": "nikto",
        },
    }
    assert weakness_key(a) != weakness_key(b)
    assert legacy_pre_location_weakness_key(a) == legacy_pre_location_weakness_key(b)
    assert weakness_key(a).startswith("nikto:001021")


def test_synthetic_secret_two_files_without_rule_id() -> None:
    a = {
        "source": "code-secrets",
        "name": "Generic API key",
        "assets": ["repo"],
        "extra": {"file": "deploy.sh", "line": "12"},
    }
    b = {
        "source": "code-secrets",
        "name": "Generic API key",
        "assets": ["repo"],
        "extra": {"file": "ci.yml", "line": "4"},
    }
    assert weakness_key(a) != weakness_key(b)
    assert "file:deploy.sh" in weakness_key(a)
    assert "file:ci.yml" in weakness_key(b)
    assert legacy_pre_location_weakness_key(a) == legacy_pre_location_weakness_key(b)


def test_synthetic_ad_alice_vs_bob_on_domain_asset() -> None:
    domain = "corp.local"
    alice = {
        "source": "identity-ad",
        "name": "Kerberoastable account",
        "assets": [domain],
        "extra": {"user": "alice", "edge": "HasSPN"},
    }
    bob = {
        "source": "identity-ad",
        "name": "Kerberoastable account",
        "assets": [domain],
        "extra": {"user": "bob", "edge": "HasSPN"},
    }
    assert weakness_key(alice) != weakness_key(bob)
    assert "user:alice" in weakness_key(alice)
    assert "user:bob" in weakness_key(bob)


def test_synthetic_two_services_without_port() -> None:
    host = "app.corp.local"
    http = {
        "source": "inventory-nmap",
        "name": "Service exposed",
        "assets": [host],
        "extra": {"service": "http"},
    }
    ssh = {
        "source": "inventory-nmap",
        "name": "Service exposed",
        "assets": [host],
        "extra": {"service": "ssh"},
    }
    assert weakness_key(http) != weakness_key(ssh)
    assert "service:http" in weakness_key(http)
    assert "service:ssh" in weakness_key(ssh)


def _seed_pre_location(rec: dict, poam_id: str, **extra: object) -> tuple[dict, str]:
    old_fp = fp_v1(rec, weakness_key_fn=legacy_pre_location_weakness_key)
    seeded = empty_ledger()
    item = {
        "poam_id": poam_id,
        "fp": old_fp,
        "source_family": rec.get("source") or "easm",
        "weakness_key": legacy_pre_location_weakness_key(rec),
        "asset_key": (rec.get("assets") or ["asset"])[0],
        "ref_id": rec.get("ref_id") or "",
        "name": rec.get("name") or "",
        "original_detection_date": "2024-01-15",
        "first_seen": "2024-01-15T00:00:00Z",
        "status": "open",
        "severity": rec.get("severity") or "high",
        "missed_covered_runs": 0,
        "kev_comments": [],
    }
    item.update(extra)
    seeded["items"][old_fp] = item
    seeded["sha256"] = payload_sha256(seeded)
    return seeded, old_fp


def test_pre_location_upgrade_first_keeps_egp_siblings_mint_new() -> None:
    """No stored location: first URL keeps the #161 EGP; sibling mints new. No ghost."""
    login = _easm_admin("/login", "https://admin.example.com/login", "url-login")
    apex = _easm_admin(
        "https://admin.example.com", "https://admin.example.com", "url-apex"
    )
    assert weakness_key(login) != weakness_key(apex)
    seeded, old_fp = _seed_pre_location(login, "EGP-KEEPADMIN")
    assert old_fp == fp_v1(apex, weakness_key_fn=legacy_pre_location_weakness_key)
    out = apply_ledger(
        [login, apex],
        catalog=_unevaluated(),
        run_at=_run("2026-09-20T00:00:00Z"),
        ledger_in=seeded,
        prior_existed=True,
    )
    created = [e for e in out.get("events_this_run") or [] if e.get("kind") == "created"]
    open_items = [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]
    ids = {it["poam_id"] for it in open_items}
    assert "EGP-KEEPADMIN" in ids
    assert len(open_items) == 2
    assert len(created) == 1, [e.get("poam_id") for e in created]
    assert created[0]["poam_id"] != "EGP-KEEPADMIN"
    assert created[0]["poam_id"] in ids
    assert {it["poam_id"] for it in open_items if it["poam_id"] != "EGP-KEEPADMIN"} == {
        created[0]["poam_id"]
    }
    assert out["items"][fp_v1(login)]["poam_id"] == "EGP-KEEPADMIN"
    assert out["items"][fp_v1(apex)]["poam_id"] != "EGP-KEEPADMIN"
    fresh = apply_ledger(
        [login, apex],
        catalog=_unevaluated(),
        run_at=_run("2026-09-20T00:00:00Z"),
        ledger_in=empty_ledger(),
        prior_existed=False,
    )
    fresh_open = [
        it for it in fresh["items"].values() if str(it.get("status") or "") != "closed"
    ]
    assert len(fresh_open) == 2


def test_upgrade_demo_admin_root_keeps_egp_when_login_is_first() -> None:
    """DEMO: master EGP-513DC647D6 is the root URL, not /login (record order)."""
    from collectors import easm

    recs = easm.parse_file(ROOT / "fixtures" / "demo" / "easm" / "httpx.json")
    recs += easm.parse_file(ROOT / "fixtures" / "demo" / "easm" / "httpx.jsonl")
    admins = [
        r
        for r in recs
        if r.get("kind") == "finding"
        and str(r.get("name") or "").startswith("Exposed admin interface on")
        and "admin.example.com" in (r.get("assets") or [])
    ]
    login = next(
        r
        for r in admins
        if "/login" in str((r.get("extra") or {}).get("url") or "")
    )
    apex = next(
        r
        for r in admins
        if str((r.get("extra") or {}).get("url") or "").rstrip("/")
        == "https://admin.example.com"
    )
    assert weakness_key(login) != weakness_key(apex)
    old_fp = fp_v1(login, weakness_key_fn=legacy_pre_location_weakness_key)
    assert old_fp == fp_v1(apex, weakness_key_fn=legacy_pre_location_weakness_key)
    seeded, _ = _seed_pre_location(
        apex,
        "EGP-513DC647D6",
        description=apex["description"],
        url="https://admin.example.com",
        ref_id=apex["ref_id"],
        source_family="easm",
    )
    # File order: httpx.json /login first, then jsonl root URL.
    out = apply_ledger(
        [login, apex],
        catalog=_unevaluated(),
        run_at=_run("2026-09-20T00:00:00Z"),
        ledger_in=seeded,
        prior_existed=True,
    )
    created = [e for e in out.get("events_this_run") or [] if e.get("kind") == "created"]
    open_items = [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]
    assert len(open_items) == 2
    assert len(created) == 1
    assert out["items"][fp_v1(apex)]["poam_id"] == "EGP-513DC647D6"
    assert out["items"][fp_v1(login)]["poam_id"] != "EGP-513DC647D6"
    assert created[0]["poam_id"] == out["items"][fp_v1(login)]["poam_id"]
    assert "https://admin.example.com" in (out["items"][fp_v1(apex)].get("description") or "")
    assert "/login" in (out["items"][fp_v1(login)].get("description") or "")


def test_upgrade_farm_wget_keeps_egp_when_uname_is_first() -> None:
    """Farm Beelzebub: master EGP-8CDFC42465 is wget, not uname -a (record order)."""
    from collectors import honeypot

    recs = honeypot.parse_file(
        ROOT / "fixtures" / "demo" / "honeypot_beelzebub" / "events.jsonl"
    )
    cmds = [
        r
        for r in recs
        if r.get("kind") == "finding" and (r.get("extra") or {}).get("event") == "cmd"
    ]
    assert [str((r.get("extra") or {}).get("cmd") or "") for r in cmds][0] == "uname -a"
    wget = next(
        r
        for r in cmds
        if str((r.get("extra") or {}).get("cmd") or "").startswith("wget ")
    )
    uname = next(
        r for r in cmds if str((r.get("extra") or {}).get("cmd") or "") == "uname -a"
    )
    assert weakness_key(wget) != weakness_key(uname)
    old_fp = fp_v1(wget, weakness_key_fn=legacy_pre_location_weakness_key)
    assert old_fp == fp_v1(uname, weakness_key_fn=legacy_pre_location_weakness_key)
    seeded, _ = _seed_pre_location(
        wget,
        "EGP-8CDFC42465",
        description=wget["description"],
        cmd=str((wget.get("extra") or {}).get("cmd") or ""),
        source_family="honeypot",
        name=wget["name"],
        ref_id=wget["ref_id"],
        severity="low",
    )
    out = apply_ledger(
        cmds,
        catalog=_unevaluated(),
        run_at=_run("2026-09-20T00:00:00Z"),
        ledger_in=seeded,
        prior_existed=True,
    )
    created = [e for e in out.get("events_this_run") or [] if e.get("kind") == "created"]
    open_items = [
        it for it in out["items"].values() if str(it.get("status") or "") != "closed"
    ]
    assert len(open_items) == len(cmds)
    assert len(created) == len(cmds) - 1
    assert out["items"][fp_v1(wget)]["poam_id"] == "EGP-8CDFC42465"
    assert out["items"][fp_v1(uname)]["poam_id"] != "EGP-8CDFC42465"
    for rec in cmds:
        if rec is wget:
            continue
        assert out["items"][fp_v1(rec)]["poam_id"] != "EGP-8CDFC42465"
    assert "wget " in (out["items"][fp_v1(wget)].get("description") or "")
    assert "uname -a" in (out["items"][fp_v1(uname)].get("description") or "")


def test_cve_key_does_not_grow_file_location() -> None:
    rec = {
        "source": "vuln-scan",
        "name": "xz-utils supply chain backdoor",
        "assets": ["app:latest"],
        "labels": ["trivy"],
        "extra": {
            "cve": "CVE-2024-3094",
            "pkg": "xz-utils",
            "file": "liblzma.so",
            "class": "vuln",
            "tool": "trivy",
        },
    }
    assert weakness_key(rec) == "cve:CVE-2024-3094"
    assert weakness_key(rec) == legacy_pre_location_weakness_key(rec)
    assert any(
        fp == fp_v1(rec, weakness_key_fn=legacy_pre_location_weakness_key)
        for fp in fingerprints_for(rec)
    )

