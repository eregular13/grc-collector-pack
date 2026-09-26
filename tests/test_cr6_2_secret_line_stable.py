"""Argus CR6-2: secret-class IDs stay put when a line number moves.

Secrets with usable material key on rule + file + HMAC secret_hash.
Empty or redacted values keep line so two leaks stay two IDs.
#170 path/url split (httpx-admin root vs /login) and honeypot cmd
location stay. Client-facing CSVs omit secret_hash.

LAB/SAMPLE/DEMO ≠ client KEEP. No POST /api/risks.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from pathlib import Path

from collectors import code_secrets, easm
from shared.finding_types import (
    finding_identity,
    is_secret_finding,
    secret_material_hash,
    secret_material_usable,
    strip_secret_hash_from_key,
)
from shared.kev import KevCatalog
from shared.poam_ledger import (
    apply_ledger,
    empty_ledger,
    fingerprints_for,
    fp_v1,
    legacy_secret_line_weakness_key,
    payload_sha256,
    weakness_key,
)

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"
NOW = "2026-09-01T00:00:00Z"


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _run(when: str) -> datetime:
    return datetime.fromisoformat(when.replace("Z", "+00:00"))


def _apply(findings, ledger=None, when="2026-09-10T00:00:00Z", prior=True):
    return apply_ledger(
        findings,
        catalog=_unevaluated(),
        run_at=_run(when),
        ledger_in=ledger,
        overrides={},
        prior_existed=prior,
    )


def _gitleaks_findings():
    recs = code_secrets.parse_file(DEMO / "code" / "gitleaks.json")
    return [r for r in recs if r.get("kind") == "finding"]


def _demo_api_key():
    return next(
        r
        for r in _gitleaks_findings()
        if "services/payments/config.py" in (r.get("assets") or [])
    )


def test_gitleaks_line_move_keeps_egp_no_ghost() -> None:
    """Line 12 → 40, same rule/file/secret: same EGP, no pending ghost row."""
    rec = _demo_api_key()
    assert is_secret_finding(rec)
    assert rec["extra"].get("line") == 12
    assert rec["extra"].get("file") == "services/payments/config.py"
    assert rec["extra"].get("secret_hash")
    assert rec["extra"].get("secret_hash") == secret_material_hash("AKIAIOSFODNN7EXAMPLE")
    wk = weakness_key(rec)
    assert "line:" not in wk
    assert "secret_hash:" in wk
    assert "file:services/payments/config.py" in wk
    ident = finding_identity(rec)
    assert "line:" not in ident
    assert "secret_hash:" in ident

    first = _apply([rec], when="2026-09-01T00:00:00Z")
    fp = fp_v1(rec)
    assert fp in first["items"]
    pid = first["items"][fp]["poam_id"]

    moved = deepcopy(rec)
    moved["extra"] = {**rec["extra"], "line": 40}
    moved["description"] = rec["description"].replace(":12", ":40")
    assert moved["extra"]["line"] == 40
    assert fp_v1(moved) == fp
    assert weakness_key(moved) == wk

    second = _apply([moved], ledger=first, when="2026-10-01T00:00:00Z")
    assert fp in second["items"]
    assert second["items"][fp]["poam_id"] == pid
    assert second["items"][fp]["status"] != "pending_verification"
    assert not any(i.get("status") == "pending_verification" for i in second["items"].values())
    open_items = [
        i for i in second["items"].values() if str(i.get("status") or "") != "closed"
    ]
    assert len(open_items) == 1
    assert len(second["items"]) == 1
    created = [e for e in second.get("events_this_run") or [] if e.get("kind") == "created"]
    assert created == []


def test_gitleaks_two_files_same_rule_stay_split() -> None:
    recs = code_secrets.parse_file(
        # in-memory via tmp would need a file; synthesize extra on parsed row
        DEMO / "code" / "gitleaks.json"
    )
    base = next(r for r in recs if r.get("kind") == "finding")
    a = deepcopy(base)
    b = deepcopy(base)
    a["assets"] = ["services/payments/config.py"]
    b["assets"] = ["services/billing/config.py"]
    a["extra"] = {**base["extra"], "file": "services/payments/config.py"}
    b["extra"] = {**base["extra"], "file": "services/billing/config.py"}
    assert weakness_key(a) != weakness_key(b)
    assert fp_v1(a) != fp_v1(b)
    assert "file:services/payments/config.py" in weakness_key(a)
    assert "file:services/billing/config.py" in weakness_key(b)


def test_gitleaks_two_secrets_same_file_stay_split() -> None:
    rec = _demo_api_key()
    other = deepcopy(rec)
    other["extra"] = {
        **rec["extra"],
        "secret_hash": secret_material_hash("other-demo-secret-value"),
    }
    assert rec["extra"]["secret_hash"] != other["extra"]["secret_hash"]
    assert weakness_key(rec) != weakness_key(other)
    assert fp_v1(rec) != fp_v1(other)
    first = _apply([rec, other], when="2026-09-01T00:00:00Z")
    open_items = [
        i for i in first["items"].values() if str(i.get("status") or "") != "closed"
    ]
    assert len(open_items) == 2


def test_pre_cr6_2_line_keyed_secret_migrates_egp() -> None:
    """A master line-keyed gitleaks row keeps its EGP after file+hash stamp."""
    rec = _demo_api_key()
    old = deepcopy(rec)
    old["extra"] = {k: v for k, v in rec["extra"].items() if k not in ("secret_hash", "file")}
    assert old["extra"].get("line") == 12
    old_fp = fp_v1(old, weakness_key_fn=legacy_secret_line_weakness_key)
    new_fp = fp_v1(rec)
    assert old_fp != new_fp
    assert "line:12" in legacy_secret_line_weakness_key(old)
    assert old_fp in fingerprints_for(rec)

    seeded = empty_ledger()
    seeded["items"][old_fp] = {
        "poam_id": "EGP-SECRET12",
        "fp": old_fp,
        "source_family": "code",
        "weakness_key": legacy_secret_line_weakness_key(old),
        "asset_key": (rec.get("assets") or ["asset"])[0],
        "ref_id": rec.get("ref_id") or "",
        "name": rec.get("name") or "",
        "description": rec.get("description") or "",
        "original_detection_date": "2024-01-15",
        "first_seen": "2024-01-15T00:00:00Z",
        "status": "open",
        "severity": rec.get("severity") or "critical",
        "missed_covered_runs": 0,
        "kev_comments": [],
    }
    seeded["sha256"] = payload_sha256(seeded)

    migrated = _apply([rec], ledger=seeded, when="2026-09-20T00:00:00Z")
    assert new_fp in migrated["items"]
    assert old_fp not in migrated["items"]
    got = migrated["items"][new_fp]
    assert got["poam_id"] == "EGP-SECRET12"
    assert got["status"] != "pending_verification"
    assert not any(i.get("status") == "pending_verification" for i in migrated["items"].values())
    assert any(
        m.get("from") == old_fp
        and m.get("to") == new_fp
        and m.get("reason") == "secret_line_to_hash"
        for m in migrated["fp_migrations"]
    )


def test_secret_hash_never_stores_raw_secret() -> None:
    recs = code_secrets.parse_file(DEMO / "code" / "gitleaks.json")
    recs += code_secrets.parse_file(DEMO / "code" / "trufflehog.jsonl")
    blob = str(recs)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "super-secret-demo-value-not-real" not in blob
    assert "ghp_demoNotARealTokenValue0001" not in blob
    for rec in recs:
        extra = rec.get("extra") or {}
        for banned in ("Secret", "Match", "Raw", "RawV2", "Fingerprint"):
            assert banned not in extra
        if rec.get("kind") == "finding" and is_secret_finding(rec):
            assert extra.get("secret_hash")
            assert extra.get("file")


def test_httpx_admin_root_vs_login_still_split() -> None:
    """#170 location split must survive secret-class identity changes."""
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
    idents = {finding_identity(r) for r in httpx}
    assert len(keys) == len(httpx)
    assert len(idents) == len(httpx)
    assert all("url:" in weakness_key(r) or "path:" in weakness_key(r) for r in httpx)
    assert all(not is_secret_finding(r) for r in httpx)


def test_redacted_gitleaks_two_lines_stay_two_ids(tmp_path) -> None:
    """gitleaks --redact: same rule+file, lines 12 and 20 stay two EGPs."""
    dest = tmp_path / "gitleaks-redact.json"
    dest.write_text(
        """[{"RuleID":"generic-api-key","Description":"Generic API Key",
        "File":"app/config.py","Secret":"REDACTED","Match":"KEY=REDACTED","StartLine":12},
        {"RuleID":"generic-api-key","Description":"Generic API Key",
        "File":"app/config.py","Secret":"REDACTED","Match":"KEY=REDACTED","StartLine":20}]""",
        encoding="utf-8",
    )
    recs = [r for r in code_secrets.parse_file(dest) if r.get("kind") == "finding"]
    assert len(recs) == 2
    assert all(not (r.get("extra") or {}).get("secret_hash") for r in recs)
    assert all("line:" in weakness_key(r) for r in recs)
    assert weakness_key(recs[0]) != weakness_key(recs[1])
    first = _apply(recs, when="2026-09-01T00:00:00Z")
    open_items = [
        i for i in first["items"].values() if str(i.get("status") or "") != "closed"
    ]
    assert len(open_items) == 2
    assert {fp_v1(r) for r in recs} == {i["fp"] for i in open_items}


def test_redacted_gitleaks_upgrade_keeps_both_line_ids(tmp_path) -> None:
    """Master line-keyed redacted pair upgrades with 0 folds / 0 ghosts."""
    dest = tmp_path / "gitleaks-redact.json"
    dest.write_text(
        """[{"RuleID":"generic-api-key","File":"app/config.py",
        "Secret":"REDACTED","StartLine":12},
        {"RuleID":"generic-api-key","File":"app/config.py",
        "Secret":"REDACTED","StartLine":20}]""",
        encoding="utf-8",
    )
    recs = [r for r in code_secrets.parse_file(dest) if r.get("kind") == "finding"]
    a, b = recs
    old_a = deepcopy(a)
    old_b = deepcopy(b)
    old_a["extra"] = {k: v for k, v in a["extra"].items() if k not in ("secret_hash", "file")}
    old_b["extra"] = {k: v for k, v in b["extra"].items() if k not in ("secret_hash", "file")}
    seeded = empty_ledger()
    for rec, pid in ((old_a, "EGP-REDACT12"), (old_b, "EGP-REDACT20")):
        old_fp = fp_v1(rec, weakness_key_fn=legacy_secret_line_weakness_key)
        seeded["items"][old_fp] = {
            "poam_id": pid,
            "fp": old_fp,
            "source_family": "code",
            "weakness_key": legacy_secret_line_weakness_key(rec),
            "asset_key": (rec.get("assets") or ["asset"])[0],
            "ref_id": rec.get("ref_id") or "",
            "name": rec.get("name") or "",
            "description": rec.get("description") or "",
            "original_detection_date": "2024-01-15",
            "first_seen": "2024-01-15T00:00:00Z",
            "status": "open",
            "severity": "critical",
            "missed_covered_runs": 0,
            "kev_comments": [],
        }
    seeded["sha256"] = payload_sha256(seeded)
    out = _apply(recs, ledger=seeded, when="2026-09-20T00:00:00Z")
    open_items = [
        i for i in out["items"].values() if str(i.get("status") or "") != "closed"
    ]
    assert len(open_items) == 2
    ids = {i["poam_id"] for i in open_items}
    assert ids == {"EGP-REDACT12", "EGP-REDACT20"}
    assert not any(i.get("status") == "pending_verification" for i in out["items"].values())
    created = [e for e in out.get("events_this_run") or [] if e.get("kind") == "created"]
    assert created == []


def test_omitted_secret_two_lines_stay_two_ids(tmp_path) -> None:
    """No Secret/Match: same rule+file, two StartLines stay two EGPs."""
    dest = tmp_path / "gitleaks-nosecret.json"
    dest.write_text(
        """[{"RuleID":"generic-api-key","File":"app/config.py","StartLine":12},
        {"RuleID":"generic-api-key","File":"app/config.py","StartLine":20}]""",
        encoding="utf-8",
    )
    recs = [r for r in code_secrets.parse_file(dest) if r.get("kind") == "finding"]
    assert len(recs) == 2
    assert all(not (r.get("extra") or {}).get("secret_hash") for r in recs)
    assert "line:12" in weakness_key(recs[0]) or "line:12" in weakness_key(recs[1])
    assert weakness_key(recs[0]) != weakness_key(recs[1])
    first = _apply(recs, when="2026-09-01T00:00:00Z")
    open_items = [
        i for i in first["items"].values() if str(i.get("status") or "") != "closed"
    ]
    assert len(open_items) == 2


def test_secret_hash_is_keyed_not_unsalted_sha256() -> None:
    rec = _demo_api_key()
    hashed = rec["extra"]["secret_hash"]
    import hashlib

    unsalted = hashlib.sha256(b"AKIAIOSFODNN7EXAMPLE").hexdigest()[:16]
    assert hashed != unsalted
    assert hashed == secret_material_hash("AKIAIOSFODNN7EXAMPLE")
    assert not secret_material_usable("REDACTED")
    assert not secret_material_usable("****")
    assert not secret_material_usable("")
    assert secret_material_hash("REDACTED") == ""


def test_fedramp_csv_omits_secret_hash() -> None:
    rec = _demo_api_key()
    assert "secret_hash:" in weakness_key(rec)
    ledger = _apply([rec], when="2026-09-01T00:00:00Z")
    from shared.poam_fedramp import item_to_row

    item = next(iter(ledger["items"].values()))
    row = item_to_row(item)
    blob = ",".join(row)
    assert "secret_hash" not in blob.lower()
    assert strip_secret_hash_from_key(item["weakness_key"]) in row
    assert "secret_hash" not in strip_secret_hash_from_key(item["weakness_key"])


def test_honeypot_cmd_location_untouched() -> None:
    from collectors import honeypot

    recs = honeypot.parse_file(DEMO / "honeypot_beelzebub" / "events.jsonl")
    cmds = [
        r
        for r in recs
        if r.get("kind") == "finding" and (r.get("extra") or {}).get("event") == "cmd"
    ]
    wget = next(r for r in cmds if str((r.get("extra") or {}).get("cmd") or "").startswith("wget "))
    uname = next(r for r in cmds if str((r.get("extra") or {}).get("cmd") or "") == "uname -a")
    assert not is_secret_finding(wget)
    assert weakness_key(wget) != weakness_key(uname)
    assert "cmd:" in weakness_key(wget)
    assert "cmd:" in weakness_key(uname)
