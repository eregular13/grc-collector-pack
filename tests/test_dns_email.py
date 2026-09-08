"""DNS/email Seen collector: fixtures, honesty, live allowlist rails."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from collectors import dns_email
from shared.control_map import map_finding
from shared.dns_email import SOURCE, parse_file, parse_payload, parse_text
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo" / "dns_email"


def test_demo_fixtures_normalize() -> None:
    recs = parse_file(DEMO / "dns-txt.json")
    assets = [r for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    evidence = [r for r in recs if r["kind"] == "evidence"]
    names = {r["name"] for r in recs}
    assert any(r["name"] == "mail.example.invalid" for r in assets)
    assert any(r["name"] == "corp.example.invalid" for r in assets)
    assert any(r["category"] == "mail_org" for r in assets)
    assert any("DMARC missing" in r["name"] for r in findings)
    assert any("SPF +all" in r["name"] for r in findings)
    assert any("softfail" in r["name"] for r in findings)
    assert any("DKIM selector selector1 missing" in r["name"] for r in findings)
    assert evidence
    blob = str(recs).lower()
    assert "not a breach" in blob
    assert "compromised" not in blob
    assert all("Seen" in r["description"] for r in findings)
    assert SOURCE == "dns-email"
    assert names


def test_missing_dmarc_is_control_gap_not_breach() -> None:
    recs = parse_file(DEMO / "dns-txt.json")
    gap = next(r for r in recs if r["kind"] == "finding" and "DMARC missing" in r["name"])
    assert gap["severity"] == "medium"
    assert gap["category"] == "control-gap"
    assert gap["extra"].get("finding_id") == "dmarc_missing"
    assert "not a breach" in gap["description"]
    assert "control gap" in gap["description"].lower()
    mapped = map_finding(gap)
    assert mapped["include_poam"] is True
    assert "DMARC" in mapped["control_name"]
    assert "CVE-" not in mapped["recommended_fix"]
    assert "not a breach" in mapped["recommended_fix"]


def test_spf_maps() -> None:
    recs = parse_file(DEMO / "dns-txt.json")
    plus = next(r for r in recs if r["kind"] == "finding" and "SPF +all" in r["name"])
    soft = next(r for r in recs if r["kind"] == "finding" and "softfail" in r["name"])
    assert plus["severity"] == "high"
    assert map_finding(plus)["include_poam"] is True
    assert map_finding(soft)["include_poam"] is False
    assert "hygiene" in map_finding(soft)["recommended_fix"].lower() or "softfail" in map_finding(soft)["recommended_fix"].lower()


def test_crtsh_expired_cert_seen() -> None:
    recs = parse_file(DEMO / "crtsh.json")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    assert any("Expired certificate" in r["name"] for r in findings)
    assert any(r["kind"] == "evidence" for r in recs)
    blob = str(recs).lower()
    assert "not a breach" in blob
    assert "not a live" in blob


def test_openssl_text_pem_snapshot() -> None:
    recs = parse_file(DEMO / "cert-openssl.txt")
    assets = [r["name"] for r in recs if r["kind"] == "asset"]
    assert "vpn.example.invalid" in assets
    assert any(r["kind"] == "finding" and "Expired" in r["name"] for r in recs)


def test_empty_and_hostile_invent_nothing(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    assert parse_file(empty) == []
    trunc = tmp_path / "trunc.json"
    trunc.write_text('{"domains":[{"domain":', encoding="utf-8")
    assert parse_file(trunc) == []
    blank = tmp_path / "blank.txt"
    blank.write_text("\n", encoding="utf-8")
    assert parse_file(blank) == []
    assert parse_payload([]) == []
    assert parse_text("") == []


def test_checkdmarc_shape(tmp_path: Path) -> None:
    dest = tmp_path / "checkdmarc.json"
    dest.write_text(
        """{"domain":"ok.example.invalid","spf":{"record":"v=spf1 -all","valid":true},
        "dmarc":{"record":"v=DMARC1; p=reject;","valid":true},"mx":[{"hostname":"mx.ok.example.invalid"}]}""",
        encoding="utf-8",
    )
    recs = parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any(r["name"] == "ok.example.invalid" for r in recs if r["kind"] == "asset")
    assert not any("DMARC missing" in r["name"] for r in findings)
    assert not any("SPF +all" in r["name"] for r in findings)


def test_dig_transcript(tmp_path: Path) -> None:
    dest = tmp_path / "dig.txt"
    dest.write_text(
        "; <<>> DiG 9.18 <<>> TXT mail.example.invalid\n"
        "mail.example.invalid. 300 IN TXT \"v=spf1 -all\"\n"
        "_dmarc.mail.example.invalid. 300 IN TXT \"v=DMARC1; p=reject;\"\n"
        "mail.example.invalid. 300 IN MX 10 mx.mail.example.invalid.\n",
        encoding="utf-8",
    )
    recs = parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any(r["name"] == "mail.example.invalid" for r in recs if r["kind"] == "asset")
    assert not any("missing" in r["name"].lower() for r in findings)


def test_collector_parse_file_matches_shared() -> None:
    assert dns_email.parse_file(DEMO / "dns-txt.json") == parse_file(DEMO / "dns-txt.json")


def test_collector_has_no_live_imports() -> None:
    src = (ROOT / "collectors" / "dns_email.py").read_text(encoding="utf-8")
    assert "import shared.dns_email_live" not in src
    assert "from shared.dns_email_live" not in src
    assert "import dropbox" not in src
    assert "from dropbox" not in src
    assert "socket.socket" not in src
    assert "subprocess" not in src
    parser = (ROOT / "shared" / "dns_email.py").read_text(encoding="utf-8")
    assert "subprocess" not in parser
    assert "socket.socket" not in parser
    assert "import socket" not in parser


def test_live_offline_default() -> None:
    from shared.dns_email_live import main

    assert main([]) == 0


def test_live_requires_scope_and_allowlist(tmp_path: Path) -> None:
    from shared.dns_email_live import LiveRefuse, main, refuse_offscope, run_live

    with pytest.raises(SystemExit, match="requires --scope"):
        main(["--live"])
    att = tmp_path / "consent.md"
    att.write_text("dns-email live consent\n", encoding="utf-8")
    digest = hashlib.sha256(att.read_bytes()).hexdigest()
    scope = tmp_path / "SCOPE.yaml"
    scope.write_text(
        "client:\n  name: DEMO — dns-email live\nconsent:\n"
        f"  attestation_path: {att}\n  attestation_sha256: {digest}\n"
        "engagement:\n  start: 2026-09-01\n  end: 2026-12-31\n"
        "internal:\n  hosts:\n    - 127.0.0.1\n"
        "external:\n  hosts:\n    - vpn.example.com\n  domains:\n    - example.invalid\n"
        "allow_tools:\n  - dig\n",
        encoding="utf-8",
    )
    from dropbox.scope import load_scope

    loaded = load_scope(scope)
    refuse_offscope(loaded, "mail.example.invalid")
    with pytest.raises(LiveRefuse, match="not in SCOPE"):
        refuse_offscope(loaded, "evil.example.com")
    with pytest.raises(LiveRefuse, match="wildcard"):
        refuse_offscope(loaded, "*.example.invalid")
    dest = tmp_path / "out.json"
    if not Path("/usr/bin/dig").exists() and not Path("/bin/dig").exists():
        with pytest.raises(LiveRefuse, match="dig not on PATH|SCOPE"):
            run_live(scope_path=scope, domains=["evil.example.com"], dest=dest)
    else:
        with pytest.raises(LiveRefuse, match="not in SCOPE"):
            run_live(scope_path=scope, domains=["evil.example.com"], dest=dest)
    assert not dest.exists()


def test_load_inputs_falls_back_to_fixtures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from shared.io_util import load_inputs

    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-dns"))
    (tmp_path / "empty-dns" / "dns_email").mkdir(parents=True)
    files, demo = load_inputs("dns-email", (".json", ".jsonl", ".txt", ".pem"))
    assert demo is True
    names = {p.name for p in files}
    assert "dns-txt.json" in names
    assert "crtsh.json" in names


def _status_text() -> str:
    return (ROOT / "STATUS.md").read_text(encoding="utf-8")


def test_prove_bar_fixture_file_drop_writes_canonical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CoS prove bar: fixture file_drop → collector → out/canonical. SAMPLE ≠ client."""
    in_root = tmp_path / "in"
    lane = in_root / "dns_email"
    lane.mkdir(parents=True)
    for src in sorted(DEMO.iterdir()):
        if src.is_file():
            (lane / src.name).write_bytes(src.read_bytes())
    out_root = tmp_path / "out"
    out_root.mkdir()
    monkeypatch.setenv("IN_DIR", str(in_root))
    monkeypatch.setenv("OUT_DIR", str(out_root))
    monkeypatch.setenv("FIXTURES_DIR", str(ROOT / "fixtures" / "demo"))
    monkeypatch.setenv("CISO_PUSH", "0")
    monkeypatch.setenv("RISKREADY_PUSH", "0")
    monkeypatch.setenv("GRC_LIVE_SCAN", "0")
    monkeypatch.setenv("DRY_RUN", "1")
    dns_email.main()
    dest = out_root / "canonical" / "dns-email.jsonl"
    assert dest.is_file()
    rows = [json.loads(line) for line in dest.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(r["kind"] == "asset" for r in rows)
    assert any(r["kind"] == "finding" for r in rows)
    assert any(r["kind"] == "evidence" for r in rows)
    assert any("DMARC missing" in r["name"] for r in rows if r["kind"] == "finding")
    blob = dest.read_text(encoding="utf-8")
    assert "not a breach" in blob.lower()
    assert "/api/risks" not in blob
    collector = (ROOT / "collectors" / "dns_email.py").read_text(encoding="utf-8")
    assert "urllib" not in collector
    assert "requests" not in collector
    assert "/api/risks" not in collector
    status = _status_text()
    assert "paying_day: FAIL" in status
    assert "DEMO — not a client estate" in status
    assert "wrap: review-only" in status
    assert "argus_keep: SAMPLE/fixture KEEP ≠ client KEEP" in status


def test_prove_bar_empty_in_stamps_demo_not_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty in/dns_email/ falls back to fixtures and stamps demo — not a client estate."""
    in_root = tmp_path / "in"
    (in_root / "dns_email").mkdir(parents=True)
    out_root = tmp_path / "out"
    out_root.mkdir()
    monkeypatch.setenv("IN_DIR", str(in_root))
    monkeypatch.setenv("OUT_DIR", str(out_root))
    monkeypatch.setenv("FIXTURES_DIR", str(ROOT / "fixtures" / "demo"))
    dns_email.main()
    dest = out_root / "canonical" / "dns-email.jsonl"
    rows = [json.loads(line) for line in dest.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows
    assert all("demo" in (r.get("labels") or []) for r in rows)
    assert all("client" not in [str(x).lower() for x in (r.get("labels") or [])] for r in rows)
    status = _status_text()
    assert "paying_day: FAIL" in status
    assert "DEMO — not a client estate" in status


def test_control_map_dmarc_record() -> None:
    rec = make_record(
        kind="finding",
        source="dns-email",
        ref_id="DNS-x-dmarc",
        name="DMARC missing on mail.example.invalid",
        description="mail.example.invalid has no published _dmarc TXT policy. Control gap candidate.",
        severity="medium",
        category="control-gap",
        extra={"finding_id": "dmarc_missing"},
    )
    mapped = map_finding(rec)
    assert mapped["include_poam"] is True
    assert "breach" not in mapped["recommended_fix"].lower() or "not a breach" in mapped["recommended_fix"]
