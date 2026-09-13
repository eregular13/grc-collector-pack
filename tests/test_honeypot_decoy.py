from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXT = ROOT / "tests" / "fixtures_realish" / "honeypot"


def test_parse_v1_events_and_sessions() -> None:
    from collectors.honeypot_decoy import parse_files

    recs = parse_files([FIXT / "events.jsonl", FIXT / "sessions.jsonl"])
    names = {r.name for r in recs}
    kinds = {r.kind for r in recs}
    assert "php_my_admin" in names
    assert "php_my_admin:8081/tcp" in names
    assert "Decoy session observed" in names or "Decoy auth attempt observed" in names
    assert "asset" in kinds
    assert "finding" in kinds
    findings = [r for r in recs if r.kind == "finding"]
    assert findings
    assert all(r.severity == "info" for r in findings)
    blob = " ".join(r.description.lower() for r in recs)
    assert "mfa failed" not in blob
    assert "edr failed" not in blob
    assert "operating effectiveness" in blob
    assert all("honeypot_validated" in r.labels for r in recs if r.kind in {"asset", "finding"})


def test_parse_dd_honeypot_skips_junk() -> None:
    from collectors.honeypot_decoy import parse_files

    recs = parse_files([FIXT / "dd-honeypot.jsonl"])
    findings = [r for r in recs if r.kind == "finding"]
    assert len(findings) == 1
    assert "172.26.0.1" in findings[0].description
    assert "password" not in findings[0].description.lower()
    assets = [r.name for r in recs if r.kind == "asset"]
    assert "php_my_admin" in assets


def test_skip_when_no_files(tmp_path, monkeypatch, capsys) -> None:
    from collectors import honeypot_decoy

    pack = tmp_path / "pack"
    (pack / "in" / "honeypot").mkdir(parents=True)
    (pack / "fixtures" / "demo" / "honeypot").mkdir(parents=True)
    monkeypatch.setenv("PACK_ROOT", str(pack))
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    honeypot_decoy.main()
    out = capsys.readouterr().out
    assert "skip" in out.lower()
    assert not (tmp_path / "out" / "canonical" / "honeypot.jsonl").is_file()


def test_infeed_prefers_in_honeypot(tmp_path, monkeypatch) -> None:
    from collectors.honeypot_decoy import parse_files
    from shared.io_util import discover_input_files

    pack = tmp_path / "pack"
    (pack / "in" / "honeypot").mkdir(parents=True)
    (pack / "fixtures" / "demo" / "honeypot").mkdir(parents=True)
    (pack / "in" / "honeypot" / "events.jsonl").write_bytes((FIXT / "events.jsonl").read_bytes())
    (pack / "fixtures" / "demo" / "honeypot" / "other.jsonl").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("PACK_ROOT", str(pack))
    files = discover_input_files("honeypot")
    assert [p.name for p in files] == ["events.jsonl"]
    recs = parse_files(files)
    assert any(r.name == "php_my_admin" for r in recs)


def test_honeypot_source_has_no_api_risks() -> None:
    text = (ROOT / "collectors" / "honeypot_decoy.py").read_text(encoding="utf-8")
    assert "/api/risks" not in text
    assert "urlopen" not in text
    assert "nmap" not in text.lower() or "never scan" in text.lower()


def test_honeypot_drop_doc() -> None:
    text = (ROOT / "docs" / "HONEYPOT_DROP.md").read_text(encoding="utf-8")
    assert "in/honeypot" in text
    assert "honeypot_event.v1" in text
    assert "192.168.10.0/24" in text
    assert "operating effectiveness" in text.lower()
    assert "/api/risks" in text
