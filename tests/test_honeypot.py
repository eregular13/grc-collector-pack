"""Honeypot file_drop: events → canonical records. Not a live trap."""

from __future__ import annotations

from pathlib import Path

from collectors import honeypot
from shared.control_map import map_finding
from shared.honeypot import HONESTY, parse_honeypot
from shared.io_util import load_inputs

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo" / "honeypot"


def test_in_honeypot_lane_exists() -> None:
    lane = ROOT / "in" / "honeypot"
    assert lane.is_dir()
    assert (lane / ".gitkeep").is_file()
    extras = [p for p in lane.iterdir() if p.name not in {".gitkeep", ".DS_Store"}]
    assert extras == [], extras


def test_events_normalize_to_assets_findings() -> None:
    recs = honeypot.parse_file(DEMO / "events.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    assert assets
    assert any(r["name"] == "ssh-canary-01" for r in assets)
    assert all("not a compromised host" in r["description"].lower() for r in assets)
    assert len(findings) == 2
    stages = {int((r.get("extra") or {}).get("stage") or 0) for r in findings}
    assert stages == {1, 2}
    for rec in findings:
        blob = f"{rec['name']} {rec['description']}".lower()
        assert "deception-sensor" in blob
        assert "agent-behavior" in blob.replace(" ", "-") or "agent-behavior" in blob
        assert "network is compromised" in rec["description"]
        assert "not" in rec["description"].lower()
        assert rec["severity"] in {"low", "medium"}
        assert rec["severity"] != "critical"
        assert rec["category"] == "deception-sensor"
        assert rec["source"] == "honeypot"
        assert rec["ref_id"].startswith("HPOT-")


def test_stage2_is_medium_not_compromise() -> None:
    recs = honeypot.parse_file(DEMO / "events.jsonl")
    stage2 = next(r for r in recs if r["kind"] == "finding" and (r.get("extra") or {}).get("stage") == 2)
    assert stage2["severity"] == "medium"
    assert (stage2.get("extra") or {}).get("conceal_detected") is True
    assert (stage2.get("extra") or {}).get("level2_emitted") is True
    mapped = map_finding(stage2)
    assert mapped["include_poam"] is False
    assert "deception-sensor" in mapped["recommended_fix"]
    assert "not a full control failure" in mapped["recommended_fix"]
    assert "network is compromised" in mapped["recommended_fix"]
    assert "CVE-" not in mapped["recommended_fix"]


def test_sessions_and_meta_evidence() -> None:
    sessions = honeypot.parse_file(DEMO / "sessions.jsonl")
    assert any(r["kind"] == "asset" for r in sessions)
    find = [r for r in sessions if r["kind"] == "finding"]
    assert find
    assert any("session" in r["name"].lower() for r in find)
    assert all(HONESTY.split(".")[0] in r["description"] for r in find)
    meta = honeypot.parse_file(DEMO / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    assert "fleet-sensor" in evid[0]["name"] or "fleet-sensor" in evid[0]["description"]
    assert "compromise" not in evid[0]["name"].lower()


def test_empty_honeypot_invents_nothing(tmp_path: Path) -> None:
    dest = tmp_path / "events.jsonl"
    dest.write_text("", encoding="utf-8")
    assert honeypot.parse_file(dest) == []
    dest.write_text("{}\n", encoding="utf-8")
    assert honeypot.parse_file(dest) == []
    dest.write_text('{"hello":"world"}\n', encoding="utf-8")
    assert honeypot.parse_file(dest) == []


def test_honeypot_load_inputs_falls_back_to_fixtures(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty"))
    (tmp_path / "empty" / "honeypot").mkdir(parents=True)
    files, demo = load_inputs("honeypot", (".jsonl", ".json"))
    assert demo is True
    names = {p.name for p in files}
    assert "events.jsonl" in names
    assert "sessions.jsonl" in names
    assert "meta.json" in names


def test_honeypot_collector_no_live() -> None:
    for rel in ("collectors/honeypot.py", "shared/honeypot.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "import subprocess" not in src
        assert "Popen" not in src
        assert "socket.socket" not in src
        assert "urllib.request" not in src
        assert "http.client" not in src
        assert "/api/risks" not in src


def test_parse_honeypot_none_for_foreign_json(tmp_path: Path) -> None:
    dest = tmp_path / "hosts.json"
    dest.write_text('{"hosts":[{"ip":"10.0.0.1"}]}\n', encoding="utf-8")
    assert parse_honeypot(dest, dest.read_text(encoding="utf-8"), "2026-09-08T00:00:00Z") is None
