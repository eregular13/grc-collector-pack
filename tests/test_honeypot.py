"""Honeypot file_drop: events → canonical records. Not a live trap."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from collectors import honeypot
from shared.control_map import map_finding
from shared.honeypot import BEELZEBUB_HONESTY, HONESTY, parse_honeypot
from shared.io_util import load_inputs

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo" / "honeypot"
BEEL = ROOT / "fixtures" / "demo" / "honeypot_beelzebub"


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


def test_beelzebub_fixture_does_not_invent_palisade_fields() -> None:
    blob = ""
    for name in ("events.jsonl", "sessions.jsonl", "meta.json"):
        text = (BEEL / name).read_text(encoding="utf-8")
        blob += text
        assert "trap_id" not in text
        assert "conceal_detected" not in text
        assert "level2_emitted" not in text
        assert "canary" not in text
        assert '"stage":1' not in text.replace(" ", "")
        assert '"stage":2' not in text.replace(" ", "")
    assert "beelzebub" in blob.lower()
    assert '"event":"login"' in blob.replace(" ", "")
    assert '"event":"cmd"' in blob.replace(" ", "")


def test_beelzebub_events_are_session_cmd_login_stage_null() -> None:
    recs = honeypot.parse_file(BEEL / "events.jsonl")
    assets = [r for r in recs if r["kind"] == "asset"]
    findings = [r for r in recs if r["kind"] == "finding"]
    assert assets
    assert any(r["name"] == "beelzebub-ssh" for r in assets)
    for rec in assets:
        extra = rec.get("extra") or {}
        assert "trap_id" not in extra
        assert extra.get("family") == "beelzebub"
        assert "not a palisade trap" in rec["description"].lower()
        assert "demo" in (rec.get("labels") or [])
        assert "beelzebub" in (rec.get("labels") or [])
    assert len(findings) == 4
    events = {(r.get("extra") or {}).get("event") for r in findings}
    assert events == {"login", "cmd"}
    for rec in findings:
        extra = rec.get("extra") or {}
        assert extra.get("stage") is None
        assert extra.get("family") == "beelzebub"
        assert "trap_id" not in extra
        assert "conceal_detected" not in extra
        assert "level2_emitted" not in extra
        labels = rec.get("labels") or []
        assert "stage-1" not in labels
        assert "stage-2" not in labels
        assert "demo" in labels
        assert rec["severity"] == "low"
        assert rec["category"] == "deception-sensor"
        assert rec["ref_id"].startswith("HPOT-")
        assert "stage-" not in rec["name"].lower()
        assert "stage=null" in rec["description"]
        assert "do not apply" in rec["description"].lower()
        assert "network is compromised" in rec["description"]
    assert any((r.get("extra") or {}).get("cmd") == "uname -a" for r in findings)
    mapped = map_finding(findings[0])
    assert mapped["include_poam"] is False


def test_beelzebub_ignores_stuffed_palisade_stage(tmp_path: Path) -> None:
    dest = tmp_path / "honeypot_beelzebub" / "events.jsonl"
    dest.parent.mkdir(parents=True)
    dest.write_text(
        json.dumps(
            {
                "schema": "honeypot_event.v1",
                "source": "beelzebub",
                "event": "cmd",
                "session_id": "bz-fake-stage",
                "cmd": "id",
                "stage": 2,
                "trap_id": "ssh-canary-01",
                "conceal_detected": True,
                "level2_emitted": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    recs = honeypot.parse_file(dest)
    find = next(r for r in recs if r["kind"] == "finding")
    extra = find.get("extra") or {}
    assert extra.get("stage") is None
    assert extra.get("family") == "beelzebub"
    assert "trap_id" not in extra
    assert "stage-2" not in (find.get("labels") or [])
    assert find["severity"] == "low"


def test_beelzebub_sessions_and_meta() -> None:
    sessions = honeypot.parse_file(BEEL / "sessions.jsonl")
    find = [r for r in sessions if r["kind"] == "finding"]
    assert find
    assert all((r.get("extra") or {}).get("stage") is None for r in find)
    assert all("trap_id" not in (r.get("extra") or {}) for r in find)
    assert any("session" in r["name"].lower() for r in find)
    assert all(BEELZEBUB_HONESTY.split(".")[0] in r["description"] for r in find)
    meta = honeypot.parse_file(BEEL / "meta.json")
    evid = [r for r in meta if r["kind"] == "evidence"]
    assert evid
    assert "beelzebub" in evid[0]["name"].lower() or "beelzebub" in evid[0]["description"].lower()
    assert "palisade-only" in evid[0]["description"].lower() or "palisade" in evid[0]["description"].lower()
    assert "demo" in (evid[0].get("labels") or [])
    assert (evid[0].get("extra") or {}).get("family") == "beelzebub"


def test_beelzebub_pack_drop_file_drop_to_canonical(tmp_path: Path, monkeypatch) -> None:
    """Prove bar: drop fixture on in/honeypot/pack_drop/ → collector → canonical + demo."""
    drop = tmp_path / "in" / "honeypot" / "pack_drop"
    drop.mkdir(parents=True)
    for name in ("events.jsonl", "sessions.jsonl", "meta.json"):
        shutil.copy(BEEL / name, drop / name)
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(out))
    honeypot.main()
    canon = out / "canonical" / "honeypot.jsonl"
    assert canon.is_file()
    recs = [json.loads(line) for line in canon.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert recs
    assert all("demo" in (r.get("labels") or []) for r in recs)
    kinds = {r["kind"] for r in recs}
    assert {"asset", "finding", "evidence"} <= kinds
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings
    for rec in findings:
        extra = rec.get("extra") or {}
        assert extra.get("stage") is None
        assert extra.get("family") == "beelzebub"
        assert "trap_id" not in extra
        assert "stage-1" not in (rec.get("labels") or [])
        assert "stage-2" not in (rec.get("labels") or [])
    assert any((r.get("extra") or {}).get("event") == "login" for r in findings)
    assert any((r.get("extra") or {}).get("event") == "cmd" for r in findings)
    assert any((r.get("extra") or {}).get("event") == "session" for r in findings)


def test_beelzebub_docs_name_palisade_only_stages() -> None:
    docs = (ROOT / "docs" / "HONEYPOT_BEELZEBUB.md").read_text(encoding="utf-8")
    assert "Palisade" in docs
    assert "Beelzebub" in docs
    assert "stage" in docs.lower()
    assert "in/honeypot/" in docs
    assert "null" in docs.lower()
    matrix = (ROOT / "docs" / "EVIDENCE_MATRIX.md").read_text(encoding="utf-8")
    assert "HONEYPOT_BEELZEBUB.md" in matrix
    assert "Palisade" in matrix
    yaml = (ROOT / "docs" / "evidence_matrix.yaml").read_text(encoding="utf-8")
    assert "Beelzebub" in yaml or "beelzebub" in yaml
