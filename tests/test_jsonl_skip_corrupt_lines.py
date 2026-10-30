"""Corrupt middle JSONL lines are skipped and counted; good rows kept."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

from shared import io_util
from shared.io_util import JSONL_SKIPS, read_jsonl


def test_corrupt_middle_line_skipped_with_warning(tmp_path: Path) -> None:
    dest = tmp_path / "findings.jsonl"
    dest.write_text(
        json.dumps({"id": "a"})
        + "\n"
        + "{not-json\n"
        + json.dumps({"id": "c"})
        + "\n",
        encoding="utf-8",
    )
    JSONL_SKIPS.clear()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        rows = read_jsonl(dest)
    assert [r["id"] for r in rows] == ["a", "c"]
    assert JSONL_SKIPS[str(dest)] == [2]
    assert any("skipped 1 corrupt JSONL line" in str(w.message) for w in caught)


def test_nul_in_line_skipped(tmp_path: Path) -> None:
    dest = tmp_path / "rows.jsonl"
    dest.write_bytes(
        (json.dumps({"id": "ok"}) + "\n").encode()
        + b'{"id": "bad\x00"}\n'
        + (json.dumps({"id": "ok2"}) + "\n").encode()
    )
    JSONL_SKIPS.clear()
    rows = read_jsonl(dest)
    assert [r["id"] for r in rows] == ["ok", "ok2"]
    assert JSONL_SKIPS[str(dest)] == [2]


def test_run_collector_marks_partial_parse(tmp_path: Path, monkeypatch) -> None:
    sensor = tmp_path / "in" / "code"
    sensor.mkdir(parents=True)
    dest = sensor / "trufflehog.jsonl"
    dest.write_text(
        json.dumps({"id": "keep"}) + "\n" + "NOPE\n" + json.dumps({"id": "keep2"}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("OUT_DIR", str(tmp_path / "out"))
    (tmp_path / "out").mkdir()
    JSONL_SKIPS.clear()

    def parse_file(path: Path):
        rows = read_jsonl(path)
        return [{"kind": "finding", "id": r["id"], "name": r["id"]} for r in rows]

    # Use a source that maps to folder "code"
    recs = io_util.run_collector("code-secrets", [".jsonl"], parse_file)
    assert {r["id"] for r in recs} == {"keep", "keep2"}
    assert str(dest) not in JSONL_SKIPS  # popped after run_collector
    status_path = tmp_path / "out" / "status" / "code-secrets.json"
    if not status_path.is_file():
        # Older layout fallback
        candidates = list((tmp_path / "out").rglob("*code-secrets*"))
        status_path = next((c for c in candidates if c.suffix == ".json"), status_path)
    import json as _json
    status = _json.loads(status_path.read_text(encoding="utf-8"))
    issues = status.get("issues") or []
    assert any(i.get("status") == "partial_parse" for i in issues), status
    assert any("skipped 1 corrupt JSONL line" in str(i.get("reason")) for i in issues)
