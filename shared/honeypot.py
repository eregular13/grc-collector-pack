"""Parse fleet-sensor honeypot_event.v1 file-drops. Parse-only. No live trap."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.schema import make_record, make_ref

SOURCE = "honeypot"
LABELS = ["honeypot", "deception-sensor"]

HONESTY = (
    "This is deception-sensor evidence / an agent-behavior signal. "
    "A honeypot stage hit is not a full control failure and does not mean "
    "the network is compromised."
)

_EVENT_HINTS = (
    "session_id",
    "trap_id",
    "conceal_detected",
    "level2_emitted",
    "canary",
    "session_summary",
)
_META_SCHEMAS = {
    "honeypot.meta.v1",
    "honeypot_event.v1",
    "fleet-sensor.honeypot.v1",
}


def honesty_text() -> str:
    return HONESTY


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _stage(value: Any) -> int:
    raw = str(value or "").strip().lower().replace("stage", "").replace("-", "").replace("_", "")
    if raw in {"2", "ii"}:
        return 2
    if raw in {"1", "i", ""}:
        return 1
    try:
        n = int(raw)
    except ValueError:
        return 1
    return 2 if n >= 2 else 1


def looks_like_honeypot_row(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    schema = str(row.get("schema") or row.get("kind") or "").strip().lower()
    if schema in _META_SCHEMAS or schema.startswith("honeypot") or "honeypot_event" in schema:
        return True
    hits = sum(1 for key in _EVENT_HINTS if row.get(key) not in (None, ""))
    return hits >= 2


def looks_like_honeypot_file(path: Path, raw: str) -> bool:
    name = path.name.lower()
    if name in {"events.jsonl", "sessions.jsonl", "meta.json"}:
        return True
    if path.parent.name.lower() in {"honeypot", "pack_drop"}:
        stripped = raw.lstrip("\ufeff").lstrip()
        if not stripped:
            return False
        try:
            first = json.loads(stripped.splitlines()[0])
        except json.JSONDecodeError:
            return False
        return looks_like_honeypot_row(first) or (
            isinstance(first, dict) and str(first.get("sensor") or "").lower() == "honeypot"
        )
    return False


def _severity(stage: int, conceal: bool, level2: bool) -> str:
    if stage >= 2 or conceal or level2:
        return "medium"
    return "low"


def _trap_name(row: dict[str, Any]) -> str:
    trap = str(row.get("trap_id") or row.get("canary") or "").strip()
    return trap or "honeypot-trap"


def _emit_trap_asset(records: list[dict], seen: set[str], now: str, row: dict[str, Any]) -> str:
    name = _trap_name(row)
    if name not in seen:
        seen.add(name)
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=(
                    f"Deception-sensor trap {name} (not a compromised host). {HONESTY}"
                ),
                severity="info",
                category="deception-sensor",
                assets=[name],
                labels=list(LABELS),
                collected_at=now,
                extra={
                    "asset_type": "PR",
                    "trap_id": name,
                    "canary": str(row.get("canary") or ""),
                    "sensor": "honeypot",
                },
            )
        )
    return name


def _event_finding(now: str, row: dict[str, Any], trap: str) -> dict[str, Any]:
    session = str(row.get("session_id") or "session")
    stage = _stage(row.get("stage"))
    conceal = _truthy(row.get("conceal_detected"))
    level2 = _truthy(row.get("level2_emitted"))
    cmd = str(row.get("cmd") or row.get("command") or "").strip()
    summary = str(row.get("session_summary") or "").strip()
    ts = str(row.get("ts") or row.get("timestamp") or now)
    title = f"Deception-sensor stage-{stage} hit on {trap}"
    bits = [
        HONESTY,
        f"session_id={session}.",
        f"stage={stage}.",
    ]
    if cmd:
        bits.append(f"Observed command {cmd!r} (agent-behavior signal, not proof of control).")
    if summary:
        bits.append(summary)
    if conceal:
        bits.append("conceal_detected=true (sensor hid the next stage).")
    if level2:
        bits.append("level2_emitted=true (stage-2 decoy presented).")
    extra = {
        "session_id": session,
        "stage": stage,
        "trap_id": trap,
        "conceal_detected": conceal,
        "level2_emitted": level2,
        "cmd": cmd,
        "ts": ts,
        "canary": str(row.get("canary") or ""),
        "src_ip": str(row.get("src_ip") or row.get("src") or ""),
        "honesty": "deception-sensor",
    }
    return make_record(
        kind="finding",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"{trap}-{session}-s{stage}-{ts}-{cmd}"),
        name=title,
        description=" ".join(bits),
        severity=_severity(stage, conceal, level2),
        category="deception-sensor",
        assets=[trap],
        labels=list(LABELS) + [f"stage-{stage}"],
        collected_at=now,
        extra=extra,
    )


def _session_finding(now: str, row: dict[str, Any], trap: str) -> dict[str, Any]:
    session = str(row.get("session_id") or "session")
    stage = _stage(row.get("stage"))
    conceal = _truthy(row.get("conceal_detected"))
    level2 = _truthy(row.get("level2_emitted"))
    summary = str(row.get("session_summary") or "session closed")
    title = f"Deception-sensor session {session} on {trap}"
    desc = (
        f"{HONESTY} session_id={session}. stage={stage}. {summary} "
        "Review the trap transcript as an agent-behavior signal."
    )
    return make_record(
        kind="finding",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"{trap}-{session}-session"),
        name=title,
        description=desc,
        severity=_severity(stage, conceal, level2),
        category="deception-sensor",
        assets=[trap],
        labels=list(LABELS) + ["session", f"stage-{stage}"],
        collected_at=now,
        extra={
            "session_id": session,
            "stage": stage,
            "trap_id": trap,
            "conceal_detected": conceal,
            "level2_emitted": level2,
            "session_summary": summary,
            "honesty": "deception-sensor",
        },
    )


def _meta_evidence(now: str, row: dict[str, Any]) -> dict[str, Any]:
    sensor = str(row.get("source") or row.get("sensor") or "fleet-sensor")
    generated = str(row.get("generated_at") or row.get("ts") or now)
    name = f"honeypot collector run ({sensor})"
    desc = (
        f"File-drop attestation from {sensor} at {generated}. "
        f"{HONESTY} Schema {row.get('schema') or 'honeypot.meta.v1'}."
    )
    return make_record(
        kind="evidence",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"evidence-{sensor}-{generated}"),
        name=name,
        description=desc,
        severity="info",
        category="deception-sensor",
        labels=list(LABELS) + ["evidence"],
        collected_at=now,
        extra={"schema": str(row.get("schema") or ""), "sensor": sensor},
    )


def _iter_rows(raw: str) -> list[dict[str, Any]]:
    text = raw.lstrip("\ufeff").strip()
    if not text:
        return []
    rows: list[dict[str, Any]] = []
    if text.startswith("{") or text.startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, list):
            rows.extend(r for r in payload if isinstance(r, dict))
            return rows
        if isinstance(payload, dict):
            for key in ("events", "sessions", "records", "items"):
                blob = payload.get(key)
                if isinstance(blob, list):
                    rows.extend(r for r in blob if isinstance(r, dict))
            if not rows:
                rows.append(payload)
            return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def parse_honeypot(path: Path, raw: str, now: str) -> list[dict[str, Any]] | None:
    """Return canonical records, [] if recognized-but-empty, or None if not this format."""
    if not looks_like_honeypot_file(path, raw) and not any(
        looks_like_honeypot_row(r) for r in _iter_rows(raw)[:3]
    ):
        return None
    rows = _iter_rows(raw)
    if not rows:
        return []
    name = path.name.lower()
    records: list[dict[str, Any]] = []
    seen_traps: set[str] = set()
    is_meta = name == "meta.json" or all(
        str(r.get("schema") or "").lower() in _META_SCHEMAS
        or (r.get("sensor") and not looks_like_honeypot_row(r))
        for r in rows
    )
    if is_meta and name == "meta.json":
        for row in rows:
            records.append(_meta_evidence(now, row))
        return records
    is_sessions = name == "sessions.jsonl" or all(
        r.get("session_summary") and not r.get("cmd") for r in rows
    )
    for row in rows:
        if not isinstance(row, dict):
            continue
        schema = str(row.get("schema") or "").lower()
        if schema in _META_SCHEMAS and not looks_like_honeypot_row(row):
            records.append(_meta_evidence(now, row))
            continue
        if not looks_like_honeypot_row(row):
            continue
        trap = _emit_trap_asset(records, seen_traps, now, row)
        if is_sessions or (row.get("session_summary") and not row.get("cmd") and name != "events.jsonl"):
            records.append(_session_finding(now, row, trap))
        elif looks_like_honeypot_row(row) or name == "events.jsonl":
            records.append(_event_finding(now, row, trap))
    return records
