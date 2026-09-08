"""Parse honeypot_event.v1 file-drops (Palisade + Beelzebub). Parse-only. No live trap."""

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

BEELZEBUB_HONESTY = (
    "This is deception-sensor evidence / an agent-behavior signal. "
    "Beelzebub records session, command, and login activity only. "
    "Palisade stage-1/stage-2 do not apply; stage is null. "
    "This does not mean the network is compromised."
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
    "beelzebub.honeypot.v1",
}
_BEELZEBUB_EVENTS = frozenset({"login", "cmd", "command", "session", "auth", "authentication"})
_PALISADE_KEYS = ("trap_id", "canary", "conceal_detected", "level2_emitted")
_HONEYPOT_PARENTS = frozenset({"honeypot", "pack_drop", "honeypot_beelzebub"})
_ALIASES = (
    ("command", "cmd"),
    ("Command", "cmd"),
    ("remoteAddr", "src_ip"),
    ("RemoteAddr", "src_ip"),
    ("remote_addr", "src_ip"),
    ("DateTime", "ts"),
    ("datetime", "ts"),
    ("Protocol", "protocol"),
    ("User", "user"),
)


def honesty_text() -> str:
    return HONESTY


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _parse_stage(value: Any) -> int | None:
    """Honor explicit Palisade 1|2 only. Unknown / empty / null → None (fail-closed)."""
    if value is None:
        return None
    raw = str(value).strip().lower()
    if raw in {"", "null", "none", "nil"}:
        return None
    raw = raw.replace("stage", "").replace("-", "").replace("_", "")
    if raw in {"2", "ii"}:
        return 2
    if raw in {"1", "i"}:
        return 1
    try:
        n = int(raw)
    except ValueError:
        return None
    if n >= 2:
        return 2
    if n == 1:
        return 1
    return None


def _is_palisade(row: dict[str, Any]) -> bool:
    src = str(row.get("source") or row.get("sensor") or row.get("family") or "").lower()
    if "palisade" in src or src == "fleet-sensor" or "fleet-sensor" in src:
        return True
    if row.get("trap_id") not in (None, ""):
        return True
    if row.get("canary") not in (None, ""):
        return True
    if "conceal_detected" in row or "level2_emitted" in row:
        return True
    return False


def _is_beelzebub(path: Path, row: dict[str, Any]) -> bool:
    src = str(row.get("source") or row.get("sensor") or row.get("family") or "").lower()
    if "beelzebub" in src:
        return True
    parts = {p.lower() for p in path.parts}
    if "honeypot_beelzebub" in parts or "beelzebub" in parts:
        return True
    ev = str(row.get("event") or row.get("type") or "").strip().lower()
    if ev in _BEELZEBUB_EVENTS and not _is_palisade(row):
        return True
    return False


def _family(path: Path, row: dict[str, Any]) -> str:
    if _is_beelzebub(path, row):
        return "beelzebub"
    if _is_palisade(row):
        return "palisade"
    return "honeypot"


def _stage_for(row: dict[str, Any], family: str) -> int | None:
    """Palisade may emit 1|2. Beelzebub and unknown families stay null (fail-closed)."""
    if family == "beelzebub":
        return None
    parsed = _parse_stage(row.get("stage"))
    if parsed is not None and family == "palisade":
        return parsed
    if family == "palisade":
        return 1
    return None


def _event_kind(row: dict[str, Any]) -> str:
    ev = str(row.get("event") or row.get("type") or "").strip().lower()
    if ev in {"login", "auth", "authentication"}:
        return "login"
    if ev in {"cmd", "command"} or row.get("cmd") or row.get("command"):
        return "cmd"
    if ev == "session" or (row.get("session_summary") and not row.get("cmd") and not row.get("command")):
        return "session"
    if row.get("user") and not row.get("cmd") and not row.get("command"):
        return "login"
    return "event"


def _is_demo(path: Path, row: dict[str, Any]) -> bool:
    if row.get("demo") is True:
        return True
    if str(row.get("demo") or "").strip().lower() in {"1", "true", "yes"}:
        return True
    parts = {p.lower() for p in path.parts}
    return "fixtures" in parts and "demo" in parts


def _labels_for(path: Path, row: dict[str, Any], family: str, extra: list[str]) -> list[str]:
    labels = list(LABELS)
    if family == "beelzebub" and "beelzebub" not in labels:
        labels.append("beelzebub")
    if family == "palisade" and "palisade" not in labels:
        labels.append("palisade")
    for item in extra:
        if item and item not in labels:
            labels.append(item)
    if _is_demo(path, row) and "demo" not in labels:
        labels.append("demo")
    return labels


def looks_like_honeypot_row(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    schema = str(row.get("schema") or row.get("kind") or "").strip().lower()
    if schema in _META_SCHEMAS or schema.startswith("honeypot") or "honeypot_event" in schema:
        return True
    if "beelzebub" in schema or "beelzebub" in str(row.get("source") or "").lower():
        return True
    ev = str(row.get("event") or row.get("type") or "").strip().lower()
    if ev in _BEELZEBUB_EVENTS and row.get("session_id") not in (None, ""):
        return True
    hits = sum(1 for key in _EVENT_HINTS if row.get(key) not in (None, ""))
    return hits >= 2


def looks_like_honeypot_file(path: Path, raw: str) -> bool:
    name = path.name.lower()
    if name in {"events.jsonl", "sessions.jsonl", "meta.json"}:
        return True
    if path.parent.name.lower() in _HONEYPOT_PARENTS:
        stripped = raw.lstrip("\ufeff").lstrip()
        if not stripped:
            return False
        try:
            first = json.loads(stripped.splitlines()[0])
        except json.JSONDecodeError:
            return False
        return looks_like_honeypot_row(first) or (
            isinstance(first, dict)
            and str(first.get("sensor") or first.get("source") or "").lower()
            in {"honeypot", "beelzebub", "fleet-sensor", "palisade"}
        )
    return False


def _severity(stage: int | None, conceal: bool, level2: bool) -> str:
    if (stage is not None and stage >= 2) or conceal or level2:
        return "medium"
    return "low"


def _trap_name(row: dict[str, Any]) -> str:
    trap = str(row.get("trap_id") or row.get("canary") or "").strip()
    return trap or "honeypot-trap"


def _instance_name(row: dict[str, Any], family: str) -> str:
    if family == "palisade":
        return _trap_name(row)
    inst = str(row.get("instance") or row.get("service") or "").strip()
    if inst:
        return inst
    proto = str(row.get("protocol") or "").strip().lower()
    if family == "beelzebub":
        return f"beelzebub-{proto or 'ssh'}"
    return proto or "honeypot-sensor"


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for src, dest in _ALIASES:
        if out.get(dest) in (None, "") and out.get(src) not in (None, ""):
            out[dest] = out[src]
    return out


def _emit_instance_asset(
    records: list[dict],
    seen: set[str],
    now: str,
    path: Path,
    row: dict[str, Any],
    family: str,
) -> str:
    name = _instance_name(row, family)
    if name in seen:
        return name
    seen.add(name)
    extra: dict[str, Any] = {
        "asset_type": "PR",
        "sensor": "honeypot",
        "family": family,
        "honesty": "deception-sensor",
    }
    if family == "palisade":
        extra["trap_id"] = name
        extra["canary"] = str(row.get("canary") or "")
        desc = f"Deception-sensor trap {name} (not a compromised host). {HONESTY}"
    else:
        extra["instance"] = name
        proto = str(row.get("protocol") or "").strip()
        if proto:
            extra["protocol"] = proto
        desc = (
            f"Deception-sensor Beelzebub instance {name} "
            f"(not a compromised host, not a Palisade trap). {BEELZEBUB_HONESTY}"
            if family == "beelzebub"
            else f"Deception-sensor {name} (not a compromised host). {HONESTY}"
        )
    records.append(
        make_record(
            kind="asset",
            source=SOURCE,
            ref_id=make_ref(SOURCE, f"asset-{name}"),
            name=name,
            description=desc,
            severity="info",
            category="deception-sensor",
            assets=[name],
            labels=_labels_for(path, row, family, []),
            collected_at=now,
            extra=extra,
        )
    )
    return name


def _event_finding(
    now: str,
    path: Path,
    row: dict[str, Any],
    instance: str,
    family: str,
) -> dict[str, Any]:
    session = str(row.get("session_id") or "session")
    stage = _stage_for(row, family)
    event = _event_kind(row)
    cmd = str(row.get("cmd") or row.get("command") or "").strip()
    summary = str(row.get("session_summary") or "").strip()
    ts = str(row.get("ts") or row.get("timestamp") or now)
    extra: dict[str, Any] = {
        "session_id": session,
        "stage": stage,
        "event": event,
        "family": family,
        "cmd": cmd,
        "ts": ts,
        "src_ip": str(row.get("src_ip") or row.get("src") or row.get("remoteAddr") or ""),
        "honesty": "deception-sensor",
    }
    proto = str(row.get("protocol") or "").strip()
    if proto:
        extra["protocol"] = proto
    user = str(row.get("user") or "").strip()
    if user:
        extra["user"] = user
    extra_labels = [event] if event != "event" else []
    if family == "palisade":
        conceal = _truthy(row.get("conceal_detected"))
        level2 = _truthy(row.get("level2_emitted"))
        extra["trap_id"] = instance
        extra["conceal_detected"] = conceal
        extra["level2_emitted"] = level2
        extra["canary"] = str(row.get("canary") or "")
        title = f"Deception-sensor stage-{stage} hit on {instance}"
        bits = [HONESTY, f"session_id={session}.", f"stage={stage}."]
        if conceal:
            bits.append("conceal_detected=true (sensor hid the next stage).")
        if level2:
            bits.append("level2_emitted=true (stage-2 decoy presented).")
        extra_labels.append(f"stage-{stage}")
        severity = _severity(stage, conceal, level2)
        ref = f"{instance}-{session}-s{stage}-{ts}-{cmd}"
    else:
        title = f"Deception-sensor {event} on {instance}"
        bits = [
            BEELZEBUB_HONESTY if family == "beelzebub" else HONESTY,
            f"session_id={session}.",
            "stage=null (Palisade stages do not apply)." if family == "beelzebub" else "stage=null.",
        ]
        extra["instance"] = instance
        severity = "low"
        ref = f"{instance}-{session}-{event}-{ts}-{cmd or user or event}"
    if cmd:
        bits.append(f"Observed command {cmd!r} (agent-behavior signal, not proof of control).")
    if user and event == "login":
        bits.append(f"Observed login user {user!r} (credential-guess signal, not a compromise).")
    if summary:
        bits.append(summary)
    return make_record(
        kind="finding",
        source=SOURCE,
        ref_id=make_ref(SOURCE, ref),
        name=title,
        description=" ".join(bits),
        severity=severity,
        category="deception-sensor",
        assets=[instance],
        labels=_labels_for(path, row, family, extra_labels),
        collected_at=now,
        extra=extra,
    )


def _session_finding(
    now: str,
    path: Path,
    row: dict[str, Any],
    instance: str,
    family: str,
) -> dict[str, Any]:
    session = str(row.get("session_id") or "session")
    stage = _stage_for(row, family)
    summary = str(row.get("session_summary") or "session closed")
    extra: dict[str, Any] = {
        "session_id": session,
        "stage": stage,
        "event": "session",
        "family": family,
        "session_summary": summary,
        "honesty": "deception-sensor",
    }
    extra_labels = ["session"]
    if family == "palisade":
        conceal = _truthy(row.get("conceal_detected"))
        level2 = _truthy(row.get("level2_emitted"))
        extra["trap_id"] = instance
        extra["conceal_detected"] = conceal
        extra["level2_emitted"] = level2
        honesty = HONESTY
        desc = (
            f"{honesty} session_id={session}. stage={stage}. {summary} "
            "Review the trap transcript as an agent-behavior signal."
        )
        extra_labels.append(f"stage-{stage}")
        severity = _severity(stage, conceal, level2)
    else:
        extra["instance"] = instance
        honesty = BEELZEBUB_HONESTY if family == "beelzebub" else HONESTY
        desc = (
            f"{honesty} session_id={session}. stage=null. {summary} "
            "Review the session transcript as an agent-behavior signal."
        )
        severity = "low"
    return make_record(
        kind="finding",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"{instance}-{session}-session"),
        name=f"Deception-sensor session {session} on {instance}",
        description=desc,
        severity=severity,
        category="deception-sensor",
        assets=[instance],
        labels=_labels_for(path, row, family, extra_labels),
        collected_at=now,
        extra=extra,
    )


def _meta_evidence(now: str, path: Path, row: dict[str, Any]) -> dict[str, Any]:
    sensor = str(row.get("source") or row.get("sensor") or "fleet-sensor")
    generated = str(row.get("generated_at") or row.get("ts") or now)
    family = _family(path, row)
    name = f"honeypot collector run ({sensor})"
    honesty = BEELZEBUB_HONESTY if family == "beelzebub" else HONESTY
    desc = (
        f"File-drop attestation from {sensor} at {generated}. "
        f"{honesty} Schema {row.get('schema') or 'honeypot.meta.v1'}."
    )
    extra = {"schema": str(row.get("schema") or ""), "sensor": sensor, "family": family}
    extra_labels = ["evidence"]
    if family == "beelzebub":
        extra_labels.append("beelzebub")
        desc += " Stages are Palisade-only; Beelzebub is session/deception evidence."
    return make_record(
        kind="evidence",
        source=SOURCE,
        ref_id=make_ref(SOURCE, f"evidence-{sensor}-{generated}"),
        name=name,
        description=desc,
        severity="info",
        category="deception-sensor",
        labels=_labels_for(path, row, family, extra_labels),
        collected_at=now,
        extra=extra,
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
    seen: set[str] = set()
    is_meta = name == "meta.json" or all(
        str(r.get("schema") or "").lower() in _META_SCHEMAS
        or (r.get("sensor") and not looks_like_honeypot_row(r))
        for r in rows
    )
    if is_meta and name == "meta.json":
        for row in rows:
            records.append(_meta_evidence(now, path, _normalize_row(row)))
        return records
    is_sessions = name == "sessions.jsonl" or all(
        r.get("session_summary") and not r.get("cmd") and not r.get("command") for r in rows
    )
    for row in rows:
        if not isinstance(row, dict):
            continue
        row = _normalize_row(row)
        schema = str(row.get("schema") or "").lower()
        if schema in _META_SCHEMAS and not looks_like_honeypot_row(row):
            records.append(_meta_evidence(now, path, row))
            continue
        if not looks_like_honeypot_row(row):
            continue
        family = _family(path, row)
        instance = _emit_instance_asset(records, seen, now, path, row, family)
        kind = _event_kind(row)
        if is_sessions or kind == "session" or (
            row.get("session_summary") and not row.get("cmd") and name != "events.jsonl"
        ):
            records.append(_session_finding(now, path, row, instance, family))
        elif looks_like_honeypot_row(row) or name == "events.jsonl":
            records.append(_event_finding(now, path, row, instance, family))
    return records
