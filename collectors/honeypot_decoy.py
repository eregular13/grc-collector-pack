"""Honeypot / decoy file_drop. Parse only. Never scan. Never claim control OE."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.io_util import discover_input_files, emit
from shared.schema import asset, control_extra, evidence, finding

SOURCE = "honeypot"
PREFIX = "HPOT-"
HONESTY = "honeypot validated ≠ surface map ≠ control operating effectiveness"
LABELS = ["honeypot_validated", "not_control_oe", "not_surface_map"]


def _text(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    return str(value).strip()


def _port(value: Any, default: int | None = None) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if 1 <= n <= 65535:
        return n
    return default


def _is_event_v1(item: dict[str, Any]) -> bool:
    return _text(item.get("schema")) == "honeypot_event.v1"


def _is_session_v1(item: dict[str, Any]) -> bool:
    return _text(item.get("schema")) == "session_summary.v1"


def _is_dd_honeypot(item: dict[str, Any]) -> bool:
    return item.get("dd-honeypot") is True


def parse_event_v1(item: dict[str, Any]) -> dict[str, Any] | None:
    event_id = _text(item.get("event_id"))
    observed = _text(item.get("observed_at"))
    sensor_id = _text(item.get("sensor_id"))
    src_ip = _text(item.get("src_ip"))
    dst_ip = _text(item.get("dst_ip"))
    dst_port = _port(item.get("dst_port"))
    protocol = _text(item.get("protocol")).lower()
    action = _text(item.get("action")).lower()
    if not all((event_id, observed, sensor_id, src_ip, dst_ip, dst_port, protocol, action)):
        return None
    if protocol not in {"tcp", "udp", "icmp"}:
        return None
    if action not in {"connect", "banner", "auth_attempt", "payload", "close"}:
        return None
    rec = {
        "event_id": event_id,
        "observed_at": observed,
        "sensor_id": sensor_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port),
        "protocol": protocol,
        "action": action,
        "session_id": _text(item.get("session_id")) or event_id,
        "service": _text(item.get("service")) or protocol,
        "payload_sha256": _text(item.get("payload_sha256")),
    }
    return rec


def parse_session_v1(item: dict[str, Any]) -> dict[str, Any] | None:
    session_id = _text(item.get("session_id"))
    sensor_id = _text(item.get("sensor_id"))
    src_ip = _text(item.get("src_ip"))
    dst_port = _port(item.get("dst_port"))
    protocol = _text(item.get("protocol")).lower()
    if not all((session_id, sensor_id, src_ip, dst_port, protocol)):
        return None
    try:
        count = int(item.get("event_count") or 0)
    except (TypeError, ValueError):
        count = 0
    if count < 1:
        return None
    if protocol not in {"tcp", "udp", "icmp"}:
        return None
    return {
        "session_id": session_id,
        "sensor_id": sensor_id,
        "src_ip": src_ip,
        "dst_port": int(dst_port),
        "protocol": protocol,
        "event_count": count,
        "started_at": _text(item.get("started_at")),
        "ended_at": _text(item.get("ended_at")),
        "outcome": _text(item.get("outcome")),
        "first_action": _text(item.get("first_action")),
        "last_action": _text(item.get("last_action")),
        "dst_ip": _text(item.get("dst_ip")) or "decoy",
        "service": _text(item.get("service")) or protocol,
    }


def parse_dd_honeypot(item: dict[str, Any]) -> dict[str, Any] | None:
    """Thales dd-honeypot JSON line. Login dict may contain secrets — keep IP only."""
    login = item.get("login") if isinstance(item.get("login"), dict) else {}
    src_ip = _text(login.get("client_ip") or item.get("src_ip") or item.get("ip"))
    observed = _text(item.get("time") or item.get("observed_at"))
    session_id = _text(item.get("session-id") or item.get("session_id"))
    name = _text(item.get("name") or "dd-honeypot")
    if not src_ip or not observed:
        return None
    kind = _text(item.get("type") or "http").lower()
    service = "http" if kind in {"http", "https"} else kind or "http"
    dst_port = _port(item.get("dst_port") or item.get("port"), 8081)
    extra_login = {str(k).lower() for k in login} - {"client_ip", "ip", "src_ip"}
    action = "auth_attempt" if extra_login else "connect"
    event_id = session_id or f"{observed}-{src_ip}"
    return {
        "event_id": event_id,
        "observed_at": observed,
        "sensor_id": name,
        "src_ip": src_ip,
        "dst_ip": _text(item.get("dst_ip")) or "127.0.0.1",
        "dst_port": int(dst_port or 8081),
        "protocol": "tcp",
        "action": action,
        "session_id": session_id or event_id,
        "service": service,
        "payload_sha256": "",
    }


def _load_items(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            items.append(rec)
    if not items and raw.strip().startswith("{"):
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            return items
        if isinstance(rec, dict):
            items.append(rec)
        elif isinstance(rec, list):
            items.extend(x for x in rec if isinstance(x, dict))
    return items


def parse_files(files: list[Path]) -> list:
    events: list[dict[str, Any]] = []
    sessions: list[dict[str, Any]] = []
    for path in files:
        if not path.is_file() or path.name.startswith("."):
            continue
        for item in _load_items(path):
            if _is_event_v1(item):
                parsed = parse_event_v1(item)
                if parsed:
                    events.append(parsed)
                continue
            if _is_session_v1(item):
                parsed = parse_session_v1(item)
                if parsed:
                    sessions.append(parsed)
                continue
            if _is_dd_honeypot(item):
                parsed = parse_dd_honeypot(item)
                if parsed:
                    events.append(parsed)
    records = []
    sensors: set[str] = set()
    services: set[tuple[str, int, str]] = set()
    for row in events:
        sensors.add(row["sensor_id"])
        services.add((row["sensor_id"], row["dst_port"], row["protocol"]))
    for row in sessions:
        sensors.add(row["sensor_id"])
        services.add((row["sensor_id"], row["dst_port"], row["protocol"]))
    for sensor_id in sorted(sensors):
        records.append(
            asset(
                PREFIX,
                f"sensor-{sensor_id}",
                sensor_id,
                description=f"Decoy sensor {sensor_id}. {HONESTY}.",
                asset_type="SP",
                source=SOURCE,
                labels=list(LABELS),
                extra={"honesty": HONESTY, "role": "decoy_sensor"},
            )
        )
    for sensor_id, port, proto in sorted(services):
        name = f"{sensor_id}:{port}/{proto}"
        records.append(
            asset(
                PREFIX,
                f"svc-{sensor_id}-{port}-{proto}",
                name,
                description=f"Decoy service {name}. {HONESTY}.",
                asset_type="SP",
                source=SOURCE,
                labels=list(LABELS),
                extra={"honesty": HONESTY, "role": "decoy_service"},
            )
        )
    seen_sessions: set[str] = set()
    for row in sessions:
        sid = row["session_id"]
        if sid in seen_sessions:
            continue
        seen_sessions.add(sid)
        records.extend(_session_finding(row, event_count=row["event_count"]))
    for row in events:
        sid = row["session_id"]
        if sid in seen_sessions:
            continue
        seen_sessions.add(sid)
        records.extend(_session_finding(row, event_count=1))
    return records


def _session_finding(row: dict[str, Any], *, event_count: int) -> list:
    svc = f"{row.get('sensor_id')}:{row.get('dst_port')}/{row.get('protocol')}"
    action = _text(row.get("action") or row.get("last_action") or "connect")
    name = "Decoy session observed"
    if action == "auth_attempt":
        name = "Decoy auth attempt observed"
    desc = (
        f"{name} on {svc} from {row.get('src_ip')} "
        f"(events={event_count}). {HONESTY}. "
        "Do not file MFA, EDR, backup, or IR failure from this row."
    )
    blob = (name + " " + desc).lower()
    if any(tok in blob for tok in ("mfa failed", "edr failed", "backup failed")):
        return []
    extra = control_extra(
        "CTL-DECOY-REVIEW",
        "Review decoy alerts",
        category="process",
        csf_function="detect",
        description="Review honeypot/decoy sessions. Not a control operating-effectiveness test.",
    )
    extra["honesty"] = HONESTY
    extra["claim"] = "decoy_session_observed"
    extra["session_id"] = row.get("session_id")
    extra["src_ip"] = row.get("src_ip")
    extra["payload_sha256"] = row.get("payload_sha256") or ""
    return [
        finding(
            PREFIX,
            f"sess-{row.get('session_id')}",
            name,
            description=desc,
            severity="info",
            source=SOURCE,
            related_assets=[svc],
            labels=list(LABELS),
            extra=extra,
        )
    ]


def main() -> None:
    files = discover_input_files("honeypot")
    if not files:
        print("honeypot: no input files; skip (not a silent demo)")
        return
    records = parse_files(files)
    records.append(
        evidence(
            PREFIX,
            "DROP",
            "Honeypot file_drop parse",
            description=(
                "Parsed honeypot_event.v1 / session_summary.v1 and optional "
                "dd-honeypot JSONL. File_drop only. No live scan. "
                + HONESTY
            ),
            source=SOURCE,
        )
    )
    emit("honeypot", records, files)


if __name__ == "__main__":
    main()
