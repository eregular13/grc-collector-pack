#!/usr/bin/env python3
"""Parse Wazuh/osquery JSON into coverage gaps + incidents."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, read_text, run_collector
from shared.schema import make_record, make_ref

SOURCE = "host-wazuh"
LABELS = ["wazuh", "host"]


def _agents(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [a for a in payload if isinstance(a, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("affected_items"), list):
        return [a for a in data["affected_items"] if isinstance(a, dict)]
    if isinstance(payload.get("agents"), list):
        return [a for a in payload["agents"] if isinstance(a, dict)]
    osq = payload.get("osquery")
    if isinstance(osq, list):
        out = []
        for row in osq:
            if not isinstance(row, dict):
                continue
            cols = row.get("columns") if isinstance(row.get("columns"), dict) else row
            name = cols.get("hostname") or cols.get("name") or row.get("hostname")
            if name:
                out.append({"name": name, "status": row.get("status") or "active", "ip": cols.get("local_hostname") or ""})
        return out
    hosts = payload.get("hosts")
    if isinstance(hosts, list):
        out = []
        for row in hosts:
            if not isinstance(row, dict):
                continue
            name = row.get("hostname") or row.get("computer_name") or row.get("display_name") or row.get("id")
            if not name:
                continue
            status = str(row.get("status") or "online").lower()
            if status in {"offline", "mia"}:
                status = "disconnected"
            out.append({"name": name, "status": status, "ip": row.get("primary_ip") or row.get("ip") or ""})
        return out
    return []


_LYNIS_BANG = re.compile(r"^!\s+(.+?)\s+\[([A-Z]+-\d+)\]\s*$")
_LYNIS_DAT = re.compile(r"^warning\[\]=([^|]+)\|(.+)$", re.I)
_LYNIS_HOST = re.compile(r"(?im)^(?:hostname\s*[:=]\s*|hostname\s+)(\S+)")


def parse_lynis_report(text: str, now: str) -> list[dict]:
    """Parse a Lynis report or report.dat. Warnings only. No invented hosts."""
    host = "lynis-host"
    mhost = _LYNIS_HOST.search(text)
    if mhost:
        host = mhost.group(1).strip().strip("\"'")
    warnings: list[tuple[str, str]] = []
    for line in text.splitlines():
        raw = line.strip()
        bang = _LYNIS_BANG.match(raw)
        if bang:
            warnings.append((bang.group(2), bang.group(1)))
            continue
        dat = _LYNIS_DAT.match(raw)
        if dat:
            warnings.append((dat.group(1).strip(), dat.group(2).strip()))
    if not warnings:
        return []
    records = [
        make_record(
            kind="asset",
            source=SOURCE,
            ref_id=make_ref(SOURCE, f"asset-{host}"),
            name=host,
            description=f"Lynis-audited host {host}",
            category="host",
            assets=[host],
            labels=LABELS + ["lynis"],
            collected_at=now,
            extra={"asset_type": "PR"},
        )
    ]
    seen: set[str] = set()
    for cid, title in warnings:
        key = f"{cid}-{host}"
        if key in seen:
            continue
        seen.add(key)
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"lynis-{key}"),
                name=f"Lynis {cid}: {title}",
                description=title,
                severity="high",
                category="host-posture",
                assets=[host],
                labels=LABELS + ["lynis"],
                collected_at=now,
                extra={"check_id": cid, "id": cid},
            )
        )
    return records


def parse_file(path: Path) -> list[dict]:
    if path.suffix.lower() in {".txt", ".log", ".dat"}:
        return parse_lynis_report(read_text(path), iso_now())
    payload = read_json(path)
    now = iso_now()
    records: list[dict] = []
    for agent in _agents(payload):
        name = str(agent.get("name") or agent.get("id") or "agent")
        status = str(agent.get("status") or "unknown").lower()
        ip = str(agent.get("ip") or "")
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=f"Wazuh agent {name} status={status} ip={ip}",
                category="host",
                assets=[name],
                labels=LABELS,
                collected_at=now,
                extra={"asset_type": "PR", "agent_status": status, "ip": ip},
            )
        )
        if status in {"disconnected", "never_connected", "pending"}:
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"coverage-{name}"),
                    name=f"Wazuh agent disconnected: {name}",
                    description=f"Endpoint {name} is {status}; coverage gap.",
                    severity="high",
                    category="coverage-gap",
                    assets=[name],
                    labels=LABELS + ["coverage"],
                    collected_at=now,
                    extra={"agent_status": status},
                )
            )
    alerts = []
    if isinstance(payload, dict):
        raw_alerts = payload.get("alerts") or payload.get("hits") or []
        if isinstance(raw_alerts, list):
            alerts = [a for a in raw_alerts if isinstance(a, dict)]
    for alert in alerts:
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
        aname = str(agent.get("name") or "unknown")
        title = str(rule.get("description") or alert.get("id") or "wazuh alert")
        records.append(
            make_record(
                kind="incident",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"inc-{alert.get('id', title)}"),
                name=title,
                description=title,
                severity=alert.get("severity") or ("high" if int(rule.get("level") or 0) >= 10 else "medium"),
                category="incident",
                assets=[aname],
                labels=LABELS + ["alert"],
                collected_at=now,
                extra={"rule_id": rule.get("id")},
            )
        )
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"alert-{alert.get('id', title)}"),
                name=title,
                description=title,
                severity=alert.get("severity") or "high",
                category="incident",
                assets=[aname],
                labels=LABELS + ["alert"],
                collected_at=now,
                extra={},
            )
        )
    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".txt", ".log", ".dat"), parse_file)


if __name__ == "__main__":
    main()
