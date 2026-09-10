"""Accept Covey pack_drop (assets.jsonl / findings.jsonl / meta.json / evidence/).

Thin adapter for the existing inventory-nmap lane. Parse-only. No scanner spawn.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from shared.schema import make_record, make_ref

PACK_DROP_NAMES = frozenset({"assets.jsonl", "findings.jsonl", "meta.json"})
PACK_DROP_SCHEMAS = {
    "covey.pack_drop.v1",
    "evergreen-covey.pack_drop.v1",
    "evergreen.pack_drop.v1",
    "pack_drop.v1",
}
KIND_ALIASES = {
    "host": "asset",
    "service": "finding",
    "observation": "finding",
    "asset": "asset",
    "finding": "finding",
    "evidence": "evidence",
    "incident": "incident",
}
EVIDENCE_DIR_NAMES = frozenset({"evidence", "pack_drop"})

HostEmitter = Callable[..., None]


def looks_like_pack_drop(path: Path, raw: str = "") -> bool:
    name = path.name.lower()
    if name in PACK_DROP_NAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if "pack_drop" in parts:
        return True
    if path.parent.name.lower() == "evidence":
        return True
    text = (raw or "").lstrip("\ufeff").lstrip()
    if not text:
        return False
    try:
        first = json.loads(text.splitlines()[0])
    except json.JSONDecodeError:
        return False
    if not isinstance(first, dict):
        return False
    schema = str(first.get("schema") or "").strip().lower()
    if schema in PACK_DROP_SCHEMAS:
        return True
    source = str(first.get("source") or "").strip().lower()
    if "covey" in source or source == "evergreen-covey":
        return True
    return False


def _iter_rows(raw: str) -> list[Any]:
    text = raw.lstrip("\ufeff").strip()
    if not text:
        return []
    if text.startswith("[") or (text.startswith("{") and "\n{" not in text and "\n[" not in text):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        else:
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict):
                if payload.get("kind"):
                    return [payload]
                for key in ("assets", "findings", "records", "items", "hosts"):
                    blob = payload.get(key)
                    if isinstance(blob, list) and blob and isinstance(blob[0], dict):
                        return blob
                return [payload]
    rows: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _row_address(row: dict[str, Any]) -> str:
    return str(row.get("ip") or row.get("addr") or row.get("address") or "").strip()


def _row_kind(row: dict[str, Any], default_kind: str) -> str:
    raw = str(row.get("kind") or default_kind).strip().lower()
    mapped = KIND_ALIASES.get(raw, default_kind)
    if mapped not in {"asset", "finding", "evidence", "incident"}:
        return default_kind
    return mapped


def _row_name(row: dict[str, Any], default_kind: str) -> str:
    port = row.get("port")
    addr = _row_address(row)
    titled = str(row.get("name") or row.get("title") or row.get("ref_id") or "").strip()
    if titled:
        return titled
    if port not in (None, "") and addr:
        proto = str(row.get("protocol") or "tcp").upper()
        svc = str(row.get("service") or "").strip()
        if svc:
            return f"Open {svc} on {proto}/{port} observed"
        return f"Open {proto}/{port} observed"
    if addr:
        return addr
    if default_kind == "finding":
        return "covey-observation"
    return "covey-row"


def _ports(row: dict[str, Any]) -> list[tuple[str, str]]:
    ports: list[tuple[str, str]] = []
    raw = row.get("ports") or []
    if not isinstance(raw, list):
        return ports
    for item in raw:
        if isinstance(item, dict):
            if str(item.get("state") or "open").lower() not in {"open", ""}:
                continue
            portid = str(item.get("port") or item.get("portid") or "").strip()
            if not portid:
                continue
            svc = str(item.get("service") or item.get("name") or "")
            ports.append((portid, svc))
        elif isinstance(item, (int, str)):
            ports.append((str(item), ""))
    extra_port = str(row.get("port") or row.get("portid") or "").strip()
    if extra_port and extra_port not in {p for p, _ in ports}:
        state = str(row.get("state") or "open").lower()
        if state in {"open", ""}:
            ports.append((extra_port, str(row.get("service") or "")))
    return ports


def _host_fields(row: dict[str, Any]) -> tuple[str, str, str]:
    addr = _row_address(row)
    hostname = str(
        row.get("hostname") or row.get("host") or (row.get("name") if not row.get("kind") else "")
        or ""
    ).strip()
    kind = str(row.get("kind") or "").strip().lower()
    if kind in {"asset", "host"}:
        hostname = str(row.get("hostname") or row.get("host") or row.get("name") or hostname).strip()
    name = hostname or addr or str(row.get("name") or "").strip() or "unknown-host"
    return name, addr, hostname


def _lift_record(
    row: dict[str, Any],
    now: str,
    *,
    source: str,
    labels: list[str],
    default_kind: str,
) -> dict[str, Any]:
    kind = _row_kind(row, default_kind)
    name = _row_name(row, kind)
    extra = row.get("extra") if isinstance(row.get("extra"), dict) else {}
    extra_out = dict(extra)
    extra_out.setdefault("pack_drop", "covey")
    for key in (
        "ip",
        "addr",
        "address",
        "hostname",
        "port",
        "service",
        "adapter",
        "lane",
        "claim",
        "protocol",
        "title",
        "community",
        "sysDescr",
        "sysdescr",
        "netbios_name",
        "nb_name",
    ):
        if row.get(key) not in (None, "") and key not in extra_out:
            extra_out[key] = str(row.get(key)) if key == "port" else row.get(key)
    if row.get("not_claimed") and "not_claimed" not in extra_out:
        extra_out["not_claimed"] = row.get("not_claimed")
    rec_labels = list(labels)
    for lab in row.get("labels") or []:
        if str(lab) and str(lab) not in rec_labels:
            rec_labels.append(str(lab))
    adapter = str(row.get("adapter") or "").strip()
    if adapter and adapter not in rec_labels:
        rec_labels.append(adapter)
    if "covey" not in rec_labels:
        rec_labels.append("covey")
    assets = row.get("assets") or []
    if not assets:
        host = str(row.get("hostname") or row.get("name") or row.get("ip") or row.get("address") or "")
        if host:
            assets = [host]
    key = str(row.get("ref_id") or row.get("id") or f"{kind}-{name}")
    return make_record(
        kind=kind,  # type: ignore[arg-type]
        source=source,
        ref_id=str(row.get("ref_id") or make_ref(source, key)),
        name=name,
        description=str(row.get("description") or row.get("summary") or name),
        severity=str(row.get("severity") or ("info" if kind == "asset" else "low")),
        category=str(row.get("category") or ("host" if kind == "asset" else "exposure")),
        assets=[str(a) for a in assets if a],
        labels=rec_labels,
        collected_at=str(row.get("collected_at") or now),
        extra=extra_out,
    )


def _meta_evidence(row: dict[str, Any], now: str, *, source: str, labels: list[str]) -> dict[str, Any]:
    adapter = str(row.get("adapter") or row.get("tool") or "nmap")
    generated = str(row.get("generated_at") or row.get("created_at") or row.get("ts") or now)
    schema = str(row.get("schema") or "covey.pack_drop.v1")
    honesty = row.get("honesty") if isinstance(row.get("honesty"), dict) else {}
    extra_labels = list(labels) + ["covey", "pack_drop"]
    if adapter and adapter not in extra_labels:
        extra_labels.append(adapter)
    return make_record(
        kind="evidence",
        source=source,
        ref_id=make_ref(source, f"covey-meta-{adapter}-{generated}"),
        name=f"Covey pack_drop ({adapter})",
        description=(
            f"Accepted evergreen-covey pack_drop {schema} ({adapter}) via in/nmap/ at {generated}. "
            "Parse-only file_drop into the existing inventory-nmap → CISO Assistant path. "
            "Not a live scan. SAMPLE/DEMO ≠ client."
        ),
        severity="info",
        category="pack_drop",
        labels=extra_labels,
        collected_at=now,
        extra={
            "schema": schema,
            "adapter": adapter,
            "lane": str(row.get("lane") or "nmap"),
            "source": str(row.get("source") or "evergreen-covey"),
            "demo": bool(row.get("demo")),
            "run_id": str(row.get("run_id") or ""),
            "honesty": honesty,
            "ingest": row.get("ingest") if isinstance(row.get("ingest"), dict) else {},
        },
    )


def _file_evidence(path: Path, now: str, *, source: str, labels: list[str]) -> dict[str, Any]:
    return make_record(
        kind="evidence",
        source=source,
        ref_id=make_ref(source, f"covey-evidence-{path.name}"),
        name=f"Covey pack_drop evidence {path.name}",
        description=(
            f"Evidence artifact {path.name} from Covey pack_drop evidence/ "
            "(file_drop; not a live scan)."
        ),
        severity="info",
        category="pack_drop",
        labels=list(labels) + ["covey", "evidence"],
        collected_at=now,
        extra={"artifact": path.name, "pack_drop": "covey"},
    )


def parse_pack_drop(
    path: Path,
    raw: str,
    now: str,
    *,
    source: str,
    labels: list[str],
    host_emitter: HostEmitter | None = None,
) -> list[dict[str, Any]] | None:
    """Return records if this is a Covey pack_drop file; None otherwise."""
    if not looks_like_pack_drop(path, raw):
        return None
    name = path.name.lower()
    parent = path.parent.name.lower()
    if parent == "evidence" and name not in PACK_DROP_NAMES:
        text = raw.lstrip("\ufeff").strip()
        if text and (text[0] in "{["):
            rows = _iter_rows(raw)
            recs = [
                _lift_record(r, now, source=source, labels=labels, default_kind="evidence")
                for r in rows
                if isinstance(r, dict) and (r.get("kind") == "evidence" or r.get("name"))
            ]
            if recs:
                return recs
        return [_file_evidence(path, now, source=source, labels=labels)]

    rows = _iter_rows(raw)
    if name == "meta.json":
        recs = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if not any(
                row.get(k)
                for k in ("schema", "adapter", "source", "generated_at", "created_at", "lane")
            ):
                continue
            recs.append(_meta_evidence(row, now, source=source, labels=labels))
        return recs

    records: list[dict[str, Any]] = []
    default_kind = "finding" if name == "findings.jsonl" else "asset"
    for row in rows:
        if not isinstance(row, dict):
            continue
        schema = str(row.get("schema") or "").lower()
        if schema in PACK_DROP_SCHEMAS and not row.get("kind") and not row.get("ip"):
            records.append(_meta_evidence(row, now, source=source, labels=labels))
            continue
        kind = str(row.get("kind") or "").lower()
        ports = _ports(row)
        if not (
            kind
            or row.get("name")
            or row.get("ip")
            or row.get("hostname")
            or row.get("ref_id")
            or ports
            or row.get("schema")
        ):
            continue
        hostish = bool(
            row.get("ip") or row.get("hostname") or row.get("addr") or row.get("address") or ports
        )
        if (
            host_emitter
            and hostish
            and kind in {"", "asset", "host"}
            and name != "findings.jsonl"
        ):
            hname, addr, hostname = _host_fields(row)
            extra = {k: row.get(k) for k in ("mac", "vendor") if row.get(k)}
            extra["pack_drop"] = "covey"
            if row.get("adapter"):
                extra["adapter"] = row.get("adapter")
            extra_labels = ["covey", "pack_drop"]
            adapter = str(row.get("adapter") or "").strip()
            if adapter and adapter not in extra_labels:
                extra_labels.append(adapter)
            host_emitter(
                records,
                now,
                hname,
                addr,
                hostname or hname,
                ports,
                extra=extra or None,
                extra_labels=extra_labels,
            )
            continue
        if kind == "evidence" or name == "meta.json":
            records.append(_lift_record(row, now, source=source, labels=labels, default_kind="evidence"))
            continue
        records.append(
            _lift_record(row, now, source=source, labels=labels, default_kind=kind or default_kind)
        )
    return records
