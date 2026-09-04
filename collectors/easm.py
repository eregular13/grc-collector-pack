#!/usr/bin/env python3
"""Parse Amass / Subfinder / httpx / ffuf / gobuster / WhatWeb / testssl into external hosts.

Parse-only. Does not run amass, httpx, subfinder, ffuf, gobuster, whatweb,
sslscan, or any live DNS/HTTP/TLS probe.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, read_jsonl, read_text, run_collector
from shared.schema import make_record, make_ref
from shared.sslscan import parse_sslscan
from shared.testssl import is_testssl, iter_testssl_findings

SOURCE = "easm"
LABELS = ["easm", "external"]
WATCH = ("vpn.", "dev-api.", "admin.", "staging.")
_INTERESTING_PATH = ("admin", "login", ".git", ".env", "phpmyadmin", "wp-admin")
_OK_STATUS = {200, 204, 301, 302, 401, 403}
_GOBUSTER_STATUS = re.compile(r"\(Status:\s*(\d+)\)", re.I)


def _host_from_row(row: dict[str, Any]) -> str:
    host = str(
        row.get("host")
        or row.get("name")
        or row.get("fqdn")
        or row.get("hostname")
        or row.get("input")
        or row.get("url")
        or ""
    )
    host = host.split("://")[-1].split("/")[0]
    if host.count(":") == 1 and host.rsplit(":", 1)[-1].isdigit():
        host = host.rsplit(":", 1)[0]
    return host.strip()


def _is_failed_row(row: dict[str, Any]) -> bool:
    failed = row.get("failed")
    if failed in {True, "true", "True", 1, "1", "yes"}:
        return True
    return False


def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    """Amass / httpx / subfinder JSON array, wrapper, or single object."""
    if isinstance(payload, list):
        out: list[dict[str, Any]] = []
        for item in payload:
            if isinstance(item, dict):
                out.append(item)
            elif isinstance(item, str) and "." in item:
                out.append({"name": item})
        return out
    if not isinstance(payload, dict):
        return []
    for key in ("results", "hosts", "data", "subdomains", "domains", "records"):
        raw = payload.get(key)
        if isinstance(raw, list):
            return _rows_from_payload(raw)
    if any(payload.get(k) for k in ("host", "name", "fqdn", "hostname", "input", "url")):
        return [payload]
    return []


def _interesting_httpx(meta: dict[str, Any], name: str) -> bool:
    title = str(meta.get("title") or "")
    url = str(meta.get("url") or "")
    blob = f"{title} {url} {name}".lower()
    if "admin" in blob or "login" in blob:
        return True
    return False


def _url_path(url: str) -> str:
    rest = url.split("://", 1)[-1]
    if "/" not in rest:
        return ""
    return "/" + rest.split("/", 1)[-1]


def _interesting_path(url: str) -> bool:
    path = _url_path(url) if "://" in url else (url if url.startswith("/") else "/" + url)
    blob = path.lower()
    return any(tok in blob for tok in _INTERESTING_PATH)


def _status_ok(row: dict[str, Any]) -> bool:
    raw = row.get("status")
    if raw is None:
        raw = row.get("status_code") or row.get("Status")
    try:
        return int(raw) in _OK_STATUS
    except (TypeError, ValueError):
        return False


def _plugin_strings(plugins: dict[str, Any], name: str) -> list[str]:
    block = plugins.get(name) or plugins.get(name.lower())
    if isinstance(block, dict):
        raw = block.get("string") or block.get("strings") or []
        if isinstance(raw, list):
            return [str(x) for x in raw if x]
        if raw:
            return [str(raw)]
    if isinstance(block, list):
        return [str(x) for x in block if x]
    if isinstance(block, str) and block:
        return [block]
    return []


def _whatweb_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "results", "matches"):
        raw = payload.get(key)
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
        if isinstance(raw, dict) and ("plugins" in raw or "target" in raw):
            return [raw]
    if "plugins" in payload or "target" in payload:
        return [payload]
    return []


def _is_whatweb(payload: Any, path: Path | None = None) -> bool:
    if path is not None and "whatweb" in path.name.lower():
        return True
    rows = _whatweb_rows(payload)
    if not rows:
        return False
    row = rows[0]
    return "plugins" in row and ("target" in row or "http_status" in row)


def _whatweb_records(now: str, payload: Any) -> list[dict]:
    records: list[dict] = []
    seen_assets: set[str] = set()
    labels = list(LABELS) + ["whatweb"]
    for row in _whatweb_rows(payload):
        plugins = row.get("plugins") if isinstance(row.get("plugins"), dict) else {}
        target = str(row.get("target") or row.get("url") or "")
        host = _host_from_row({"url": target, "host": row.get("host"), "name": row.get("name")})
        titles = _plugin_strings(plugins, "Title")
        title = titles[0] if titles else ""
        blob = f"{title} {target} {host}".lower()
        watch = any(
            host.lower().startswith(p) or f".{p}" in f".{host.lower()}" for p in WATCH
        )
        interesting = (
            "admin" in blob
            or "login" in blob
            or _interesting_path(target)
            or watch
        )
        if not host or not interesting:
            continue
        if host.lower() not in seen_assets:
            seen_assets.add(host.lower())
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"External host {host}",
                    category="external-host",
                    assets=[host],
                    labels=labels,
                    collected_at=now,
                    extra={"asset_type": "PR"},
                )
            )
        if "admin" in blob or "login" in title.lower() or _interesting_path(target):
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{host}-whatweb-admin"),
                    name=f"WhatWeb admin interface on {host}",
                    description=(
                        f"{host} presents an admin/login interface "
                        f"(title={title or '[n/a]'}). "
                        "This is a dropped WhatWeb export, not a live HTTP probe."
                    ),
                    severity="high",
                    category="exposure",
                    assets=[host],
                    labels=labels + ["admin-ui"],
                    collected_at=now,
                    extra={"title": title, "url": target},
                )
            )
        elif watch:
            sev = "high" if host.lower().startswith(("vpn.", "dev-api.", "admin.")) else "medium"
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{host}-whatweb"),
                    name=f"Sensitive external hostname {host}",
                    description=(
                        f"{host} is exposed on the public perimeter "
                        "(dropped WhatWeb export, not a live DNS/HTTP probe)."
                    ),
                    severity=sev,
                    category="exposure",
                    assets=[host],
                    labels=labels,
                    collected_at=now,
                    extra={"url": target},
                )
            )
    return records


def _is_ffuf(payload: Any, path: Path | None = None) -> bool:
    if path is not None and "ffuf" in path.name.lower():
        return True
    if not isinstance(payload, dict):
        return False
    if "commandline" in payload:
        return True
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        return False
    row = results[0]
    if not isinstance(row, dict):
        return False
    return "input" in row or "position" in row or (
        "length" in row and "url" in row and "host" not in row
    )


def _ffuf_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    raw = payload.get("results") or payload.get("Results") or []
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    return []


def _is_gobuster(path: Path, text: str) -> bool:
    if "gobuster" in path.name.lower():
        return True
    return bool(_GOBUSTER_STATUS.search(text))


def _gobuster_rows(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _GOBUSTER_STATUS.search(line)
        if not match:
            continue
        token = line[: match.start()].strip().split()[0] if line[: match.start()].strip() else ""
        if not token:
            continue
        rows.append({"url": token, "status": int(match.group(1))})
    return rows


def _path_exposure_records(
    now: str, rows: list[dict[str, Any]], labels_extra: list[str]
) -> list[dict]:
    records: list[dict] = []
    seen_assets: set[str] = set()
    labels = list(LABELS) + labels_extra
    for row in rows:
        url = str(row.get("url") or row.get("input") or "")
        if isinstance(row.get("input"), dict):
            fuzz = row["input"].get("FUZZ") or row["input"].get("fuzz")
            if fuzz and "://" not in url:
                url = str(fuzz)
        if not url or not _status_ok(row) or not _interesting_path(url):
            continue
        host = _host_from_row({"url": url, "host": row.get("host"), "name": row.get("name")})
        if not host:
            continue
        if host.lower() not in seen_assets:
            seen_assets.add(host.lower())
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"External host {host}",
                    category="external-host",
                    assets=[host],
                    labels=labels,
                    collected_at=now,
                    extra={"asset_type": "PR"},
                )
            )
        path = _url_path(url) or url
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"{host}-path-{path}"),
                name=f"Exposed admin interface path on {host}",
                description=(
                    f"{host} exposes {path} (status={row.get('status') or row.get('status_code')}). "
                    "This is a dropped ffuf/gobuster finding, not a live HTTP probe."
                ),
                severity="high",
                category="exposure",
                assets=[host],
                labels=labels + ["admin-ui"],
                collected_at=now,
                extra={"url": url, "path": path},
            )
        )
    return records


def _sslscan_records(now: str, rows: list[dict[str, Any]]) -> list[dict]:
    records: list[dict] = []
    seen: set[str] = set()
    labels = list(LABELS) + ["sslscan"]
    for row in rows:
        host = str(row.get("host") or "unknown")
        if host.lower() not in seen:
            seen.add(host.lower())
            records.append(
                make_record(
                    kind="asset",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"asset-{host}"),
                    name=host,
                    description=f"External host {host}",
                    category="external-host",
                    assets=[host],
                    labels=labels,
                    collected_at=now,
                    extra={"asset_type": "PR"},
                )
            )
        vid = str(row.get("id") or row.get("name") or "sslscan")
        records.append(
            make_record(
                kind="finding",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"sslscan-{vid}-{host}"),
                name=str(row.get("name") or row.get("finding") or vid),
                description=str(row.get("finding") or row.get("name") or vid),
                severity=row.get("severity") or "high",
                category="vulnerability",
                assets=[host],
                labels=labels,
                collected_at=now,
                extra={
                    "cve": row.get("cve") or "",
                    "id": vid,
                    "port": "443",
                    "service": "https",
                },
            )
        )
    return records


def parse_file(path: Path) -> list[dict]:
    now = iso_now()
    sslscan = parse_sslscan(path)
    if sslscan is not None:
        return _sslscan_records(now, sslscan)
    if path.suffix.lower() in {".json", ".jsonl"}:
        try:
            payload = read_json(path)
        except Exception:
            payload = None
        if payload is not None and _is_whatweb(payload, path):
            return _whatweb_records(now, payload)
        if payload is None:
            rows = [r for r in read_jsonl(path) if isinstance(r, dict)]
            if rows and _is_whatweb(rows, path):
                return _whatweb_records(now, rows)

        if payload is not None and is_testssl(payload):
            records: list[dict] = []
            seen: set[str] = set()
            for row in iter_testssl_findings(payload):
                host = str(row.get("host") or "unknown")
                if host.lower() not in seen:
                    seen.add(host.lower())
                    records.append(
                        make_record(
                            kind="asset",
                            source=SOURCE,
                            ref_id=make_ref(SOURCE, f"asset-{host}"),
                            name=host,
                            description=f"External host {host}",
                            category="external-host",
                            assets=[host],
                            labels=LABELS + ["testssl"],
                            collected_at=now,
                            extra={"asset_type": "PR"},
                        )
                    )
                vid = str(row.get("cve") or row.get("id") or "testssl")
                records.append(
                    make_record(
                        kind="finding",
                        source=SOURCE,
                        ref_id=make_ref(SOURCE, f"{vid}-{host}"),
                        name=str(row.get("id") or row.get("finding") or vid),
                        description=str(row.get("finding") or row.get("cve") or vid),
                        severity=row.get("severity") or "high",
                        category="vulnerability",
                        assets=[host],
                        labels=LABELS + ["testssl"],
                        collected_at=now,
                        extra={"cve": row.get("cve") or "", "id": row.get("id") or "", "port": "443", "service": "https"},
                    )
                )
            return records

        if _is_ffuf(payload, path):
            return _path_exposure_records(now, _ffuf_rows(payload), labels_extra=["ffuf"])

    text = read_text(path)
    if path.suffix.lower() in {".txt", ".log"} or "gobuster" in path.name.lower():
        if _is_gobuster(path, text):
            return _path_exposure_records(now, _gobuster_rows(text), labels_extra=["gobuster"])

    hosts: dict[str, dict] = {}
    name_l = path.name.lower()
    if path.suffix.lower() in {".jsonl", ".json"} or "httpx" in name_l:
        payload: Any = None
        try:
            payload = read_json(path)
        except Exception:
            payload = None
        rows = _rows_from_payload(payload) if payload is not None else []
        if not rows:
            rows = [r for r in read_jsonl(path) if isinstance(r, dict)]
        for row in rows:
            if not isinstance(row, dict):
                continue
            if _is_failed_row(row):
                continue
            host = _host_from_row(row)
            if host:
                hosts[host.lower()] = {"name": host, "meta": row}
    if not hosts:
        for line in read_text(path).splitlines():
            line = line.strip()
            if not line or line.startswith("{") or line.startswith("[") or line.startswith("#"):
                continue
            host = line.split()[0].split("://")[-1].split("/")[0]
            if "." in host:
                hosts.setdefault(host.lower(), {"name": host, "meta": {}})
    demo_file = path.name.lower().startswith("dropbox-")
    records: list[dict] = []
    for key, item in sorted(hosts.items()):
        name = item["name"]
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        tech = meta.get("tech") or []
        tech_s = " ".join(str(x) for x in tech) if isinstance(tech, list) else str(tech)
        title = str(meta.get("title") or "")
        blob = f"{title} {tech_s}".lower()
        labels = list(LABELS)
        if demo_file or "dropbox-demo" in blob:
            labels.append("demo")
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=f"External host {name}",
                category="external-host",
                assets=[name],
                labels=labels,
                collected_at=now,
                extra={"asset_type": "PR", "httpx": meta},
            )
        )
        if any(name.lower().startswith(p) or f".{p}" in f".{name.lower()}" for p in WATCH):
            sev = "high" if name.lower().startswith(("vpn.", "dev-api.", "admin.")) else "medium"
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, name),
                    name=f"Sensitive external hostname {name}",
                    description=f"{name} is exposed on the public perimeter.",
                    severity=sev,
                    category="exposure",
                    assets=[name],
                    labels=labels,
                    collected_at=now,
                    extra={},
                )
            )
        if _interesting_httpx(meta, name) and (
            "admin" in f"{title} {name}".lower() or "login" in title.lower()
        ):
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{name}-admin-ui"),
                    name=f"Exposed admin interface on {name}",
                    description=f"{name} presents an admin/login interface (title={title or '[n/a]'}).",
                    severity="high",
                    category="exposure",
                    assets=[name],
                    labels=labels + ["admin-ui"],
                    collected_at=now,
                    extra={"title": title, "url": meta.get("url") or ""},
                )
            )
        if "weak" in blob and ("cipher" in blob or "tls" in blob or "ssl" in blob):
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{name}-tls-weak"),
                    name=f"TLS weak cipher: {name}",
                    description=f"{name} presents a weak TLS cipher posture (not a specific CVE).",
                    severity="medium",
                    category="exposure",
                    assets=[name],
                    labels=labels + ["tls", "https"],
                    collected_at=now,
                    extra={"port": "443", "service": "https"},
                )
            )
    return records


def main() -> None:
    run_collector(SOURCE, (".txt", ".json", ".jsonl", ".xml"), parse_file)


if __name__ == "__main__":
    main()
