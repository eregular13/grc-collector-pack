#!/usr/bin/env python3
"""Parse Amass / Subfinder / httpx into external hosts."""

from __future__ import annotations

from pathlib import Path

from shared.io_util import iso_now, read_json, read_jsonl, read_text, run_collector
from shared.schema import make_record, make_ref
from shared.testssl import is_testssl, iter_testssl_findings

SOURCE = "easm"
LABELS = ["easm", "external"]
WATCH = ("vpn.", "dev-api.", "admin.", "staging.")


def parse_file(path: Path) -> list[dict]:
    now = iso_now()
    if path.suffix.lower() in {".json", ".jsonl"}:
        try:
            payload = read_json(path)
        except Exception:
            payload = None
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
    hosts: dict[str, dict] = {}
    name_l = path.name.lower()
    if path.suffix.lower() in {".jsonl", ".json"} or "httpx" in name_l:
        for row in read_jsonl(path):
            if not isinstance(row, dict):
                continue
            host = str(
                row.get("host")
                or row.get("name")
                or row.get("fqdn")
                or row.get("input")
                or row.get("url")
                or ""
            ).split("://")[-1].split("/")[0]
            if host:
                hosts[host.lower()] = {"name": host, "meta": row}
        if not hosts:
            # single JSON object or list handled poorly; try text domains
            pass
    if not hosts:
        for line in read_text(path).splitlines():
            line = line.strip()
            if not line or line.startswith("{") or line.startswith("#"):
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
    run_collector(SOURCE, (".txt", ".json", ".jsonl"), parse_file)


if __name__ == "__main__":
    main()
