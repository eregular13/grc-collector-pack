#!/usr/bin/env python3
"""Parse Amass / Subfinder / httpx into external hosts."""

from __future__ import annotations

from pathlib import Path

from shared.io_util import iso_now, read_jsonl, read_text, run_collector
from shared.schema import make_record, make_ref

SOURCE = "easm"
LABELS = ["easm", "external"]
WATCH = ("vpn.", "dev-api.", "admin.", "staging.")


def parse_file(path: Path) -> list[dict]:
    now = iso_now()
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
    records: list[dict] = []
    for key, item in sorted(hosts.items()):
        name = item["name"]
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=f"External host {name}",
                category="external-host",
                assets=[name],
                labels=LABELS,
                collected_at=now,
                extra={"asset_type": "PR", "httpx": item.get("meta") if isinstance(item.get("meta"), dict) else {}},
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
                    labels=LABELS,
                    collected_at=now,
                    extra={},
                )
            )
    return records


def main() -> None:
    run_collector(SOURCE, (".txt", ".json", ".jsonl"), parse_file)


if __name__ == "__main__":
    main()
