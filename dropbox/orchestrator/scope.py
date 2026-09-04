from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dropbox.orchestrator.yaml_lite import load_yaml


@dataclass
class Batch:
    discover_shard_size: int = 16
    deepen_batch_size: int = 3
    max_concurrent_discover: int = 2
    max_concurrent_deepen: int = 1


@dataclass
class Integrity:
    timeout_seconds: int = 300
    max_runtime_seconds: int = 7200
    refuse_if_unsigned: bool = True
    refuse_if_empty_targets: bool = True


@dataclass
class Scope:
    client_legal_name: str
    named_contact: str
    consent_attested: bool
    signed: bool
    window_start: str
    window_end: str
    profiles: str
    internal_cidrs: list[str] = field(default_factory=list)
    internal_hosts: list[str] = field(default_factory=list)
    internal_endpoints: list[str] = field(default_factory=list)
    external_hostnames: list[str] = field(default_factory=list)
    external_urls: list[str] = field(default_factory=list)
    allow_tools: list[str] = field(default_factory=list)
    batch: Batch = field(default_factory=Batch)
    integrity: Integrity = field(default_factory=Integrity)
    path: Path | None = None

    def live_ok(self) -> tuple[bool, str]:
        if not self.consent_attested:
            return False, "consent_attested=false"
        if self.integrity.refuse_if_unsigned and not self.signed:
            return False, "unsigned SCOPE"
        if self.integrity.refuse_if_empty_targets and not self.targets():
            return False, "empty technical targets"
        if not self.allow_tools:
            return False, "empty allow_tools"
        return True, "ok"

    def targets(self) -> list[str]:
        out: list[str] = []
        if self.profiles in {"internal", "both"}:
            out.extend(self.internal_cidrs)
            out.extend(self.internal_hosts)
            out.extend(self.internal_endpoints)
        if self.profiles in {"external", "both"}:
            out.extend(self.external_hostnames)
            out.extend(self.external_urls)
        return [t for t in out if t]

    def tool_allowed(self, name: str) -> bool:
        return name in self.allow_tools


def load_scope(path: Path) -> Scope:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw) if path.suffix.lower() == ".json" else load_yaml(raw)
    return parse_scope(data, path)


def parse_scope(data: dict[str, Any], path: Path | None = None) -> Scope:
    internal = data.get("internal") or {}
    external = data.get("external") or {}
    batch = data.get("batch") or {}
    integ = data.get("integrity") or {}
    return Scope(
        client_legal_name=str(data.get("client_legal_name") or ""),
        named_contact=str(data.get("named_contact") or ""),
        consent_attested=bool(data.get("consent_attested")),
        signed=bool(data.get("signed")),
        window_start=str(data.get("window_start") or ""),
        window_end=str(data.get("window_end") or ""),
        profiles=str(data.get("profiles") or "internal"),
        internal_cidrs=list(internal.get("cidrs") or []),
        internal_hosts=list(internal.get("hosts") or []),
        internal_endpoints=list(internal.get("endpoints") or []),
        external_hostnames=list(external.get("hostnames") or []),
        external_urls=list(external.get("urls") or []),
        allow_tools=[str(t) for t in (data.get("allow_tools") or [])],
        batch=Batch(
            discover_shard_size=int(batch.get("discover_shard_size") or 16),
            deepen_batch_size=int(batch.get("deepen_batch_size") or 3),
            max_concurrent_discover=int(batch.get("max_concurrent_discover") or 2),
            max_concurrent_deepen=int(batch.get("max_concurrent_deepen") or 1),
        ),
        integrity=Integrity(
            timeout_seconds=int(integ.get("timeout_seconds") or 300),
            max_runtime_seconds=int(integ.get("max_runtime_seconds") or 7200),
            refuse_if_unsigned=bool(integ.get("refuse_if_unsigned", True)),
            refuse_if_empty_targets=bool(integ.get("refuse_if_empty_targets", True)),
        ),
        path=path,
    )
