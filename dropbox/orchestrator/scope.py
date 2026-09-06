"""SCOPE load + fail-closed validation. Unsigned or empty targets refuse live stages."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# CIDR-only does not unlock testssl; Entra-only does not unlock Lynis.
TOOL_TARGET_KINDS: dict[str, tuple[str, ...]] = {
    "nmap": ("cidr", "internal_host"),
    "nessus": ("cidr", "internal_host", "endpoint"),
    "testssl": ("external_hostname", "external_url"),
    "curl": ("external_hostname", "external_url"),
    "lynis": ("endpoint",),
    "hardeningkitty": ("endpoint",),
    "prowler": ("cloud",),
    "scoutsuite": ("cloud",),
    "maester": ("entra",),
    "ss": ("internal_host", "endpoint"),
}


class ScopeError(ValueError):
    """Fail-closed SCOPE problem."""


def parse_window(raw: str) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _as_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        text = raw.strip()
        return [text] if text else []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return []


def _mini_yaml(text: str) -> dict[str, Any]:
    """Tiny YAML subset: mappings, nested mappings, lists of scalars. No tags."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    def _parse_scalar(raw: str) -> Any:
        raw = raw.strip()
        if raw in {"", "~", "null", "Null"}:
            return None
        if raw == "true":
            return True
        if raw == "false":
            return False
        if re.fullmatch(r"-?\d+", raw):
            return int(raw)
        if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
            return raw[1:-1]
        return raw

    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    pending: tuple[int, dict[str, Any], str] | None = None

    def _parent_for(indent: int) -> Any:
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        return stack[-1][1]

    for lineno, raw_line in enumerate(text.splitlines(), 1):
        if (not raw_line.strip()) or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if line.startswith("- "):
            item = _parse_scalar(line[2:])
            if pending and indent > pending[0]:
                lst: list[Any] = [item]
                pending[1][pending[2]] = lst
                stack.append((indent, lst))
                pending = None
                continue
            while len(stack) > 1 and indent < stack[-1][0]:
                stack.pop()
            parent = stack[-1][1]
            if isinstance(parent, list) and indent == stack[-1][0]:
                parent.append(item)
                continue
            raise ScopeError(f"line {lineno}: list item without key")
        parent = _parent_for(indent)
        if pending and indent > pending[0]:
            child: dict[str, Any] = {}
            pending[1][pending[2]] = child
            stack.append((pending[0], child))
            pending = None
            parent = child
        if ":" not in line:
            raise ScopeError(f"line {lineno}: expected key:")
        if not isinstance(parent, dict):
            raise ScopeError(f"line {lineno}: mapping under list")
        key, rest = line.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        if rest == "":
            pending = (indent, parent, key)
            continue
        if rest.startswith("[") and rest.endswith("]"):
            inner = rest[1:-1].strip()
            parent[key] = [_parse_scalar(p.strip()) for p in inner.split(",") if p.strip()]
            pending = None
            continue
        parent[key] = _parse_scalar(rest)
        pending = None
    if pending:
        pending[1][pending[2]] = {}
    return root


# Quiet→loud blast-radius laws. SCOPE cannot hail-mary these off.
MAX_DISCOVER_SHARD_SIZE = 256
MAX_DEEPEN_BATCH_SIZE = 5
MAX_CONCURRENT_DISCOVER = 4
MAX_CONCURRENT_DEEPEN = 2
# This lab host's office LAN. Parsed targets only — comments must not trip this.
OFFICE_LAN = ipaddress.ip_network("192.168.10.0/24")
FORBIDDEN_EXACT_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


@dataclass
class Batch:
    discover_shard_size: int = 32
    deepen_batch_size: int = 3
    max_concurrent_discover: int = 2
    max_concurrent_deepen: int = 1


@dataclass
class Integrity:
    timeouts_seconds: int = 600
    max_runtime_seconds: int = 14400
    refuse_if_unsigned: bool = True
    refuse_if_empty_targets: bool = True
    allow_live_exec: bool = False


@dataclass
class Scope:
    path: Path
    client_legal_name: str
    named_contact: str
    consent_attested: bool
    window_start: str
    window_end: str
    internal_cidrs: list[str] = field(default_factory=list)
    internal_hosts: list[str] = field(default_factory=list)
    internal_endpoints: list[str] = field(default_factory=list)
    external_hostnames: list[str] = field(default_factory=list)
    external_urls: list[str] = field(default_factory=list)
    cloud_accounts: list[str] = field(default_factory=list)
    entra_tenants: list[str] = field(default_factory=list)
    allow_tools: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    batch: Batch = field(default_factory=Batch)
    integrity: Integrity = field(default_factory=Integrity)

    @property
    def signed(self) -> bool:
        """Consent is not attested without a legal name and named contact (schema required)."""
        return (
            bool(self.consent_attested)
            and bool(self.client_legal_name.strip())
            and bool(self.named_contact.strip())
        )

    def technical_targets(self) -> list[str]:
        return (
            self.internal_cidrs
            + self.internal_hosts
            + self.internal_endpoints
            + self.external_hostnames
            + self.external_urls
            + self.cloud_accounts
            + self.entra_tenants
        )

    def named_hosts(self) -> list[str]:
        return list(self.discover_hosts())

    def profile_set(self) -> set[str]:
        return {p.lower() for p in self.profiles if str(p).strip()}

    def uses_internal(self) -> bool:
        names = self.profile_set()
        return (not names) or "internal" in names or "both" in names

    def uses_external(self) -> bool:
        names = self.profile_set()
        return "external" in names or "both" in names

    def discover_cidrs(self) -> list[str]:
        """Internal CIDRs only when the internal/both profile is active."""
        return list(self.internal_cidrs) if self.uses_internal() else []

    def discover_hosts(self) -> list[str]:
        hosts: list[str] = []
        if self.uses_internal():
            hosts.extend(self.internal_hosts)
        if self.uses_external():
            hosts.extend(self.external_hostnames)
        return hosts

    def kinds_present(self) -> set[str]:
        kinds: set[str] = set()
        if self.uses_internal() and self.internal_cidrs:
            kinds.add("cidr")
        if self.uses_internal() and self.internal_hosts:
            kinds.add("internal_host")
        if self.uses_internal() and self.internal_endpoints:
            kinds.add("endpoint")
        if self.uses_external() and self.external_hostnames:
            kinds.add("external_hostname")
        if self.uses_external() and self.external_urls:
            kinds.add("external_url")
        if self.cloud_accounts:
            kinds.add("cloud")
        if self.entra_tenants:
            kinds.add("entra")
        return kinds

    def tool_gate(self, name: str) -> str | None:
        """Refuse a tool when SCOPE target kinds cannot feed it."""
        key = name.lower().strip()
        needed = TOOL_TARGET_KINDS.get(key)
        if not needed:
            return None
        present = self.kinds_present()
        if any(kind in present for kind in needed):
            return None
        return f"{key}_needs_{'|'.join(needed)}"

    def tool_gates(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for tool in self.allow_tools:
            reason = self.tool_gate(tool)
            out[tool] = reason or "ok"
        return out

    def usable_tools(self) -> list[str]:
        return [t for t in self.allow_tools if self.tool_gate(t) is None]

    def window_reason(self, now: datetime | None = None) -> str | None:
        start_raw = (self.window_start or "").strip()
        end_raw = (self.window_end or "").strip()
        start = parse_window(self.window_start)
        end = parse_window(self.window_end)
        if not start_raw or not end_raw:
            return "window_missing"
        if start is None or end is None:
            return "window_unparseable"
        clock = now or datetime.now(timezone.utc)
        if clock.tzinfo is None:
            clock = clock.replace(tzinfo=timezone.utc)
        if start is not None and clock < start:
            return "window_not_open"
        if end is not None and clock > end:
            return "window_closed"
        return None

    def forbidden_cidr_reason(self) -> str | None:
        """Refuse office LAN / default-route CIDRs. Comments are not targets."""
        for cidr in self.internal_cidrs:
            text = (cidr or "").strip()
            if not text:
                continue
            if text in FORBIDDEN_EXACT_CIDRS:
                return "forbidden_cidr"
            try:
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                continue
            if int(net.prefixlen) == 0:
                return "forbidden_cidr"
            if net.overlaps(OFFICE_LAN):
                return "forbidden_cidr"
        hosts: list[str] = []
        hosts.extend(self.internal_hosts)
        hosts.extend(self.external_hostnames)
        for raw in list(self.external_urls) + list(self.internal_endpoints):
            t = (raw or "").strip()
            if "://" in t:
                hosts.append(urlparse(t).hostname or "")
            else:
                hosts.append(t)
        for host in hosts:
            h = (host or "").strip()
            if not h:
                continue
            try:
                ip = ipaddress.ip_address(h)
            except ValueError:
                continue
            if ip in OFFICE_LAN:
                return "forbidden_cidr"
        return None

    def refuse_live(self, now: datetime | None = None) -> str | None:
        """Return reason to refuse discover/deepen, or None if allowed to plan live stages.
        Unsigned and empty-target refuses are laws — SCOPE cannot toggle them off."""
        if not self.signed:
            return "unsigned_or_consent_false"
        if not self.technical_targets():
            return "empty_targets"
        if not self.allow_tools:
            return "empty_allow_tools"
        forbidden = self.forbidden_cidr_reason()
        if forbidden:
            return forbidden
        window = self.window_reason(now=now)
        if window:
            return window
        if self.allow_tools and not self.usable_tools():
            return "no_tool_matches_target_kind"
        return None

    def tool_allowed(self, name: str) -> bool:
        return name.lower() in {t.lower() for t in self.allow_tools} and self.tool_gate(name) is None


def load_scope(path: Path | str) -> Scope:
    path = Path(path)
    if not path.is_file():
        raise ScopeError(f"SCOPE missing: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        raw = json.loads(text)
    else:
        raw = _mini_yaml(text)
    if not isinstance(raw, dict):
        raise ScopeError("SCOPE root must be a mapping")
    internal = raw.get("internal") if isinstance(raw.get("internal"), dict) else {}
    external = raw.get("external") if isinstance(raw.get("external"), dict) else {}
    batch_raw = raw.get("batch") if isinstance(raw.get("batch"), dict) else {}
    integ_raw = raw.get("integrity") if isinstance(raw.get("integrity"), dict) else {}
    profiles = _as_list(raw.get("profiles"))
    if not profiles and isinstance(raw.get("profiles"), str):
        profiles = [p.strip() for p in str(raw.get("profiles")).split("|") if p.strip()]
    return Scope(
        path=path,
        client_legal_name=str(raw.get("client_legal_name") or ""),
        named_contact=str(raw.get("named_contact") or ""),
        consent_attested=bool(raw.get("consent_attested") is True),
        window_start=str(raw.get("window_start") or ""),
        window_end=str(raw.get("window_end") or ""),
        internal_cidrs=_as_list(internal.get("cidrs")),
        internal_hosts=_as_list(internal.get("hosts")),
        internal_endpoints=_as_list(internal.get("endpoints")),
        external_hostnames=_as_list(external.get("hostnames")),
        external_urls=_as_list(external.get("urls")),
        cloud_accounts=_as_list(
            (raw.get("cloud") or {}).get("accounts")
            if isinstance(raw.get("cloud"), dict)
            else raw.get("cloud")
        ),
        entra_tenants=_as_list(
            (raw.get("entra") or {}).get("tenants")
            if isinstance(raw.get("entra"), dict)
            else raw.get("entra")
        ),
        allow_tools=_as_list(raw.get("allow_tools")),
        profiles=profiles or ["internal"],
        batch=Batch(
            discover_shard_size=max(
                1, min(int(batch_raw.get("discover_shard_size") or 32), MAX_DISCOVER_SHARD_SIZE)
            ),
            deepen_batch_size=max(
                1, min(int(batch_raw.get("deepen_batch_size") or 3), MAX_DEEPEN_BATCH_SIZE)
            ),
            max_concurrent_discover=max(
                1, min(int(batch_raw.get("max_concurrent_discover") or 2), MAX_CONCURRENT_DISCOVER)
            ),
            max_concurrent_deepen=max(
                1, min(int(batch_raw.get("max_concurrent_deepen") or 1), MAX_CONCURRENT_DEEPEN)
            ),
        ),
        integrity=Integrity(
            timeouts_seconds=int(integ_raw.get("timeouts_seconds") or 600),
            max_runtime_seconds=int(integ_raw.get("max_runtime_seconds") or 14400),
            refuse_if_unsigned=True,
            refuse_if_empty_targets=True,
            allow_live_exec=bool(integ_raw.get("allow_live_exec") is True),
        ),
    )
