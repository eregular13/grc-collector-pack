"""Load and fail-closed validate SCOPE.yaml."""

from __future__ import annotations

import hashlib
import ipaddress
import os
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from dropbox.yaml_lite import load_yaml

ROOT = Path(__file__).resolve().parents[1]

# Never apt-install / Docker-embed these. Orchestrator may BYO nmap/nessus if on PATH.
NEVER_EMBED = frozenset(
    {
        "nmap",
        "ncat",
        "nping",
        "nuclei",
        "openvas",
        "gvm",
        "gvmd",
        "ospd-openvas",
        "nessus",
        "nessusd",
        "nessuscli",
        "zeek",
        "bro",
        "wazuh",
        "wazuh-agent",
        "osquery",
        "osqueryd",
        "osqueryi",
        "pingcastle",
        "purpleknight",
        "purple-knight",
        "bloodhound",
        "sharphound",
        "azurehound",
        "cis-cat",
        "ciscat",
        "cis_cat",
        "riskready",
        "hailmary",
        "hail-mary",
    }
)
ORCH_BYO = frozenset({"nmap", "nessus", "nessuscli"})
FORBIDDEN_TOOLS = NEVER_EMBED - ORCH_BYO
# Never resolve or subprocess these from FARM_TOOL_BIN or PATH — even if dropped
# there. nmap/nessus stay ORCH_BYO (signed SCOPE.allow_tools + stage only).
LICENSE_LOCK_SPAWN = frozenset(FORBIDDEN_TOOLS) | {
    "hexstrike",
    "hexstrike-ai",
    "enum4linux",
    "enum4linux-ng",
    "smbmap",
    "smbclient",
    "zmap",
    "unicornscan",
    "metasploit",
    "msfconsole",
}

ALLOWED_RUNNERS = frozenset({"lynis", "ss", "ip", "curl", "testssl", "testssl.sh"})
EXTERNAL_STAGE_TOOLS = frozenset({"curl", "testssl", "testssl.sh"})

# Quiet discover may only plan/run inventory tools. Deepen (louder) is a separate list.
DISCOVER_STAGE_TOOLS = frozenset({"nmap"})
DEEPEN_STAGE_TOOLS = frozenset({"nessus", "nessuscli"})

# Explicit allowlist of known keys per section. Derived from Scope / load_scope,
# committed dropbox/SCOPE.yaml + SCOPE.example.yaml, and OPERATOR / WEB_TLS docs.
# Comparison is exact: lower-case, no surrounding whitespace, as documented.
# Non-canonical spellings (PORTS_ALLOWED, ' ports_allowed ', quoted NBSP
# keys, BOM) refuse. Unquoted NBSP is yaml_lite whitespace and is read
# as the canonical key.
# Unknown keys and any non-ASCII key refuse. engagement.begin is not an alias.
_SCOPE_KEYS: dict[str, frozenset[str]] = {
    "": frozenset(
        {
            "client",
            "consent",
            "engagement",
            "revoked",
            "status",
            "ports_allowed",
            "internal",
            "external",
            "allow_tools",
            "orchestrator",
            "byo",
        }
    ),
    "client": frozenset({"name"}),
    "consent": frozenset({"attestation_path", "attestation_sha256"}),
    "engagement": frozenset(
        {"start", "end", "status", "revoked", "ports_allowed"}
    ),
    "internal": frozenset({"cidrs", "hosts"}),
    "external": frozenset({"hosts", "domains", "ips"}),
    "orchestrator": frozenset(
        {
            "discover_prefix",
            "deepen_batch",
            "max_live_shards",
            "max_workers",
            "host_timeout_sec",
            "stages",
            "deepen_hosts",
            "stage_tools",
        }
    ),
    "orchestrator.stages": frozenset({"discover", "deepen", "external"}),
    "orchestrator.stage_tools": frozenset({"discover", "deepen"}),
    "byo[]": frozenset({"name", "args", "sensor", "timeout"}),
}


class GateError(SystemExit):
    """SCOPE gate failed. Exit non-zero."""

    def __init__(self, message: str) -> None:
        super().__init__(f"SCOPE gate: {message}")


@dataclass
class Scope:
    path: Path
    client_name: str
    consent_path: Path
    consent_sha256: str
    window_start: date
    window_end: date
    internal_cidrs: list[str] = field(default_factory=list)
    internal_hosts: list[str] = field(default_factory=list)
    external_hosts: list[str] = field(default_factory=list)
    external_domains: list[str] = field(default_factory=list)
    external_ips: list[str] = field(default_factory=list)
    allow_tools: list[str] = field(default_factory=list)
    byo: list[dict] = field(default_factory=list)
    discover_prefix: int = 24
    deepen_batch: int = 3
    max_live_shards: int = 16
    max_workers: int = 2
    host_timeout_sec: int = 30
    stage_discover: bool = True
    stage_deepen: bool = False
    deepen_hosts: list[str] = field(default_factory=list)
    stage_tools_discover: list[str] = field(default_factory=lambda: ["nmap"])
    stage_tools_deepen: list[str] = field(default_factory=lambda: ["nessus"])
    # None = field absent (current behavior: any port on an in-scope host).
    # An explicit list is fail-closed: only those TCP ports may be probed.
    ports_allowed: list[int] | None = None
    revoked: bool = False

    def tools_for(self, stage: str) -> list[str]:
        """Intersect SCOPE.allow_tools with the tools permitted for this stage."""
        if stage == "discover":
            wanted = self.stage_tools_discover or ["nmap"]
            permit = DISCOVER_STAGE_TOOLS
        elif stage == "deepen":
            wanted = self.stage_tools_deepen or ["nessus", "nessuscli"]
            permit = DEEPEN_STAGE_TOOLS
        else:
            return []
        allow = {t.lower() for t in self.allow_tools}
        return [t for t in wanted if t.lower() in allow and t.lower() in permit]

    def allows_internal_target(self, target: str) -> bool:
        raw = (target or "").strip()
        if not raw:
            return False
        host = raw.split("://")[-1].split("/")[0].split(":")[0].lower().rstrip(".")
        if not host:
            return False
        named = {h.lower().rstrip(".") for h in self.internal_hosts}
        named |= {h.lower().rstrip(".") for h in self.deepen_hosts}
        if host in named:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        for cidr in self.internal_cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if ip in net:
                return True
        return False

    def external_names(self) -> set[str]:
        names = {h.lower().rstrip(".") for h in self.external_hosts}
        names |= {d.lower().rstrip(".") for d in self.external_domains}
        names |= {i.lower() for i in self.external_ips}
        return names

    def allows_external_target(self, target: str) -> bool:
        raw = (target or "").strip()
        if not raw:
            return False
        if "*" in raw or "?" in raw:
            return False
        if "://" not in raw and "/" in raw:
            return False
        host = raw.split("://")[-1].split("/")[0].split(":")[0].lower().rstrip(".")
        if not host or "*" in host or "?" in host:
            return False
        names = self.external_names()
        if host in names:
            return True
        for domain in self.external_domains:
            d = domain.lower().rstrip(".")
            if host == d or host.endswith("." + d):
                return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return str(ip) in {i.lower() for i in self.external_ips}

    def allows_target(self, target: str) -> bool:
        """True when target is an authorized internal or named-external SCOPE host."""
        return self.allows_internal_target(target) or self.allows_external_target(target)

    def allows_port(self, port: int) -> bool:
        """True when port is in 1..65535 and (if set) in ports_allowed.

        Absent ``ports_allowed`` keeps pre-port-list behavior (any valid
        TCP port on an in-scope host). Out-of-range ports always deny.
        An explicit empty list denies every port.
        """
        try:
            if isinstance(port, bool):
                return False
            num = int(port)
        except (TypeError, ValueError):
            return False
        if not 1 <= num <= 65535:
            return False
        if self.ports_allowed is None:
            return True
        return num in self.ports_allowed


def require_authorized_targets(scope: Scope, targets: list[str]) -> None:
    """Fail closed if any requested target is outside the signed SCOPE.

    Checked before scan/pack/SoR. Empty target list is a refusal — do not
    invent an estate.
    """
    rows = [str(item or "").strip() for item in (targets or []) if str(item or "").strip()]
    if not rows:
        raise GateError("scan_to_sor requires at least one authorized target")
    missing = [raw for raw in rows if not scope.allows_target(raw)]
    if missing:
        shown = ", ".join(missing)
        raise GateError(f"requested target(s) outside authorized SCOPE: {shown}")


def require_not_revoked(scope: Scope) -> None:
    """Fail closed when the signed SCOPE has been revoked."""
    if scope.revoked:
        raise GateError("engagement is revoked")


def require_authorized_ports(scope: Scope, ports: list[int]) -> None:
    """Fail closed when any requested port is outside 1..65535 or SCOPE.

    Ports outside 1..65535 always refuse, even when ports_allowed is
    absent. An explicit list then refuses every port not named,
    including an empty allow-list.
    """
    rows: list[int] = []
    for item in ports or []:
        if isinstance(item, bool):
            raise GateError(f"invalid port {item!r}")
        try:
            num = int(item)
        except (TypeError, ValueError) as exc:
            raise GateError(f"invalid port {item!r}") from exc
        if not 1 <= num <= 65535:
            raise GateError(f"port out of range: {item!r}")
        rows.append(num)
    missing = [p for p in rows if not scope.allows_port(p)]
    if missing:
        shown = ", ".join(str(p) for p in missing)
        raise GateError(f"requested port(s) outside authorized SCOPE: {shown}")


def require_live_probe(scope: Scope, target: str, ports: list[int]) -> None:
    """Fail-closed live gate: not revoked, target in SCOPE, ports allowed."""
    require_not_revoked(scope)
    require_authorized_targets(scope, [target])
    require_authorized_ports(scope, ports)


def _refuse_external_scope_item(field: str, item: str) -> None:
    """Named hosts/URLs only. Refuse wildcard, CIDR, and 0.0.0.0/0."""
    raw = str(item or "").strip()
    if not raw:
        raise GateError(f"external {field} refuses empty target")
    if "*" in raw or "?" in raw:
        raise GateError(f"external {field} refuses wildcard {item!r}")
    if raw in {"0.0.0.0/0", "0.0.0.0", "::/0", "::"}:
        raise GateError(f"external {field} refuses open-internet {item!r}")
    if "://" in raw:
        host = raw.split("://", 1)[1].split("/")[0].split(":")[0]
        if not host or "*" in host or "?" in host:
            raise GateError(f"external {field} refuses {item!r}")
        if host in {"0.0.0.0", "::"}:
            raise GateError(f"external {field} refuses open-internet {item!r}")
        return
    if "/" in raw:
        raise GateError(f"external {field} refuses CIDR {item!r}")


def is_open_internet_cidr(cidr: str) -> bool:
    """Refuse 0.0.0.0/0 and other internet-wide prefixes. Integrity over coverage."""
    try:
        net = ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return True
    if net.version != 4:
        return True
    return net.prefixlen < 8


def _looks_wide_cidr(raw: str) -> bool:
    text = str(raw or "").strip()
    if "/" not in text:
        return False
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return net.num_addresses > 1


def _as_bool(value, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    return default


_REVOKED_TRUE = frozenset({"true", "yes", "1", "on", "y"})
_REVOKED_FALSE = frozenset({"false", "no", "0", "off", "n", ""})
# Absent status, or one of these tokens, is the only live-valid set.
# Docs (SCOPE.example.yaml) name ``authorized``; Metis/operator also use
# ``active`` / ``approved``. Everything else (expired, on-hold, withdrawn,
# revoked-by-client, terminated, nested mappings, …) refuses.
_STATUS_ALLOWED = frozenset({"", "active", "authorized", "approved"})


def _ci_values(mapping: Any, key: str) -> list[Any]:
    """All values whose key case-folds to ``key`` (YAML keys are case-sensitive)."""
    if not isinstance(mapping, dict):
        return []
    want = str(key).strip().lower()
    out: list[Any] = []
    for raw_key, value in mapping.items():
        if str(raw_key).strip().lower() == want:
            out.append(value)
    return out


def _ci_get(mapping: Any, key: str) -> Any:
    """First case-insensitive hit, or None when the key is absent."""
    rows = _ci_values(mapping, key)
    return rows[0] if rows else None


def _flag_is_revoked(raw: Any) -> bool | None:
    """True / False / None (absent). Unknown tokens fail closed."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    text = str(raw).split("#", 1)[0].strip().lower()
    if text in _REVOKED_TRUE:
        return True
    if text in _REVOKED_FALSE:
        return False
    raise GateError(f"invalid revoked value {raw!r}")


def _status_is_allowed(raw: Any) -> bool:
    """True only for absent or allowlisted status. Nested / unknown refuse."""
    if raw is None:
        return True
    if isinstance(raw, (dict, list, bool)):
        return False
    text = str(raw).split("#", 1)[0].strip().lower()
    return text in _STATUS_ALLOWED


def _engagement_is_revoked(data: dict, eng: dict) -> bool:
    """Revoked flags or any status outside the allowlist.

    The loader boundary already refused non-canonical keys, so YAML
    mappings only carry documented spellings. Helpers still fold case
    for constructed (non-YAML) mappings. Nested ``status: {state: …}``
    refuses. Absent status is allowed.
    """
    eng_ci = eng if isinstance(eng, dict) else {}
    if not _ci_values(eng_ci, "status") and not _ci_values(eng_ci, "revoked"):
        found = _ci_get(data, "engagement")
        if isinstance(found, dict):
            eng_ci = found
    for raw in (*_ci_values(data, "revoked"), *_ci_values(eng_ci, "revoked")):
        flag = _flag_is_revoked(raw)
        if flag is True:
            return True
    for raw in (*_ci_values(eng_ci, "status"), *_ci_values(data, "status")):
        if not _status_is_allowed(raw):
            return True
    return False


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_str_list(value) -> list[str]:
    out = []
    for item in _as_list(value):
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def _parse_day(value, field_name: str) -> date:
    text = str(value or "").strip()
    if not text:
        raise GateError(f"missing {field_name}")
    try:
        return datetime.strptime(text[:10], "%Y-%m-%d").date()
    except ValueError as exc:
        raise GateError(f"invalid {field_name} {text!r}") from exc


def default_scope_path() -> Path:
    raw = (os.environ.get("DROPBOX_SCOPE") or "").strip()
    if raw:
        return Path(raw)
    return ROOT / "dropbox" / "SCOPE.yaml"


def canonical_attestation_bytes(raw: bytes) -> bytes:
    """LF-canonical consent bytes. Git on Windows may check out CRLF; do not skip the hash."""
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def attestation_digest(raw: bytes) -> str:
    """SHA-256 hex of LF-canonical attestation bytes. Required; never skip."""
    return hashlib.sha256(canonical_attestation_bytes(raw)).hexdigest()


def resolve_attestation_path(att_rel: str) -> Path:
    att_path = Path(att_rel)
    if not att_path.is_absolute():
        att_path = (ROOT / att_rel).resolve()
    return att_path


def consent_file_from_scope(scope_path: Path) -> tuple[Path, str]:
    """Resolve attestation path + declared hash. Does not verify the hash (attest uses this)."""
    if not scope_path.is_file():
        raise GateError(f"no SCOPE file at {scope_path}")
    data = _load_scope_mapping(scope_path)
    consent = data.get("consent") if isinstance(data.get("consent"), dict) else {}
    att_rel = str(consent.get("attestation_path") or "").strip()
    att_hash = str(consent.get("attestation_sha256") or "").strip().lower()
    if not att_rel:
        raise GateError("consent.attestation_path is required")
    att_path = resolve_attestation_path(att_rel)
    if not att_path.is_file():
        raise GateError(f"consent attestation missing: {att_path}")
    return att_path, att_hash


def write_attestation_hash(scope_path: Path, digest: str) -> None:
    """Stamp consent.attestation_sha256 in place. Refuses to invent a skip-hash."""
    hex_digest = str(digest or "").strip().lower()
    if len(hex_digest) != 64 or any(c not in "0123456789abcdef" for c in hex_digest):
        raise GateError("attestation digest must be a 64-char sha256 hex")
    text = scope_path.read_text(encoding="utf-8")
    if not text:
        raise GateError("SCOPE.yaml is empty")
    lines = text.splitlines(keepends=True)
    updated = False
    out: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("attestation_sha256:"):
            indent = line[: len(line) - len(stripped)]
            rest = stripped.split(":", 1)[1].strip()
            quote = rest[0] if rest[:1] in {"'", '"'} else ""
            if line.endswith("\r\n"):
                newline = "\r\n"
            elif line.endswith("\n"):
                newline = "\n"
            elif line.endswith("\r"):
                newline = "\r"
            else:
                newline = ""
            if quote:
                out.append(f"{indent}attestation_sha256: {quote}{hex_digest}{quote}{newline}")
            else:
                out.append(f"{indent}attestation_sha256: {hex_digest}{newline}")
            updated = True
        else:
            out.append(line)
    if not updated:
        raise GateError("consent.attestation_sha256 line not found")
    scope_path.write_text("".join(out), encoding="utf-8")


def _key_is_ascii(key: str) -> bool:
    return all(ord(ch) < 128 for ch in key)


def _where(path: str) -> str:
    return path if path else "root"


def _canonical_for(allowed: frozenset[str], key: str) -> str | None:
    """Documented spelling if ``key`` case-folds and strips to an allowlisted name."""
    fold = str(key).strip().lower()
    for name in allowed:
        if name == fold:
            return name
    return None


def allowlisted_scope_keys() -> list[tuple[str, str]]:
    """Every allowlisted (section, key) pair. Tests parametrize over this."""
    rows: list[tuple[str, str]] = []
    for section, names in _SCOPE_KEYS.items():
        for name in sorted(names):
            rows.append((section, name))
    return rows


def refuse_unknown_scope_keys(data: Any, path: str = "") -> None:
    """Refuse non-canonical, unknown, non-ASCII, and BOM keys at the loader.

    Keys must be spelled exactly as documented (lower-case, no surrounding
    whitespace). Refusing is preferred over silently normalising so a
    misspelled ``PORTS_ALLOWED`` cannot load as an absent port limit.
    Downstream readers never see a non-canonical key.

    A leading UTF-8 BOM on a key is refused. Walks every mapping section
    that has an allowlist. A known scalar field whose value is a mapping
    (nested ``status: {state: …}``) is left to the existing
    status/revocation check — that path is not a section.
    """
    if isinstance(data, list):
        item_path = f"{path}[]" if path else "[]"
        allowed = _SCOPE_KEYS.get(item_path)
        for item in data:
            if isinstance(item, dict):
                if allowed is None:
                    raise GateError(f"unexpected mapping item under {_where(path)}")
                refuse_unknown_scope_keys(item, item_path)
            elif isinstance(item, list):
                refuse_unknown_scope_keys(item, item_path)
        return
    if not isinstance(data, dict):
        return
    allowed = _SCOPE_KEYS.get(path)
    if allowed is None:
        raise GateError(f"unexpected mapping at {_where(path)}")
    for raw_key, value in data.items():
        key = str(raw_key)
        if "\ufeff" in key:
            raise GateError(f"BOM mapping key {key!r} at {_where(path)}")
        if key not in allowed:
            canon = _canonical_for(allowed, key)
            if canon is not None:
                raise GateError(
                    f"non-canonical key {key!r} at {_where(path)} (canonical: {canon})"
                )
            if not _key_is_ascii(key):
                raise GateError(f"non-ASCII mapping key {key!r} at {_where(path)}")
            raise GateError(f"unknown key {key!r} at {_where(path)}")
        child = f"{path}.{key}" if path else key
        if isinstance(value, dict) and child in _SCOPE_KEYS:
            refuse_unknown_scope_keys(value, child)
        elif isinstance(value, list):
            refuse_unknown_scope_keys(value, child)


def _load_scope_mapping(scope_path: Path) -> dict:
    """Parse SCOPE YAML. Duplicate / non-canonical / unknown / BOM keys fail closed."""
    try:
        text = scope_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"cannot read SCOPE: {exc}") from exc
    if "\ufeff" in text:
        raise GateError("BOM mapping key refused")
    try:
        data = load_yaml(text)
    except ValueError as exc:
        raise GateError(str(exc)) from exc
    if not isinstance(data, dict) or not data:
        raise GateError("SCOPE.yaml is empty or not a mapping")
    refuse_unknown_scope_keys(data)
    return data


def load_scope(path: Path | None = None) -> Scope:
    scope_path = Path(path) if path else default_scope_path()
    if not scope_path.is_file():
        raise GateError(f"no SCOPE file at {scope_path}")
    data = _load_scope_mapping(scope_path)

    client = data.get("client") if isinstance(data.get("client"), dict) else {}
    name = str(client.get("name") or "").strip()
    if not name:
        raise GateError("client.name is required")

    consent = data.get("consent") if isinstance(data.get("consent"), dict) else {}
    att_rel = str(consent.get("attestation_path") or "").strip()
    att_hash = str(consent.get("attestation_sha256") or "").strip().lower()
    if not att_rel:
        raise GateError("consent.attestation_path is required")
    if not att_hash:
        raise GateError("consent.attestation_sha256 is required")
    att_path = resolve_attestation_path(att_rel)
    if not att_path.is_file():
        raise GateError(f"consent attestation missing: {att_path}")
    digest = attestation_digest(att_path.read_bytes())
    if digest != att_hash:
        raise GateError(
            f"consent attestation hash mismatch expected {att_hash} got {digest}"
        )

    eng = data.get("engagement") if isinstance(data.get("engagement"), dict) else {}
    start = _parse_day(eng.get("start"), "engagement.start")
    end = _parse_day(eng.get("end"), "engagement.end")
    if end < start:
        raise GateError("engagement window ends before it starts")
    today = date.today()
    if today < start or today > end:
        raise GateError(f"today {today.isoformat()} is outside engagement window {start}..{end}")
    if _engagement_is_revoked(data, eng):
        raise GateError("engagement is revoked")

    ports_raw = data.get("ports_allowed")
    if ports_raw is None:
        ports_raw = eng.get("ports_allowed")
    ports_allowed: list[int] | None = None
    if ports_raw is not None:
        ports_allowed = []
        for item in _as_list(ports_raw):
            if isinstance(item, bool):
                raise GateError(f"invalid ports_allowed item {item!r}")
            try:
                num = int(item)
            except (TypeError, ValueError) as exc:
                raise GateError(f"invalid ports_allowed item {item!r}") from exc
            if not 1 <= num <= 65535:
                raise GateError(f"ports_allowed out of range: {num}")
            if num not in ports_allowed:
                ports_allowed.append(num)

    internal = data.get("internal") if isinstance(data.get("internal"), dict) else {}
    cidrs = _as_str_list(internal.get("cidrs"))
    ihosts = _as_str_list(internal.get("hosts"))
    if not cidrs and not ihosts:
        raise GateError("internal.cidrs or internal.hosts required")
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise GateError(f"invalid internal CIDR {cidr!r}") from exc
        if net.version != 4:
            raise GateError(f"IPv6 not supported: {cidr}")
        if is_open_internet_cidr(cidr):
            raise GateError(f"open-internet spray refused: {cidr}")

    external = data.get("external") if isinstance(data.get("external"), dict) else {}
    ehosts = _as_str_list(external.get("hosts"))
    domains = _as_str_list(external.get("domains"))
    eips = _as_str_list(external.get("ips"))
    if not ehosts and not domains and not eips:
        raise GateError("external hosts/domains/IPs required")
    for field, rows in (("hosts", ehosts), ("domains", domains), ("ips", eips)):
        for item in rows:
            _refuse_external_scope_item(field, item)
    for ip in eips:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise GateError(f"invalid external IP {ip!r}") from exc
        if parsed.is_unspecified or str(parsed) in {"0.0.0.0", "::"}:
            raise GateError(f"external ips refuses open-internet {ip!r}")

    allow = [t.strip().lower() for t in _as_str_list(data.get("allow_tools"))]
    forbidden = sorted(set(allow) & FORBIDDEN_TOOLS)
    if forbidden:
        raise GateError(f"LICENSE-LOCK: allow_tools names forbidden tools {forbidden}")

    orch = data.get("orchestrator") if isinstance(data.get("orchestrator"), dict) else {}
    try:
        discover_prefix = int(orch.get("discover_prefix") or 24)
        deepen_batch = int(orch.get("deepen_batch") or 3)
        max_live_shards = int(orch.get("max_live_shards") or 16)
        max_workers = int(orch.get("max_workers") or 2)
        host_timeout_sec = int(orch.get("host_timeout_sec") or 30)
    except (TypeError, ValueError) as exc:
        raise GateError("orchestrator batch/prefix/timeout must be integers") from exc
    if not 8 <= discover_prefix <= 32:
        raise GateError("orchestrator.discover_prefix must be 8..32")
    if not 2 <= deepen_batch <= 5:
        raise GateError("orchestrator.deepen_batch must be 2..5")
    if max_live_shards < 1:
        raise GateError("orchestrator.max_live_shards must be >= 1")
    if max_workers < 1:
        raise GateError("orchestrator.max_workers must be >= 1")
    if not 5 <= host_timeout_sec <= 300:
        raise GateError("orchestrator.host_timeout_sec must be 5..300")

    stages = orch.get("stages") if isinstance(orch.get("stages"), dict) else {}
    stage_discover = _as_bool(stages.get("discover"), True)
    # Fail closed: deepen is louder. Missing/false → do not deepen.
    stage_deepen = _as_bool(stages.get("deepen"), False)

    deepen_hosts = _as_str_list(orch.get("deepen_hosts"))
    for host in deepen_hosts:
        if _looks_wide_cidr(host):
            raise GateError(f"orchestrator.deepen_hosts refuses network {host!r}")

    stage_tools = orch.get("stage_tools") if isinstance(orch.get("stage_tools"), dict) else {}
    stage_tools_discover = [t.strip().lower() for t in _as_str_list(stage_tools.get("discover"))] or ["nmap"]
    stage_tools_deepen = [t.strip().lower() for t in _as_str_list(stage_tools.get("deepen"))] or [
        "nessus",
        "nessuscli",
    ]
    bad_discover = [t for t in stage_tools_discover if t not in DISCOVER_STAGE_TOOLS]
    if bad_discover:
        raise GateError(f"discover stage_tools must stay quiet (nmap only): {bad_discover}")
    bad_deepen = [t for t in stage_tools_deepen if t not in DEEPEN_STAGE_TOOLS]
    if bad_deepen:
        raise GateError(f"deepen stage_tools must be deepen-only: {bad_deepen}")
    for tool in stage_tools_discover + stage_tools_deepen:
        if tool in FORBIDDEN_TOOLS:
            raise GateError(f"LICENSE-LOCK: stage tool {tool!r} is forbidden")

    byo_raw = data.get("byo") or []
    byo: list[dict] = []
    if isinstance(byo_raw, list):
        for item in byo_raw:
            if isinstance(item, dict) and item.get("name"):
                byo.append(item)
            elif isinstance(item, str) and item.strip():
                byo.append({"name": item.strip(), "args": [], "sensor": "nmap"})
    for item in byo:
        tool = str(item.get("name") or "").strip().lower()
        if tool in FORBIDDEN_TOOLS:
            raise GateError(f"LICENSE-LOCK: BYO tool {tool!r} is forbidden")

    return Scope(
        path=scope_path,
        client_name=name,
        consent_path=att_path,
        consent_sha256=att_hash,
        window_start=start,
        window_end=end,
        internal_cidrs=cidrs,
        internal_hosts=ihosts,
        external_hosts=ehosts,
        external_domains=domains,
        external_ips=eips,
        allow_tools=allow,
        byo=byo,
        discover_prefix=discover_prefix,
        deepen_batch=deepen_batch,
        max_live_shards=max_live_shards,
        max_workers=max_workers,
        host_timeout_sec=host_timeout_sec,
        stage_discover=stage_discover,
        stage_deepen=stage_deepen,
        deepen_hosts=deepen_hosts,
        stage_tools_discover=stage_tools_discover,
        stage_tools_deepen=stage_tools_deepen,
        ports_allowed=ports_allowed,
        revoked=False,
    )
