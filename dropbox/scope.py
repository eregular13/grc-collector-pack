"""Load and fail-closed validate SCOPE.yaml."""

from __future__ import annotations

import hashlib
import ipaddress
import os
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

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

ALLOWED_RUNNERS = frozenset({"lynis", "ss", "ip", "curl", "testssl", "testssl.sh"})
EXTERNAL_STAGE_TOOLS = frozenset({"curl", "testssl", "testssl.sh"})

# Quiet discover may only plan/run inventory tools. Deepen (louder) is a separate list.
DISCOVER_STAGE_TOOLS = frozenset({"nmap"})
DEEPEN_STAGE_TOOLS = frozenset({"nessus", "nessuscli"})


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


def load_scope(path: Path | None = None) -> Scope:
    scope_path = Path(path) if path else default_scope_path()
    if not scope_path.is_file():
        raise GateError(f"no SCOPE file at {scope_path}")
    data = load_yaml(scope_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data:
        raise GateError("SCOPE.yaml is empty or not a mapping")

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
    att_path = Path(att_rel)
    if not att_path.is_absolute():
        att_path = (ROOT / att_rel).resolve()
    if not att_path.is_file():
        raise GateError(f"consent attestation missing: {att_path}")
    digest = hashlib.sha256(att_path.read_bytes()).hexdigest()
    if digest != att_hash:
        raise GateError("consent attestation hash mismatch")

    eng = data.get("engagement") if isinstance(data.get("engagement"), dict) else {}
    start = _parse_day(eng.get("start") or eng.get("begin"), "engagement.start")
    end = _parse_day(eng.get("end"), "engagement.end")
    if end < start:
        raise GateError("engagement window ends before it starts")
    today = date.today()
    if today < start or today > end:
        raise GateError(f"today {today.isoformat()} is outside engagement window {start}..{end}")

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
    )
