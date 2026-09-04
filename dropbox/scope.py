"""Load and fail-closed validate SCOPE.yaml."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from dropbox.yaml_lite import load_yaml

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_TOOLS = frozenset(
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

ALLOWED_RUNNERS = frozenset({"lynis", "ss", "ip", "curl"})


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

    def external_names(self) -> set[str]:
        names = {h.lower().rstrip(".") for h in self.external_hosts}
        names |= {d.lower().rstrip(".") for d in self.external_domains}
        names |= {i.lower() for i in self.external_ips}
        return names

    def allows_external_target(self, target: str) -> bool:
        raw = (target or "").strip()
        if not raw:
            return False
        host = raw.split("://")[-1].split("/")[0].split(":")[0].lower().rstrip(".")
        if not host:
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
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise GateError(f"invalid internal CIDR {cidr!r}") from exc

    external = data.get("external") if isinstance(data.get("external"), dict) else {}
    ehosts = _as_str_list(external.get("hosts"))
    domains = _as_str_list(external.get("domains"))
    eips = _as_str_list(external.get("ips"))
    if not ehosts and not domains and not eips:
        raise GateError("external hosts/domains/IPs required")
    for ip in eips:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise GateError(f"invalid external IP {ip!r}") from exc

    allow = [t.strip().lower() for t in _as_str_list(data.get("allow_tools"))]
    forbidden = sorted(set(allow) & FORBIDDEN_TOOLS)
    if forbidden:
        raise GateError(f"LICENSE-LOCK: allow_tools names forbidden tools {forbidden}")

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
    )
