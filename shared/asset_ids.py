"""Collect and normalize asset identifiers into ``extra.ids``.

Match order is §6.3 (Tenable-shaped), not the original §5.4 table:

    UUID → BIOS UUID → MAC → NetBIOS → FQDN → IP

Cloud ARN and container class keys sit above that host ladder.
A missing UUID is never evidence of a different host. A UUID seen
with two distinct FQDN+MAC sets is a collision and is not a match key.
Locally administered / randomized MACs are stored but never matched.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable
from urllib.parse import urlparse

ASSET_UID_PREFIX = "EGA-"
ASSET_NAMESPACE = "urn:evergreen:asset"
LEASE_DAYS = 7

# §6.3 host ladder (explicit). Agent is the §6.3 medium Wazuh key
# (wazuh:<mgr>:<id>) inserted after BIOS — it is not a Tenable field
# but is the only stable id many agent drops carry.
MATCH_ORDER = (
    "uuid",
    "bios_uuid",
    "agent",
    "mac",
    "netbios",
    "fqdn",
    "ip",
    # Last-resort collector-dupe keys (not Tenable). Same short name with a
    # conflicting stronger id still splits (§5.7.10).
    "hostname",
    "name",
)

CONTAINER_ORDER = ("image_digest", "artifact_id", "image_id")
CLOUD_ORDER = ("arn",)

# Higher number = stronger. Used only for the conflict rule.
STRENGTH: dict[str, int] = {
    "image_digest": 100,
    "artifact_id": 99,
    "image_id": 98,
    "image_ref": 97,
    "arn": 96,
    "uuid": 90,
    "bios_uuid": 80,
    "agent": 70,
    "mac": 60,
    "netbios": 50,
    "fqdn": 40,
    "ip": 10,
    "hostname": 1,
    "name": 0,
}

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_MAC_RE = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")
_PLACEHOLDER_SERIAL = frozenset(
    {
        "",
        "unknown",
        "none",
        "n/a",
        "na",
        "0",
        "bss-0123456789",
        "0123456789",
    }
)
_NON_FQDN = frozenset({"localhost", "localhost.localdomain", "localdomain"})


def extra_dict(rec: dict[str, Any] | None) -> dict[str, Any]:
    extra = (rec or {}).get("extra")
    return extra if isinstance(extra, dict) else {}


def as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(as_list(item))
        return out
    text = str(value).replace("\r", "\n")
    parts = [p.strip() for p in re.split(r"[\n,;]+", text) if p.strip()]
    return parts or ([str(value).strip()] if str(value).strip() else [])


def normalize_uuid(value: Any) -> str:
    text = str(value or "").strip().strip("{}").lower()
    if text.startswith("urn:uuid:"):
        text = text[9:]
    return text if _UUID_RE.match(text) else ""


def normalize_mac(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", ":")
    if not _MAC_RE.fullmatch(text):
        match = _MAC_RE.search(text)
        if not match:
            return ""
        text = match.group(0).lower().replace("-", ":")
    parts = text.split(":")
    if len(parts) != 6:
        return ""
    return ":".join(p.zfill(2) for p in parts)


def mac_is_locally_administered(mac: str) -> bool:
    """True for U/L-bit MACs (locally administered / randomized) and all-zero."""
    norm = normalize_mac(mac)
    if not norm or norm == "00:00:00:00:00:00":
        return True
    try:
        first = int(norm.split(":")[0], 16)
    except ValueError:
        return True
    return bool(first & 0x02)


def normalize_fqdn(value: Any) -> str:
    text = str(value or "").strip().rstrip(".").lower()
    if not text or text in _NON_FQDN:
        return ""
    if "/" in text or "://" in text:
        return ""
    if "." not in text:
        return ""
    if _looks_ip(text):
        return ""
    return text


def normalize_netbios(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("<") and text.endswith(">"):
        return ""
    if text.lower() in {"unknown", "<unknown>", "workgroup"}:
        return ""
    if _looks_ip(text) or "." in text:
        return ""
    return text.upper()


def normalize_ip(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _looks_ip(value: str) -> bool:
    return bool(normalize_ip(value))


def normalize_hostname(value: Any) -> str:
    text = str(value or "").strip().rstrip(".").lower()
    if not text or text in _NON_FQDN or _looks_ip(text):
        return ""
    if "/" in text or "://" in text or " " in text:
        return ""
    if "." in text:
        return ""
    return text


def normalize_arn(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower().startswith("arn:"):
        return text
    return ""


def normalize_digest(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text.lower()


def first_nonempty(values: Iterable[Any]) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def ids_blank() -> dict[str, Any]:
    return {
        "uuid": "",
        "bios_uuid": "",
        "mac": [],
        "mac_raw": [],
        "netbios": "",
        "fqdn": "",
        "ip": [],
        "hostname": "",
        "arn": "",
        "image_digest": [],
        "artifact_id": "",
        "image_id": "",
        "image_ref": "",
        "agent": "",
        "serial": "",
        "scope": "",
        "domain": "",
        "id_quality": "",
        "name": "",
    }


def merge_ids(*parts: dict[str, Any] | None) -> dict[str, Any]:
    out = ids_blank()
    for part in parts:
        if not isinstance(part, dict):
            continue
        for key in ("uuid", "bios_uuid"):
            got = normalize_uuid(part.get(key) or out.get(key))
            if got:
                out[key] = got
        raw_macs = as_list(part.get("mac_raw")) + as_list(part.get("mac"))
        for mac in raw_macs:
            norm = normalize_mac(mac)
            if not norm:
                continue
            if norm not in out["mac_raw"]:
                out["mac_raw"].append(norm)
            if not mac_is_locally_administered(norm) and norm not in out["mac"]:
                out["mac"].append(norm)
        netbios = normalize_netbios(part.get("netbios"))
        if netbios:
            out["netbios"] = netbios
        fqdn = normalize_fqdn(part.get("fqdn") or part.get("host-fqdn"))
        if fqdn:
            out["fqdn"] = fqdn
        for ip in as_list(part.get("ip")):
            norm = normalize_ip(ip)
            if norm and norm not in out["ip"]:
                out["ip"].append(norm)
        host = normalize_hostname(part.get("hostname"))
        if host:
            out["hostname"] = host
        arn = normalize_arn(part.get("arn"))
        if arn:
            out["arn"] = arn
        for digest in as_list(part.get("image_digest") or part.get("RepoDigests")):
            norm = normalize_digest(digest)
            if norm and norm not in out["image_digest"]:
                out["image_digest"].append(norm)
        for key in ("artifact_id", "image_id", "image_ref", "agent", "serial", "scope", "domain", "id_quality", "name"):
            got = str(part.get(key) or "").strip()
            if got:
                out[key] = got
    serial = str(out.get("serial") or "").strip()
    if serial.lower() in _PLACEHOLDER_SERIAL:
        out["serial"] = ""
    return out


def _host_from_url(text: str) -> str:
    if "://" not in text:
        return ""
    try:
        return str(urlparse(text).hostname or "").strip()
    except ValueError:
        return ""


def classify_name(name: Any) -> dict[str, Any]:
    """Turn a display name into identifier fields without inventing strength."""
    text = str(name or "").strip()
    if not text:
        return {}
    host = _host_from_url(text)
    if host:
        ip = normalize_ip(host)
        if ip:
            return {"ip": [ip]}
        fqdn = normalize_fqdn(host)
        if fqdn:
            return {"fqdn": fqdn}
        short = normalize_hostname(host)
        if short:
            return {"hostname": short}
    ip = normalize_ip(text)
    if ip:
        return {"ip": [ip]}
    fqdn = normalize_fqdn(text)
    if fqdn:
        return {"fqdn": fqdn}
    short = normalize_hostname(text)
    if short:
        return {"hostname": short}
    netbios = normalize_netbios(text)
    if netbios and text.upper() == netbios:
        return {"netbios": netbios}
    arn = normalize_arn(text)
    if arn:
        return {"arn": arn}
    return {"name": text}


def lift_extra_fields(extra: dict[str, Any]) -> dict[str, Any]:
    """Pull identifiers that collectors already store beside extra.ids."""
    blob: dict[str, Any] = {}
    if extra.get("ids") and isinstance(extra["ids"], dict):
        blob.update(extra["ids"])
    for key in (
        "uuid",
        "bios_uuid",
        "netbios",
        "fqdn",
        "hostname",
        "arn",
        "artifact_id",
        "image_id",
        "image_ref",
        "agent",
        "serial",
        "scope",
        "domain",
        "id_quality",
    ):
        if extra.get(key) not in (None, ""):
            blob[key] = extra.get(key)
    if extra.get("ip"):
        blob.setdefault("ip", as_list(extra.get("ip")))
    if extra.get("mac"):
        blob.setdefault("mac", as_list(extra.get("mac")))
    if extra.get("mac_raw"):
        blob.setdefault("mac_raw", as_list(extra.get("mac_raw")))
    if extra.get("RepoDigests") or extra.get("image_digest"):
        blob.setdefault("image_digest", extra.get("image_digest") or extra.get("RepoDigests"))
    return blob


def ids_from_record(rec: dict[str, Any] | None) -> dict[str, Any]:
    rec = rec or {}
    extra = extra_dict(rec)
    parts = [
        lift_extra_fields(extra),
        classify_name(rec.get("name")),
    ]
    assets = rec.get("assets") or []
    if assets:
        parts.append(classify_name(assets[0]))
    return merge_ids(*parts)


def stamp_ids(extra: dict[str, Any] | None, **fields: Any) -> dict[str, Any]:
    """Merge identifier fields into extra.ids and return extra."""
    extra = dict(extra or {})
    existing = extra.get("ids") if isinstance(extra.get("ids"), dict) else {}
    merged = merge_ids(existing, lift_extra_fields(extra), fields)
    extra["ids"] = {k: v for k, v in merged.items() if v not in ("", [], None)}
    return extra


def values_overlap(left: Any, right: Any) -> bool:
    a = {str(x).lower() for x in as_list(left) if str(x).strip()}
    b = {str(x).lower() for x in as_list(right) if str(x).strip()}
    return bool(a and b and a & b)


def id_values(ids: dict[str, Any], key: str) -> list[str]:
    raw = ids.get(key)
    if key in {"mac", "ip", "image_digest", "mac_raw"}:
        return [str(x) for x in as_list(raw) if str(x).strip()]
    text = str(raw or "").strip()
    return [text] if text else []


def strongest_anchor(ids: dict[str, Any], *, skip: set[str] | None = None) -> tuple[str, str]:
    """Return (type, value) for UID generation — strongest present alias."""
    skip = skip or set()
    for key in (
        "image_ref",
        "image_digest",
        "artifact_id",
        "image_id",
        "arn",
        "uuid",
        "bios_uuid",
        "agent",
        "mac",
        "netbios",
        "fqdn",
        "ip",
        "hostname",
    ):
        if key in skip:
            continue
        vals = id_values(ids, key)
        if vals:
            return key, vals[0]
    name = str(ids.get("name") or "").strip()
    return "name", name or "unknown"


def display_name_rank(name: Any) -> int:
    """Higher is a better CISO/canonical display name. Casing is not ranked."""
    text = str(name or "").strip()
    if not text:
        return 0
    inner = _host_from_url(text) or text
    if text.lower().startswith("arn:") or text.startswith("sha256:"):
        return 40
    # Image refs look like repo/app:tag — not http(s) URLs.
    if "/" in text and "://" not in text:
        return 40
    if normalize_fqdn(inner) or normalize_fqdn(text):
        return 30
    if normalize_netbios(inner) or normalize_hostname(inner):
        return 20
    if normalize_ip(inner) or normalize_ip(text):
        return 10
    return 5


def prefer_display_name(current: Any, candidate: Any) -> str:
    """Keep original casing. Upgrade IP/empty names to FQDN/image-ref."""
    cur = str(current or "").strip()
    cand = str(candidate or "").strip()
    if not cur:
        return cand
    if not cand:
        return cur
    if display_name_rank(cand) > display_name_rank(cur):
        return cand
    return cur


def display_uai(ids: dict[str, Any]) -> str:
    """IIW Unique Asset Identifier. §5 display order, not match order.

    container image ref > FQDN > cloud resource ID > IP.
    Never a short hostname alone when a stronger display id exists.
    """
    ref = str(ids.get("image_ref") or "").strip()
    if ref:
        return ref
    fqdn = str(ids.get("fqdn") or "").strip()
    if fqdn:
        return fqdn
    arn = str(ids.get("arn") or "").strip()
    if arn:
        return arn
    ips = id_values(ids, "ip")
    if ips:
        return ips[0]
    netbios = str(ids.get("netbios") or "").strip()
    if netbios:
        return netbios
    host = str(ids.get("hostname") or "").strip()
    return host


def fqdn_mac_fingerprint(ids: dict[str, Any]) -> tuple[str, frozenset[str]] | None:
    fqdn = str(ids.get("fqdn") or "").strip().lower()
    macs = frozenset(id_values(ids, "mac"))
    if not fqdn and not macs:
        return None
    return (fqdn, macs)


def is_container(ids: dict[str, Any]) -> bool:
    return bool(
        ids.get("image_ref")
        or ids.get("image_digest")
        or ids.get("artifact_id")
        or ids.get("image_id")
    )
