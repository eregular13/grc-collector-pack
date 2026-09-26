"""Fingerprint asset identity: EGA- asset UID + PORT (not the display name).

Swap point for the EGA- asset ledger (``urn:evergreen:asset`` /
``EGA-`` + 10 hex). The body of ``asset_key`` resolves
``extra.asset_uid`` / ``asset_uid()`` and keeps the ``:<port>/<PROTO>``
suffix (FedRAMP H7 / Completion Guide Col G).
"""

from __future__ import annotations

import re
from typing import Any, Callable

from shared.finding_types import extra_dict, normalize_asset_id, primary_asset

_WS = re.compile(r"\s+")


def _port_proto(rec: dict[str, Any]) -> str:
    extra = extra_dict(rec)
    port = str(extra.get("port") or "").strip()
    if not port or port == "0":
        return ""
    proto = str(
        extra.get("protocol") or extra.get("proto") or ""
    ).strip()
    if proto:
        return f":{port}/{proto.upper()}"
    return f":{port}"


def asset_id(rec: dict[str, Any]) -> str:
    """Normalized pre-EGA asset id (no port). Kept for the #131 migration map."""
    got = primary_asset(rec)
    if got:
        return got
    extra = extra_dict(rec)
    return normalize_asset_id(
        extra.get("arn") or extra.get("host") or rec.get("name") or ""
    )


def ega_asset_id(finding: dict[str, Any]) -> str:
    """``EGA-`` + 10 hex from ``extra.asset_uid`` or ``asset_uid()``.

    Identity-only: the finding/weakness name is never an anchor. #131 keyed
    on the primary asset (+ port); this keeps that host, not the plugin title.
    """
    extra = extra_dict(finding)
    uid = str(extra.get("asset_uid") or "").strip()
    if uid.startswith("EGA-"):
        return uid
    from shared.asset_ledger import asset_uid

    assets = [a for a in (finding.get("assets") or []) if str(a).strip()]
    identity = {
        "kind": "asset",
        "name": assets[0] if assets else extra.get("host") or extra.get("arn") or extra.get("fqdn") or "",
        "assets": assets,
        "extra": {
            k: v
            for k, v in extra.items()
            if k in {"ids", "ip", "mac", "fqdn", "hostname", "arn", "uuid", "bios_uuid", "agent", "netbios", "host"}
        },
    }
    uid = str(asset_uid(identity, None, observe=False) or "").strip()
    if uid.startswith("EGA-"):
        extra = finding.setdefault("extra", extra)
        if isinstance(extra, dict) and not str(extra.get("asset_uid") or "").startswith("EGA-"):
            extra["asset_uid"] = uid
    return uid


def legacy_asset_id_port_key(finding: dict[str, Any]) -> str:
    """#131 key: ``normalize_asset_id`` + port/proto. Migration source only."""
    base = asset_id(finding)
    return f"{base}{_port_proto(finding)}" if base else _port_proto(finding).lstrip(":")


def asset_key(finding: dict[str, Any]) -> str:
    """Stable fingerprint asset key: ``EGA-<hex>:<port>/<PROTO>``.

    Resolves Themis's EGA- asset ledger. Do not key on the lower-cased
    display name. Port/proto suffix is unchanged from #131.
    """
    base = ega_asset_id(finding)
    return f"{base}{_port_proto(finding)}" if base else _port_proto(finding).lstrip(":")


def asset_host(finding: dict[str, Any]) -> str:
    """Asset id without port — used for coverage (same host, any port)."""
    return ega_asset_id(finding) or asset_id(finding)


def legacy_name_asset_key(finding: dict[str, Any]) -> str:
    """Pre-migration key: lower-cased name (not asset id), plus port/proto.

    Used only to map existing POA&M IDs forward when fingerprint inputs
    change from name-based to asset-ID+port. Spec §5.4 / Gap 3 §3.3.
    """
    extra = extra_dict(finding)
    assets = finding.get("assets") or []
    raw = str(assets[0] if assets else extra.get("host") or finding.get("name") or "")
    name = raw.strip().lower().rstrip(".")
    suffix = _port_proto(finding)
    return f"{name}{suffix}" if name else suffix.lstrip(":")


def display_asset(finding: dict[str, Any]) -> str:
    """POA&M H display: scan-visible identifier plus `` (port/PROTO)``."""
    extra = extra_dict(finding)
    assets = finding.get("assets") or []
    raw = str(assets[0] if assets else extra.get("host") or finding.get("name") or "").strip()
    port = str(extra.get("port") or "").strip()
    proto = str(extra.get("protocol") or extra.get("proto") or "TCP").strip() or "TCP"
    if raw and port and port != "0":
        return f"{raw} ({port}/{proto.upper()})"
    return raw


def alias_display_names(finding: dict[str, Any]) -> list[str]:
    """Display names / IPs that a prior run may have keyed on."""
    extra = extra_dict(finding)
    ids = extra.get("ids") if isinstance(extra.get("ids"), dict) else {}
    names: list[str] = []
    for raw in (finding.get("assets") or []):
        names.append(str(raw).strip())
    names.append(str(finding.get("name") or "").strip())
    names.append(str(extra.get("host") or "").strip())
    for key in ("fqdn", "hostname", "arn"):
        names.append(str(ids.get(key) or extra.get(key) or "").strip())
    raw_ips = ids.get("ip") or extra.get("ip") or []
    if isinstance(raw_ips, str):
        raw_ips = [raw_ips]
    for ip in raw_ips:
        names.append(str(ip).strip())
    for other in extra.get("also_names") or []:
        names.append(str(other).strip())
    out: list[str] = []
    seen: set[str] = set()
    for name in names:
        if not name:
            continue
        token = name.lower()
        if token in seen:
            continue
        seen.add(token)
        out.append(name)
    return out


def normalize_weakness_name(name: str) -> str:
    return _WS.sub(" ", str(name or "").strip().lower())


AssetKeyFn = Callable[[dict[str, Any]], str]
