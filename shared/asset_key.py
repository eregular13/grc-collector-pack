"""Fingerprint asset identity: ASSET ID + PORT (not the display name).

This is the swap point for Themis's EGA- asset ledger
(``urn:evergreen:asset`` / ``EGA-`` + 10 hex). Until that ledger is wired,
derive the ID from ``normalize_asset_id`` on the finding's primary asset
(ARN leaf / sAMAccount / host), then append ``:<port>/<proto>`` when
``extra.port`` is present (FedRAMP H7 / Completion Guide Col G).
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
    """Normalized asset id only (no port). Derived from normalize_asset_id today."""
    got = primary_asset(rec)
    if got:
        return got
    extra = extra_dict(rec)
    return normalize_asset_id(
        extra.get("arn") or extra.get("host") or rec.get("name") or ""
    )


def asset_key(finding: dict[str, Any]) -> str:
    """Stable fingerprint asset key: ``<asset_id>:<port>/<PROTO>``.

    Swap point for Themis's EGA- asset ledger. Do not key on the lower-cased
    display name. Callers that later resolve ``EGA-*`` should replace the
    body of this function (and keep the port/proto suffix).
    """
    base = asset_id(finding)
    return f"{base}{_port_proto(finding)}" if base else _port_proto(finding).lstrip(":")


def asset_host(finding: dict[str, Any]) -> str:
    """Asset id without port — used for coverage (same host, any port)."""
    return asset_id(finding)


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


def normalize_weakness_name(name: str) -> str:
    return _WS.sub(" ", str(name or "").strip().lower())


AssetKeyFn = Callable[[dict[str, Any]], str]
