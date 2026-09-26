"""Deduplicate Lynis + OpenSCAP + HardeningKitty findings for the same gap."""

from __future__ import annotations

from typing import Any


def _host(rec: dict[str, Any]) -> str:
    assets = rec.get("assets") or []
    if assets:
        return str(assets[0]).strip().lower()
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    return str(extra.get("host") or rec.get("name") or "").strip().lower()


def _control_key(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    return str(extra.get("control_key") or "").strip()


def _tool(rec: dict[str, Any]) -> str:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    labels = rec.get("labels") or []
    if extra.get("tool"):
        return str(extra["tool"])
    for name in ("lynis", "openscap", "hardeningkitty"):
        if name in labels:
            return name
    return str(rec.get("source") or "")


def dedupe_hardening(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep one finding per (host, control_key). Merge tool ids into extra.

    Assets and unmapped findings (no control_key) are left as-is so OpenSCAP
    fail/error rows that lack a Lynis alias still land.
    """
    out: list[dict[str, Any]] = []
    index: dict[tuple[str, str], dict[str, Any]] = {}
    seen_assets: set[str] = set()
    for rec in records:
        if rec.get("kind") == "asset":
            host = _host(rec)
            if host and host in seen_assets:
                continue
            if host:
                seen_assets.add(host)
            out.append(rec)
            continue
        if rec.get("kind") != "finding":
            out.append(rec)
            continue
        key = _control_key(rec)
        host = _host(rec)
        if not key or not host:
            out.append(rec)
            continue
        slot = (host, key)
        existing = index.get(slot)
        if existing is None:
            extra = rec.setdefault("extra", {})
            if isinstance(extra, dict):
                extra.setdefault("sources", [_tool(rec)])
            index[slot] = rec
            out.append(rec)
            continue
        extra = existing.setdefault("extra", {})
        if not isinstance(extra, dict):
            continue
        sources = extra.setdefault("sources", [])
        tool = _tool(rec)
        if tool and tool not in sources:
            sources.append(tool)
        also = extra.setdefault("also_ids", [])
        other_id = str((rec.get("extra") or {}).get("check_id") or rec.get("ref_id") or "")
        if other_id and other_id not in also:
            also.append(other_id)
        labels = existing.setdefault("labels", [])
        for lab in rec.get("labels") or []:
            if lab and lab not in labels:
                labels.append(lab)
    return out
