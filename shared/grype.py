"""Parse Anchore Grype JSON (``grype <target> -o json``). Parse-only.

Shape (public grype JSON output): top-level ``matches`` (each with
``vulnerability`` {id, severity, fix{versions,state}}, ``relatedVulnerabilities``
[{id}], ``artifact`` {name, version, type, locations}), ``source``
{type: image|directory|file, target: {userInput|...} or str} and
``descriptor`` {name: "grype", timestamp}.

CVE ids come only from structured fields: ``vulnerability.id`` and
``relatedVulnerabilities[].id`` (a GHSA match names its CVE there). URLs,
descriptions and ``dataSource`` are never mined.
"""
from __future__ import annotations

import re
from typing import Any

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def is_grype(payload: Any) -> bool:
    if not isinstance(payload, dict) or not isinstance(payload.get("matches"), list):
        return False
    desc = payload.get("descriptor") if isinstance(payload.get("descriptor"), dict) else {}
    if str(desc.get("name") or "").lower() == "grype":
        return True
    for m in payload["matches"]:
        if isinstance(m, dict) and isinstance(m.get("vulnerability"), dict) and isinstance(m.get("artifact"), dict):
            return True
    return not payload["matches"] and isinstance(payload.get("source"), dict)


def grype_target(payload: dict[str, Any]) -> str:
    src = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    tgt = src.get("target")
    if isinstance(tgt, dict):
        name = tgt.get("userInput") or (tgt.get("tags") or [None])[0] or tgt.get("path") or tgt.get("imageID")
        return str(name or "image").strip() or "image"
    if isinstance(tgt, str) and tgt.strip():
        return tgt.strip()
    return "image"


def grype_host_target(payload: dict[str, Any], fallback: str) -> str:
    """Asset name for a grype scan. A whole-filesystem ``dir:/`` scan has
    target ``/``, which names no host (two hosts would merge into one asset).
    Use ``source.name`` (``grype --name``) when it is a real label, else the
    report file stem (``fallback``)."""
    target = grype_target(payload)
    if target.rstrip("/") != "":
        return target
    src = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    name = str(src.get("name") or "").strip()
    if name and name.rstrip("/") != "":
        return name
    return str(fallback or "").strip() or target


def grype_ids(payload: dict[str, Any]) -> dict[str, Any]:
    src = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    tgt = src.get("target") if isinstance(src.get("target"), dict) else {}
    if str(src.get("type") or "").lower() != "image":
        return {}
    digests = tgt.get("repoDigests") if isinstance(tgt.get("repoDigests"), list) else []
    return {
        "image_digest": [str(x) for x in digests if x],
        "image_id": str(tgt.get("imageID") or "").strip(),
        "image_ref": grype_target(payload),
    }


def match_cves(match: dict[str, Any]) -> list[str]:
    out: list[str] = []
    vuln = match.get("vulnerability") if isinstance(match.get("vulnerability"), dict) else {}
    ids = [vuln.get("id")]
    for rel in match.get("relatedVulnerabilities") or []:
        if isinstance(rel, dict):
            ids.append(rel.get("id"))
    for raw in ids:
        cid = str(raw or "").strip().upper()
        if CVE_RE.match(cid) and cid not in out:
            out.append(cid)
    return out


def iter_grype_matches(payload: Any) -> list[dict[str, Any]]:
    """One row per match. ``cves`` holds structured CVE ids (may be empty)."""
    if not is_grype(payload):
        return []
    rows: list[dict[str, Any]] = []
    for m in payload.get("matches") or []:
        if not isinstance(m, dict):
            continue
        vuln = m.get("vulnerability") if isinstance(m.get("vulnerability"), dict) else {}
        art = m.get("artifact") if isinstance(m.get("artifact"), dict) else {}
        fix = vuln.get("fix") if isinstance(vuln.get("fix"), dict) else {}
        versions = [str(v) for v in (fix.get("versions") or []) if str(v).strip()]
        rows.append(
            {
                "vid": str(vuln.get("id") or "").strip() or "GRYPE-UNKNOWN",
                "cves": match_cves(m),
                "severity": str(vuln.get("severity") or "").strip(),
                "pkg": str(art.get("name") or "").strip(),
                "version": str(art.get("version") or "").strip(),
                "pkg_type": str(art.get("type") or "").strip(),
                "fixed": versions[0] if versions else "",
                "fix_state": str(fix.get("state") or "").strip(),
                "description": str(vuln.get("description") or "").strip(),
            }
        )
    return rows


def grype_scan_time(payload: dict[str, Any]) -> str:
    desc = payload.get("descriptor") if isinstance(payload.get("descriptor"), dict) else {}
    return str(desc.get("timestamp") or "").strip()
