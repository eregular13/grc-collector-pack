"""Finding → CPG / NIST CSF 2.0 stubs. Unknown → UNMAPPED."""

from __future__ import annotations

from typing import Any


def map_finding(rec: dict[str, Any]) -> dict[str, Any]:
    blob = f"{rec.get('name') or ''} {rec.get('description') or ''} {rec.get('category') or ''}".lower()
    if "smbv1" in blob or "smb 445" in blob or "tcp/445" in blob or "smb 445 exposed" in blob:
        return {
            "controls": ["CPG_2_W", "PR.AA-01", "DE.CM-01"],
            "frameworks": ["CPG", "NIST CSF 2.0"],
            "reason": "SMBv1 / SMB exposure",
            "action": "Disable SMBv1, restrict TCP/445, patch and segment the host.",
        }
    if "telnet exposed" in blob or blob.startswith("telnet"):
        return {
            "controls": ["CPG_2_W", "PR.PS-01"],
            "frameworks": ["CPG", "NIST CSF 2.0"],
            "reason": "Cleartext remote admin",
            "action": "Disable Telnet; require SSH or a jump host.",
        }
    if "public" in blob and "s3" in blob:
        return {
            "controls": ["CPG_1_E", "PR.DS-01"],
            "frameworks": ["CPG", "NIST CSF 2.0"],
            "reason": "Public object storage",
            "action": "Block public ACLs/policies; enable default encryption.",
        }
    return {
        "controls": ["UNMAPPED"],
        "frameworks": [],
        "reason": "no obvious CPG/CSF map for this finding text",
        "action": "Triage with the asset owner; attach evidence.",
    }


def poam_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for rec in findings:
        mapped = map_finding(rec)
        assets = rec.get("assets") or []
        rows.append(
            {
                "weakness": rec.get("name"),
                "asset": "|".join(assets) if isinstance(assets, list) else str(assets),
                "severity": rec.get("severity"),
                "control_refs": "|".join(mapped["controls"]),
                "recommended_action": mapped["action"],
                "owner": "",
                "milestone": "",
                "status": "open",
                "ref_id": rec.get("ref_id"),
                "map_reason": mapped["reason"],
            }
        )
    return rows
