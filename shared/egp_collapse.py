"""Collapse pack_drop row-id twins that share one host/port EGP.

pack_drop extra.id is not a second plan row. Winner prefers nmap-port- check_id.
"""

from __future__ import annotations

from typing import Any


def prefer_nmap_port_check(rec: dict[str, Any]) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    return str(extra.get("check_id") or "").startswith("nmap-port-")


def collapse_same_egp(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """One included row per host/port EGP. pack_drop extra.id is not a second plan row."""
    from shared.poam_ledger import fp_v1
    from shared.port_fold import SUPERSEDED_REASON, egp_id_for

    winners: dict[str, dict[str, Any]] = {}
    for rec, decision in pairs:
        if not decision.get("include"):
            continue
        fp = fp_v1(rec)
        prev = winners.get(fp)
        if prev is None:
            winners[fp] = rec
            continue
        if prefer_nmap_port_check(rec) and not prefer_nmap_port_check(prev):
            winners[fp] = rec
            continue
        if prefer_nmap_port_check(prev):
            continue
        if str(rec.get("ref_id") or "") < str(prev.get("ref_id") or ""):
            winners[fp] = rec
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for rec, decision in pairs:
        nxt = dict(decision)
        if nxt.get("include"):
            winner = winners.get(fp_v1(rec))
            if winner is not None and winner is not rec:
                nxt["include"] = False
                nxt["reason"] = SUPERSEDED_REASON
                nxt["superseded_by"] = egp_id_for(winner)
                nxt["superseded_by_ref"] = str(winner.get("ref_id") or "")
        out.append((rec, nxt))
    return out
