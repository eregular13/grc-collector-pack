"""Collapse pack_drop row-id twins that share one host/port EGP.

pack_drop extra.id is not a second plan row. Winner prefers nmap-port- check_id.
Collapsed twins are aliases (merged_into:<survivor EGP>), not accepted risk.
"""

from __future__ import annotations

from typing import Any

MERGED_INTO_PREFIX = "merged_into:"


def prefer_nmap_port_check(rec: dict[str, Any]) -> bool:
    extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
    return str(extra.get("check_id") or "").startswith("nmap-port-")


def is_merged_into_reason(reason: str) -> bool:
    """True for collapsed-twin aliases. Not a register accept reason."""
    text = str(reason or "")
    return text.startswith(MERGED_INTO_PREFIX) and len(text) > len(MERGED_INTO_PREFIX)


def merged_into_reason(survivor_egp: str) -> str:
    """excluded.csv reason for a pack_drop twin folded into the survivor EGP."""
    egp = str(survivor_egp or "").strip()
    if not egp:
        raise ValueError("merged_into reason needs a survivor EGP")
    return f"{MERGED_INTO_PREFIX}{egp}"


def collapse_same_egp(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """One included row per host/port EGP. pack_drop extra.id is not a second plan row."""
    from shared.poam_ledger import fp_v1
    from shared.port_fold import egp_id_for

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
        winner = winners.get(fp_v1(rec))
        if winner is not None and winner is not rec:
            # Included extras and already-excluded extras (info twins, etc.)
            # that share the survivor EGP are aliases, not accepted risk.
            survivor = egp_id_for(winner)
            nxt["include"] = False
            nxt["reason"] = merged_into_reason(survivor)
            nxt["superseded_by"] = survivor
            nxt["superseded_by_ref"] = str(winner.get("ref_id") or "")
        out.append((rec, nxt))
    return out
