"""Metis flood-guard: one POA&M decision set, named reasons, no silent drops.

classify(rec) → (klass, rollup_key, band). build() applies E1 telemetry
collapse, port-only fold, and escalate-budget heuristics. E4 late-only /
NOT_YET_LATE is deferred (CoS) and is not implemented.

fp_v1 is not computed here — apply_rollups() stamps ledger items after
apply_ledger and never remints EGP- IDs.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from shared.finding_types import extra_dict
from shared.schema import canon_severity

# Canonical reason codes (spec §12) plus the named reasons already on the wire.
REASON_CODES = frozenset(
    {
        "nse_misconfig",
        "severity_high_critical",
        "key_medium",
        "severity_low",
        "severity_medium",
        "escalate",
        "honeypot",
        "severity_info",
        "severity_medium_not_key",
        "telemetry",
        "telemetry_info",
        "telemetry_duplicate",
        "superseded_by_specific",
        "DUPLICATE_INSTANCE",
        "INFO_ONLY",
        "TELEMETRY",
        "NOT_A_WEAKNESS",
        "FALSE_POSITIVE_CANDIDATE",
        "MANUAL_CHECK",
        "MUTED",
        "unexplained",
        "UNEXPLAINED",
    }
)

EXCLUDE_KLASSES = frozenset(
    {
        "telemetry",
        "info",
        "honeypot",
        "not_a_weakness",
        "false_positive",
        "muted",
        "manual_check",
    }
)

REASON_CODE_FOR = {
    "severity_info": "INFO_ONLY",
    "telemetry_info": "TELEMETRY",
    "telemetry": "TELEMETRY",
    "telemetry_duplicate": "DUPLICATE_INSTANCE",
    "superseded_by_specific": "DUPLICATE_INSTANCE",
    "honeypot": "NOT_A_WEAKNESS",
    "NOT_A_WEAKNESS": "NOT_A_WEAKNESS",
    "FALSE_POSITIVE_CANDIDATE": "FALSE_POSITIVE_CANDIDATE",
    "FALSE_POSITIVE": "FALSE_POSITIVE_CANDIDATE",
    "MANUAL_CHECK": "MANUAL_CHECK",
    "MUTED": "MUTED",
    "DUPLICATE_INSTANCE": "DUPLICATE_INSTANCE",
    "INFO_ONLY": "INFO_ONLY",
    "TELEMETRY": "TELEMETRY",
    "unexplained": "UNEXPLAINED",
    "UNEXPLAINED": "UNEXPLAINED",
}

_FALSE_POSITIVE_TOKENS = frozenset(
    {"FALSE_POSITIVE", "FALSE_POSITIVE_CANDIDATE", "fp", "false_positive"}
)
_MANUAL_TOKENS = frozenset({"MANUAL_CHECK", "manual_check", "manual"})
_MUTED_TOKENS = frozenset({"MUTED", "muted"})
_NOT_WEAK_TOKENS = frozenset({"NOT_A_WEAKNESS", "not_a_weakness", "unmapped"})

# Escalate-budget: keep current lab/farm estates intact; collapse only floods.
_BUDGET_FLOOR = 200
_BUDGET_PER_ASSET = 5
_ESCALATE_BANDS = frozenset({"high", "critical"})


def reason_code_of(reason: str | None) -> str:
    raw = str(reason or "").strip()
    if not raw:
        return "UNEXPLAINED"
    return REASON_CODE_FOR.get(raw, raw if raw in REASON_CODES else "UNEXPLAINED")


def extra_exclude_token(rec: dict[str, Any]) -> str:
    extra = extra_dict(rec)
    raw = str(extra.get("exclude_reason") or extra.get("reason_code") or "").strip()
    if extra.get("muted") is True or extra.get("Muted") is True:
        return "MUTED"
    if extra.get("false_positive") is True:
        return "FALSE_POSITIVE_CANDIDATE"
    if extra.get("manual_check") is True:
        return "MANUAL_CHECK"
    if extra.get("not_a_weakness") is True:
        return "NOT_A_WEAKNESS"
    upper = raw.upper().replace(" ", "_")
    if raw in _MUTED_TOKENS or upper == "MUTED":
        return "MUTED"
    if raw in _FALSE_POSITIVE_TOKENS or upper in _FALSE_POSITIVE_TOKENS:
        return "FALSE_POSITIVE_CANDIDATE"
    if raw in _MANUAL_TOKENS or upper == "MANUAL_CHECK":
        return "MANUAL_CHECK"
    if raw in _NOT_WEAK_TOKENS or upper == "NOT_A_WEAKNESS":
        return "NOT_A_WEAKNESS"
    return ""


def rollup_key_for(rec: dict[str, Any], klass: str) -> str:
    extra = extra_dict(rec)
    if klass == "telemetry":
        from shared.control_map import telemetry_collapse_key

        rule, asset = telemetry_collapse_key(rec)
        return f"e1|{rule}|{asset}"
    if klass == "port_only":
        from shared.port_fold import finding_port, finding_proto, finding_hosts

        port = finding_port(rec)
        proto = finding_proto(rec) or "tcp"
        hosts = "|".join(sorted(finding_hosts(rec)))
        return f"port|{hosts}|{port}|{proto}"
    from shared.poam_ledger import weakness_key

    wk = weakness_key(rec)
    if wk:
        return wk
    return str(rec.get("ref_id") or rec.get("name") or extra.get("check_id") or "finding")


def classify(rec: dict[str, Any]) -> tuple[str, str, str]:
    """Return (klass, rollup_key, band). One class per record."""
    from shared.control_map import (
        _is_honeypot,
        is_telemetry_finding,
        keep_telemetry_on_plan,
    )
    from shared.port_fold import is_port_only_finding

    band = canon_severity(rec.get("severity"))
    token = extra_exclude_token(rec)
    if token == "MUTED":
        klass = "muted"
    elif token == "FALSE_POSITIVE_CANDIDATE":
        klass = "false_positive"
    elif token == "MANUAL_CHECK":
        klass = "manual_check"
    elif token == "NOT_A_WEAKNESS":
        klass = "not_a_weakness"
    elif _is_honeypot(rec):
        klass = "honeypot"
    elif is_telemetry_finding(rec) and not keep_telemetry_on_plan(rec):
        klass = "telemetry"
    elif band == "info":
        klass = "info"
    elif is_port_only_finding(rec):
        klass = "port_only"
    else:
        klass = "weakness"
    return klass, rollup_key_for(rec, klass), band


def escalate_budget(profile: str, assets_n: int) -> int:
    """Max included rows before same-key Lows collapse. No E4 late-only."""
    del profile  # full vs lighter already applied in poam_decision
    n = max(0, int(assets_n or 0))
    return max(_BUDGET_FLOOR, n * _BUDGET_PER_ASSET)


def _ref(rec: dict[str, Any]) -> str:
    return str(rec.get("ref_id") or "")


def _enrich(rec: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    out = dict(decision)
    klass, rk, band = classify(rec)
    out.setdefault("klass", klass)
    out.setdefault("rollup_key", rk)
    out.setdefault("band", band or out.get("severity") or canon_severity(rec.get("severity")))
    reason = str(out.get("reason") or "")
    if not reason:
        out["reason"] = "unexplained"
        reason = "unexplained"
    out["reason_code"] = out.get("reason_code") or reason_code_of(reason)
    return out


def _apply_e1(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """E1: repeated included telemetry that shares (rule, asset) → one row."""
    from shared.control_map import is_telemetry_finding, telemetry_collapse_key

    seen: dict[tuple[str, str], str] = {}
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for rec, decision in pairs:
        d = dict(decision)
        if (
            d.get("include")
            and d.get("severity") == "low"
            and is_telemetry_finding(rec)
        ):
            key = telemetry_collapse_key(rec)
            if key[0] and key in seen:
                d["include"] = False
                d["reason"] = "telemetry_duplicate"
                d["reason_code"] = "DUPLICATE_INSTANCE"
                d["rolled_into_ref"] = seen[key]
                d["klass"] = "telemetry"
            elif key[0]:
                seen[key] = _ref(rec)
                d.setdefault("klass", "telemetry")
        out.append((rec, d))
    return out


def _apply_port_fold(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    from shared.port_fold import SUPERSEDED_REASON, egp_id_for, port_only_superseders

    findings = [rec for rec, _d in pairs]
    superseders = port_only_superseders(findings)
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for rec, decision in pairs:
        d = dict(decision)
        winner = superseders.get(_ref(rec))
        if winner is not None:
            d["include"] = False
            d["reason"] = SUPERSEDED_REASON
            d["reason_code"] = "DUPLICATE_INSTANCE"
            d["superseded_by"] = egp_id_for(winner)
            d["superseded_by_ref"] = _ref(winner)
            d["rolled_into_ref"] = _ref(winner)
            d["klass"] = "port_only"
        out.append((rec, d))
    return out


def _apply_budget(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    profile: str,
    assets_n: int,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """When included > budget, collapse same-key Lows. High/Critical escalate."""
    budget = escalate_budget(profile, assets_n)
    included = [(rec, d) for rec, d in pairs if d.get("include")]
    if len(included) <= budget:
        return pairs
    groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for rec, d in included:
        if str(d.get("band") or d.get("severity") or "") in _ESCALATE_BANDS:
            d["reason"] = d.get("reason") or "escalate"
            continue
        if str(d.get("reason") or "") in {"nse_misconfig", "key_medium", "severity_high_critical"}:
            continue
        if str(d.get("klass") or "") != "weakness":
            continue
        if str(d.get("band") or d.get("severity") or "") != "low":
            continue
        groups[str(d.get("rollup_key") or _ref(rec))].append((rec, d))
    collapse_refs: dict[str, str] = {}
    for rk, members in groups.items():
        if len(members) < 2:
            continue
        ranked = sorted(
            members,
            key=lambda pair: (
                str(pair[1].get("severity") or ""),
                _ref(pair[0]),
            ),
        )
        parent = _ref(ranked[0][0])
        for rec, _d in ranked[1:]:
            collapse_refs[_ref(rec)] = parent
        del rk
    if not collapse_refs:
        return pairs
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for rec, decision in pairs:
        d = dict(decision)
        parent = collapse_refs.get(_ref(rec))
        if parent:
            d["include"] = False
            d["reason"] = "telemetry_duplicate" if d.get("klass") == "telemetry" else "DUPLICATE_INSTANCE"
            d["reason_code"] = "DUPLICATE_INSTANCE"
            d["rolled_into_ref"] = parent
        out.append((rec, d))
    return out


def build(
    decisions: Iterable[tuple[dict[str, Any], dict[str, Any]]],
    profile: str,
    assets_n: int,
    ledger: dict[str, Any] | None = None,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """One decision set. profile is full|lighter. E4 late-only is not implemented."""
    del ledger  # IDs are stamped later by apply_rollups; fp_v1 stays on the ledger
    if str(profile or "").lower() in {"late", "late-only", "not_yet_late"}:
        raise ValueError("E4 late-only / NOT_YET_LATE is deferred and not implemented")
    pairs = [(rec, _enrich(rec, dict(decision))) for rec, decision in decisions]
    pairs = _apply_e1(pairs)
    pairs = _apply_port_fold(pairs)
    pairs = _apply_budget(pairs, profile=profile, assets_n=assets_n)
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for rec, decision in pairs:
        d = _enrich(rec, decision)
        if d.get("include"):
            d.setdefault("rolled_into_ref", "")
        out.append((rec, d))
    return out


def flood_guard_summary(
    pairs: Iterable[tuple[dict[str, Any], dict[str, Any]]],
    *,
    profile: str,
    assets_n: int,
    merges_n: int = 0,
    members_n: int = 0,
) -> dict[str, Any]:
    budget = escalate_budget(profile, assets_n)
    included = 0
    unexplained = 0
    by_code: dict[str, int] = {}
    rolled = 0
    escalated = 0
    for _rec, decision in pairs:
        code = str(decision.get("reason_code") or reason_code_of(decision.get("reason")))
        if decision.get("include"):
            included += 1
            if str(decision.get("reason") or "") == "escalate" or str(
                decision.get("band") or ""
            ) in _ESCALATE_BANDS:
                escalated += 1
            continue
        if code in {"UNEXPLAINED", "unexplained"} or not str(decision.get("reason") or "").strip():
            unexplained += 1
            code = "UNEXPLAINED"
        by_code[code] = by_code.get(code, 0) + 1
        if decision.get("rolled_into_ref") or decision.get("superseded_by"):
            rolled += 1
    return {
        "profile": profile,
        "assets_n": int(assets_n or 0),
        "budget": budget,
        "included": included,
        "rolled": rolled,
        "escalated": escalated,
        "merges": int(merges_n or 0),
        "members": int(members_n or 0),
        "UNEXPLAINED": unexplained,
        "reason_codes": by_code,
        "e4_late_only": False,
    }


POAM_MEMBERS_FIELDS = (
    "member_ref_id",
    "parent_ref_id",
    "member_poam_id",
    "parent_poam_id",
    "reason_code",
    "source",
    "detail",
)
