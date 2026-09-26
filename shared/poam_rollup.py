"""Metis flood-guard: one POA&M decision set, named reasons, no silent drops.

classify(rec) → (klass, rollup_key, band). build() applies E1 telemetry
collapse and port-only fold. §12.5 budget is report-only (exceeded, never
removes). E4 late-only / NOT_YET_LATE is deferred (CoS) and is not
implemented.

fp_v1 is not computed here — apply_rollups() stamps ledger items after
apply_ledger and never remints EGP- IDs.
"""

from __future__ import annotations

import math
import os
from collections import defaultdict
from typing import Any, Iterable

from shared.finding_types import extra_dict
from shared.schema import canon_severity

# Canonical §12.3 codes plus the named reasons already on the wire.
# NOT_YET_LATE is vocabulary-only (E4 deferred).
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
        "not_a_weakness",
        "DUPLICATE_INSTANCE",
        "INFO_ONLY",
        "TELEMETRY",
        "NOT_A_WEAKNESS",
        "FALSE_POSITIVE_CANDIDATE",
        "MANUAL_CHECK",
        "MUTED",
        "HONEYPOT",
        "LIGHTER_LOW",
        "LIGHTER_MEDIUM",
        "ACCEPTED_RISK",
        "UNVERIFIED_BANNER_CVE",
        "NOT_YET_LATE",
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
        "accepted_risk",
        "unverified_banner",
    }
)

LEGACY_REASON_MAP = {
    "severity_info": "INFO_ONLY",
    "telemetry_info": "TELEMETRY",
    "telemetry": "TELEMETRY",
    "telemetry_duplicate": "DUPLICATE_INSTANCE",
    "superseded_by_specific": "DUPLICATE_INSTANCE",
    "honeypot": "HONEYPOT",
    "not_a_weakness": "NOT_A_WEAKNESS",
    "severity_low": "LIGHTER_LOW",
    "severity_medium_not_key": "LIGHTER_MEDIUM",
}

REASON_CODE_FOR = {
    **LEGACY_REASON_MAP,
    "NOT_A_WEAKNESS": "NOT_A_WEAKNESS",
    "detection": "TELEMETRY",
    "FALSE_POSITIVE_CANDIDATE": "FALSE_POSITIVE_CANDIDATE",
    "FALSE_POSITIVE": "FALSE_POSITIVE_CANDIDATE",
    "MANUAL_CHECK": "MANUAL_CHECK",
    "MUTED": "MUTED",
    "DUPLICATE_INSTANCE": "DUPLICATE_INSTANCE",
    "INFO_ONLY": "INFO_ONLY",
    "TELEMETRY": "TELEMETRY",
    "HONEYPOT": "HONEYPOT",
    "LIGHTER_LOW": "LIGHTER_LOW",
    "LIGHTER_MEDIUM": "LIGHTER_MEDIUM",
    "ACCEPTED_RISK": "ACCEPTED_RISK",
    "UNVERIFIED_BANNER_CVE": "UNVERIFIED_BANNER_CVE",
    "NOT_YET_LATE": "NOT_YET_LATE",
    "unexplained": "UNEXPLAINED",
    "UNEXPLAINED": "UNEXPLAINED",
}

_FALSE_POSITIVE_TOKENS = frozenset(
    {"FALSE_POSITIVE", "FALSE_POSITIVE_CANDIDATE", "fp", "false_positive"}
)
_MANUAL_TOKENS = frozenset({"MANUAL_CHECK", "manual_check", "manual"})
_MUTED_TOKENS = frozenset({"MUTED", "muted"})
_NOT_WEAK_TOKENS = frozenset({"NOT_A_WEAKNESS", "not_a_weakness", "unmapped"})
_HONEYPOT_TOKENS = frozenset({"HONEYPOT", "honeypot"})
_ACCEPTED_TOKENS = frozenset({"ACCEPTED_RISK", "accepted_risk"})
_UNVERIFIED_TOKENS = frozenset({"UNVERIFIED_BANNER_CVE", "unverified_banner_cve"})

# Include reasons keep their wire name; LIGHTER_* only applies when excluded.
_INCLUDE_REASON_CODES = frozenset(
    {
        "nse_misconfig",
        "severity_high_critical",
        "key_medium",
        "severity_low",
        "severity_medium",
        "escalate",
    }
)

# §12.5: T = max(25, ceil(0.5 × assets)); cap = max(10, ceil(0.15 × assets)).
_BUDGET_PER100_DEFAULT = 50.0
_SOURCE_CAP_PER100_DEFAULT = 15.0
_BUDGET_FLOOR = 25
_SOURCE_CAP_FLOOR = 10
_ESCALATE_BANDS = frozenset({"high", "critical"})
BUDGET_PER100_ENV = "GRC_POAM_BUDGET_PER100"
SOURCE_CAP_PER100_ENV = "GRC_POAM_SOURCE_CAP_PER100"


def reason_code_of(reason: str | None, *, include: bool = False) -> str:
    raw = str(reason or "").strip()
    if not raw:
        return "UNEXPLAINED"
    if include and raw in _INCLUDE_REASON_CODES:
        return raw
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
    if extra.get("accepted_risk") is True:
        return "ACCEPTED_RISK"
    upper = raw.upper().replace(" ", "_")
    if raw in _MUTED_TOKENS or upper == "MUTED":
        return "MUTED"
    if raw in _FALSE_POSITIVE_TOKENS or upper in _FALSE_POSITIVE_TOKENS:
        return "FALSE_POSITIVE_CANDIDATE"
    if raw in _MANUAL_TOKENS or upper == "MANUAL_CHECK":
        return "MANUAL_CHECK"
    if raw in _NOT_WEAK_TOKENS or upper == "NOT_A_WEAKNESS":
        return "NOT_A_WEAKNESS"
    if raw in _HONEYPOT_TOKENS or upper == "HONEYPOT":
        return "HONEYPOT"
    if raw in _ACCEPTED_TOKENS or upper == "ACCEPTED_RISK":
        return "ACCEPTED_RISK"
    if raw in _UNVERIFIED_TOKENS or upper == "UNVERIFIED_BANNER_CVE":
        return "UNVERIFIED_BANNER_CVE"
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
    elif token == "ACCEPTED_RISK":
        klass = "accepted_risk"
    elif token == "UNVERIFIED_BANNER_CVE":
        klass = "unverified_banner"
    elif token == "HONEYPOT" or _is_honeypot(rec):
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


def _per100(env_name: str, default: float, floor: int, assets_n: int) -> int:
    n = max(0, int(assets_n or 0))
    raw = str(os.environ.get(env_name) or "").strip()
    rate = default
    if raw:
        try:
            rate = float(raw)
        except ValueError:
            rate = default
    return max(floor, math.ceil(rate * n / 100.0))


def budget_target(assets_n: int) -> int:
    """§12.5 T = max(25, ceil(0.5 × assets)). Tunable via GRC_POAM_BUDGET_PER100."""
    return _per100(BUDGET_PER100_ENV, _BUDGET_PER100_DEFAULT, _BUDGET_FLOOR, assets_n)


def budget_source_cap(assets_n: int) -> int:
    """§12.5 cap = max(10, ceil(0.15 × assets)). Tunable via GRC_POAM_SOURCE_CAP_PER100."""
    return _per100(
        SOURCE_CAP_PER100_ENV, _SOURCE_CAP_PER100_DEFAULT, _SOURCE_CAP_FLOOR, assets_n
    )


def escalate_budget(profile: str, assets_n: int) -> int:
    """Report-only target T. Never a removal cap. E4 late-only is not implemented."""
    del profile
    return budget_target(assets_n)


def budget_status(
    pairs: Iterable[tuple[dict[str, Any], dict[str, Any]]],
    *,
    assets_n: int,
) -> dict[str, Any]:
    """§12.5 report-only: status=exceeded lists sources over cap. Nothing is removed."""
    target = budget_target(assets_n)
    cap = budget_source_cap(assets_n)
    by_source: dict[str, int] = defaultdict(int)
    rows = 0
    for rec, decision in pairs:
        if not decision.get("include"):
            continue
        rows += 1
        by_source[str(rec.get("source") or "")] += 1
    over = sorted(src for src, count in by_source.items() if src and count > cap)
    status = "exceeded" if rows > target or over else "ok"
    return {
        "assets": int(assets_n or 0),
        "target": target,
        "cap": cap,
        "rows": rows,
        "status": status,
        "over_cap_sources": over,
    }


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
    out["reason_code"] = out.get("reason_code") or reason_code_of(
        reason, include=bool(out.get("include"))
    )
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
    """Report-only §12.5. High/Critical keep escalate; nothing is removed."""
    del profile
    snapshot = budget_status(pairs, assets_n=assets_n)
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for rec, decision in pairs:
        d = dict(decision)
        if d.get("include") and str(d.get("band") or d.get("severity") or "") in _ESCALATE_BANDS:
            d["reason"] = d.get("reason") or "escalate"
        d["budget_target"] = snapshot["target"]
        d["budget_cap"] = snapshot["cap"]
        d["budget_status"] = snapshot["status"]
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


def collect_finding_merges(
    prior: Iterable[dict[str, Any]],
    kept: Iterable[dict[str, Any]],
    *,
    detail: str,
) -> list[dict[str, Any]]:
    """C5 audit for a later dedupe pass that does not return its own merges."""
    from shared.finding_types import dedupe_key

    kept_list = list(kept)
    kept_ids = {id(rec) for rec in kept_list if rec.get("kind") == "finding"}
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for rec in kept_list:
        if rec.get("kind") != "finding":
            continue
        key = dedupe_key(rec)
        if key[0]:
            by_key[key] = rec
    extra: list[dict[str, Any]] = []
    for rec in prior:
        if rec.get("kind") != "finding" or id(rec) in kept_ids:
            continue
        key = dedupe_key(rec)
        parent = by_key.get(key) or {}
        extra.append(
            {
                "rec": rec,
                "kept": parent,
                "reason_code": "DUPLICATE_INSTANCE",
                "rolled_into": str(parent.get("ref_id") or ""),
                "source": rec.get("source") or "",
                "detail": detail,
            }
        )
    return extra


def flood_guard_summary(
    pairs: Iterable[tuple[dict[str, Any], dict[str, Any]]],
    *,
    profile: str,
    assets_n: int,
    merges_n: int = 0,
    members_n: int = 0,
    findings_in: int = 0,
    poam_rows: int = 0,
    excluded_n: int | None = None,
    lighter: bool = False,
) -> dict[str, Any]:
    """§12.6 flood_guard block. UNEXPLAINED stays a convenience field (must be 0)."""
    pair_list = list(pairs)
    included = 0
    unexplained = 0
    by_code: dict[str, int] = {}
    by_source: dict[str, int] = defaultdict(int)
    for rec, decision in pair_list:
        code = str(
            decision.get("reason_code")
            or reason_code_of(decision.get("reason"), include=bool(decision.get("include")))
        )
        if decision.get("include"):
            included += 1
            src = str(rec.get("source") or "")
            if src:
                by_source[src] += 1
            continue
        if code in {"UNEXPLAINED", "unexplained"} or not str(decision.get("reason") or "").strip():
            unexplained += 1
            code = "UNEXPLAINED"
        by_code[code] = by_code.get(code, 0) + 1
    if merges_n:
        by_code["DUPLICATE_INSTANCE"] = by_code.get("DUPLICATE_INSTANCE", 0) + int(merges_n)
    excluded_total = int(excluded_n) if excluded_n is not None else sum(by_code.values())
    members = int(members_n or included)
    budget = budget_status(pair_list, assets_n=assets_n)
    incoming = int(findings_in or (included + excluded_total))
    return {
        "findings_in": incoming,
        "duplicates_merged": int(merges_n or 0),
        "poam_rows": int(poam_rows or included),
        "poam_members": members,
        "excluded": excluded_total,
        "excluded_by_code": by_code,
        "rollup_level_by_source": {src: 1 for src in by_source},
        "budget": budget,
        "profile": profile,
        "lighter": bool(lighter) or str(profile or "").lower() == "lighter",
        "UNEXPLAINED": unexplained,
        "e4_late_only": False,
    }


# §12.6: poam_id, finding_ref_id, egp_id, asset, severity
POAM_MEMBERS_FIELDS = (
    "poam_id",
    "finding_ref_id",
    "egp_id",
    "asset",
    "severity",
)
