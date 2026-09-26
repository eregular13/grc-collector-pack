"""Risk-register + POA&M shape for SAMPLE, farm_drop, and lab prove SoR outputs.

Column contract matches schemas/ciso-assistant.md and collectors/grc_loader.py.
Lab prove (`--use-existing-in`) also calls assert_risk_register_and_poam on out/.
Dest_in LAB.txt / DEMO-adapter fail-closed lives in scripts/prove_ciso.py
(LAB_SHAPE_FAIL). Not an operator entrypoint. SAMPLE/DEMO/LAB labels stay honest.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from shared.control_map import is_poam_exclude_reason
from shared.egp_collapse import is_merged_into_reason
from shared.poam_fields import POAM_EXTRA_FIELDS

# Risk register = findings + risk_scenarios (one scenario per canonical finding).
# vulnerabilities.csv is CVE/secrets/sast only — header-only is allowed when
# the estate has no CVE-class rows (farm_drop pack_drop is exposure, not CVE).
REGISTER_CSVS = (
    "assets.csv",
    "findings.csv",
    "applied_controls.csv",
    "risk_scenarios.csv",
)
CVE_CLASS_CSV = "vulnerabilities.csv"
MUST_EXIST_CSVS = REGISTER_CSVS + (CVE_CLASS_CSV,)
OPTIONAL_CSVS = ("evidences.csv",)
ROW_REQUIRED_WHEN_FINDINGS = (
    "assets.csv",
    "findings.csv",
    "applied_controls.csv",
    "risk_scenarios.csv",
)
CISO_HEADERS = {
    "assets.csv": (
        "ref_id,name,description,domain,type,reference_link,observation,"
        "filtering_labels,parent_assets"
    ),
    "applied_controls.csv": (
        "ref_id,name,description,domain,status,category,priority,csf_function"
    ),
    "evidences.csv": "name,description",
    "findings.csv": "ref_id,name,description,severity,status,filtering_labels",
    "vulnerabilities.csv": (
        "ref_id,name,description,status,severity,assets,applied_controls"
    ),
    "risk_scenarios.csv": (
        "ref_id;assets;threats;name;description;existing_controls;"
        "current_impact;current_proba;current_risk;additional_controls;"
        "residual_impact;residual_proba;residual_risk;treatment"
    ),
}
POAM_LEGACY_HEADER = "weakness,asset,severity,framework_refs,recommended_fix,owner,due,status,estate"
POAM_HEADER = POAM_LEGACY_HEADER + "," + ",".join(POAM_EXTRA_FIELDS)
EXCLUDED_HEADER = "id,finding_ref_id,weakness,asset,severity,excluded_reason,superseded_by"
EXCLUDED_FIELDS = tuple(EXCLUDED_HEADER.split(","))
POAM_REL = Path("poam") / "poam.csv"
POAM_MD_REL = Path("poam") / "poam.md"
FINDING_SEV = frozenset({"low", "medium", "high", "critical"})
VULN_SEV = frozenset({"Information", "Low", "Medium", "High", "Critical"})
SCENARIO_LEVELS = frozenset({"Low", "Moderate", "High", "Very High"})

# ASCII-only: Windows cp1252 consoles cannot print U+2260 / U+2192.
REGISTER_OK_LINE = "REGISTER_SHAPE=ok findings_to_poam != empty paying_day=FAIL"

# Documented count relationship after weakness dedupe:
#   mitigate == POA&M == CTL; accept == non-merged excluded
#   risk_scenarios == findings.csv + vulnerabilities.csv + kind_excluded
#     - merged_into:<EGP> aliases (pack_drop twins, not accepted risk)
#   POA&M == open_risks (include_poam). findings.csv is non-CVE; vulns are CVE-class.
#   kind:excluded (Custodian cost, osquery unmapped) stay on the register as accept.
#   CISO Community risk_scenarios.csv has no justification/comment column
#   (CISO_HEADERS below). Accept reason lives in poam/excluded.csv
#   excluded_reason. existing_controls is not an exclusion dump.


def count_merged_aliases(ciso_or_out: Path, summary: dict[str, Any] | None = None) -> int:
    """How many excluded.csv rows are collapsed pack_drop twins, not accept."""
    out = resolve_out_dir(ciso_or_out)
    excluded_path = out / "poam" / "excluded.csv"
    from_csv = 0
    if excluded_path.is_file() and first_nonempty_line(excluded_path) == EXCLUDED_HEADER:
        from_csv = sum(
            1
            for row in csv_rows(excluded_path)
            if is_merged_into_reason(str(row.get("excluded_reason") or ""))
        )
    from_summary = 0
    reasons = (summary or {}).get("excluded_by_reason") or {}
    if isinstance(reasons, dict):
        from_summary = sum(
            int(count) for key, count in reasons.items() if is_merged_into_reason(str(key))
        )
    if from_csv and from_summary and from_csv != from_summary:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL merged aliases csv={from_csv} summary={from_summary}"
        )
    return from_csv or from_summary


def register_treatment_counts(ciso_or_out: Path) -> dict[str, int]:
    """mitigate / accept / CTL / excluded split. Merged twins are not accept."""
    out = resolve_out_dir(ciso_or_out)
    ciso = ciso_dir_of(out)
    scenarios = csv_rows(ciso / "risk_scenarios.csv", delimiter=";") if (ciso / "risk_scenarios.csv").is_file() else []
    controls = csv_rows(ciso / "applied_controls.csv") if (ciso / "applied_controls.csv").is_file() else []
    excluded_path = out / "poam" / "excluded.csv"
    excluded = csv_rows(excluded_path) if excluded_path.is_file() else []
    mitigate = sum(1 for row in scenarios if row.get("treatment") == "mitigate")
    accept = sum(1 for row in scenarios if row.get("treatment") == "accept")
    merged = sum(1 for row in excluded if is_merged_into_reason(str(row.get("excluded_reason") or "")))
    return {
        "mitigate": mitigate,
        "accept": accept,
        "controls": len(controls),
        "excluded": len(excluded),
        "merged_aliases": merged,
        "non_merged_excluded": len(excluded) - merged,
    }


def title_host_key(name: str, assets: str) -> tuple[str, str]:
    return ((name or "").strip().lower(), (assets or "").strip().lower())


def assert_register_no_double_treatment(ciso_or_out: Path) -> dict[str, Any]:
    """No EGP or title+host appears as both mitigate and accept."""
    from shared.control_map import iter_poam_decisions, risk_register_treatment
    from shared.io_util import read_jsonl
    from shared.port_fold import egp_id_for

    out = resolve_out_dir(ciso_or_out)
    ciso = ciso_dir_of(out)
    scenarios = csv_rows(ciso / "risk_scenarios.csv", delimiter=";")
    by_title: dict[tuple[str, str], set[str]] = {}
    for row in scenarios:
        treat = str(row.get("treatment") or "")
        if treat not in {"mitigate", "accept"}:
            raise RegisterShapeError(f"REGISTER_TREATMENT_FAIL unknown treatment: {row}")
        if (row.get("existing_controls") or "") != "":
            raise RegisterShapeError(
                f"REGISTER_TREATMENT_FAIL existing_controls must stay empty: {row}"
            )
        key = title_host_key(row.get("name") or "", row.get("assets") or "")
        by_title.setdefault(key, set()).add(treat)
    overlap_title = sorted(key for key, treats in by_title.items() if treats == {"mitigate", "accept"})
    if overlap_title:
        raise RegisterShapeError(
            f"REGISTER_TREATMENT_FAIL title-host in mitigate and accept: {overlap_title[:8]}"
        )

    overlap_egp: list[str] = []
    canon = out / "canonical"
    if canon.is_dir():
        from collectors.grc_loader import _dedupe
        from shared.finding_types import dedupe_weaknesses
        from shared.hardening_dedup import dedupe_hardening

        parsed: list[dict[str, Any]] = []
        for path in sorted(canon.glob("*.jsonl")):
            parsed.extend(row for row in read_jsonl(path) if isinstance(row, dict))
        findings = [
            rec
            for rec in dedupe_hardening(dedupe_weaknesses(_dedupe(parsed)))
            if rec.get("kind") in {"finding", "excluded"}
        ]
        mitigate_egp: set[str] = set()
        accept_egp: set[str] = set()
        for rec, decision in iter_poam_decisions(findings):
            stamp = risk_register_treatment(decision)
            if not stamp.get("on_register", True):
                continue
            egp = egp_id_for(rec)
            if stamp.get("treatment") == "mitigate":
                mitigate_egp.add(egp)
            elif stamp.get("treatment") == "accept":
                accept_egp.add(egp)
        overlap_egp = sorted(mitigate_egp & accept_egp)
        if overlap_egp:
            raise RegisterShapeError(
                f"REGISTER_TREATMENT_FAIL EGP in mitigate and accept: {overlap_egp[:8]}"
            )
    return {
        "ok": True,
        "title_host_overlap": overlap_title,
        "egp_overlap": overlap_egp,
        **register_treatment_counts(out),
    }


def assert_count_consistency(ciso_or_out: Path, summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """Risk register, POA&M, and summary must derive from the same deduped set."""
    out = resolve_out_dir(ciso_or_out)
    register = assert_ciso_register(ciso_dir_of(out))
    poam = assert_poam_for_findings(out, findings_count=int(register.get("findings") or 0))
    findings_n = int(register.get("findings") or 0)
    vulns_n = int(register.get("vulnerabilities") or 0)
    scenarios_n = int(register.get("risk_scenarios") or 0)
    poam_n = int(poam.get("poam_rows") or 0)
    if summary is None:
        summary_path = out / "summary.json"
        if summary_path.is_file():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                summary = None
    kind_excluded = int((summary or {}).get("kind_excluded") or 0)
    finding_class = findings_n + vulns_n
    merged_n = count_merged_aliases(out, summary)
    weaknesses = finding_class + kind_excluded
    expected_scenarios = weaknesses - merged_n
    if scenarios_n != expected_scenarios:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL risk_scenarios={scenarios_n} != "
            f"findings+vulnerabilities+kind_excluded-merged={expected_scenarios} "
            f"(findings={findings_n} vulns={vulns_n} kind_excluded={kind_excluded} "
            f"merged={merged_n})"
        )
    treatments = register_treatment_counts(out)
    pending = int((summary or {}).get("pending_carried") or 0)
    if treatments["mitigate"] != poam_n - pending:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL mitigate={treatments['mitigate']} != "
            f"poam-pending={poam_n - pending} (poam={poam_n} pending={pending})"
        )
    if treatments["accept"] != treatments["non_merged_excluded"]:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL accept={treatments['accept']} != "
            f"non_merged_excluded={treatments['non_merged_excluded']}"
        )
    if treatments["controls"] != treatments["mitigate"]:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL controls={treatments['controls']} != "
            f"mitigate={treatments['mitigate']}"
        )
    if summary:
        if int(summary.get("risk_scenarios") or 0) != scenarios_n:
            raise RegisterShapeError(
                f"COUNT_CONSISTENCY_FAIL summary.risk_scenarios={summary.get('risk_scenarios')} "
                f"!= risk_scenarios.csv={scenarios_n}"
            )
        if int(summary.get("poam") or 0) != poam_n:
            raise RegisterShapeError(
                f"COUNT_CONSISTENCY_FAIL summary.poam={summary.get('poam')} != poam.csv={poam_n}"
            )
        if int(summary.get("findings") or 0) != findings_n:
            raise RegisterShapeError(
                f"COUNT_CONSISTENCY_FAIL summary.findings={summary.get('findings')} "
                f"!= findings.csv={findings_n}"
            )
        if "open_risks" in summary and int(summary.get("open_risks") or 0) != poam_n:
            raise RegisterShapeError(
                f"COUNT_CONSISTENCY_FAIL summary.open_risks={summary.get('open_risks')} "
                f"!= poam={poam_n} (POA&M is 1:1 with open risks)"
            )
        if "weaknesses" in summary and int(summary.get("weaknesses") or 0) != finding_class:
            raise RegisterShapeError(
                f"COUNT_CONSISTENCY_FAIL summary.weaknesses={summary.get('weaknesses')} "
                f"!= findings+vulns={finding_class}"
            )
        if "weaknesses_total" in summary:
            assert_poam_breakdown(summary)
    overlap = assert_register_no_double_treatment(out)
    return {
        "ok": True,
        "findings": findings_n,
        "vulnerabilities": vulns_n,
        "weaknesses": finding_class,
        "kind_excluded": kind_excluded,
        "risk_scenarios": scenarios_n,
        "poam": poam_n,
        "open_risks": poam_n,
        "merged_aliases": merged_n,
        "mitigate": treatments["mitigate"],
        "accept": treatments["accept"],
        "title_host_overlap": overlap.get("title_host_overlap") or [],
        "egp_overlap": overlap.get("egp_overlap") or [],
        "relationship": (
            "POA&M is 1:1 with open risks (include_poam); "
            "mitigate == POA&M == CTL; accept == non-merged excluded; "
            "merged_into aliases stay off the register"
        ),
    }


def assert_poam_breakdown(summary: dict[str, Any]) -> dict[str, Any]:
    """weaknesses_total == poam_included + sum(excluded_by_reason). No silent drops."""
    total = int(summary.get("weaknesses_total") or 0)
    included = int(summary.get("poam_included") or 0)
    excluded = summary.get("excluded_by_reason") or {}
    if not isinstance(excluded, dict):
        raise RegisterShapeError("COUNT_CONSISTENCY_FAIL excluded_by_reason must be a dict")
    if any(not str(reason or "").strip() for reason in excluded):
        raise RegisterShapeError("COUNT_CONSISTENCY_FAIL excluded item missing named reason")
    unknown = sorted(str(reason) for reason in excluded if not is_poam_exclude_reason(str(reason)))
    if unknown:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL silent POA&M drop: unknown reasons {unknown}"
        )
    excluded_n = sum(int(count) for count in excluded.values())
    if "excluded" in summary and int(summary.get("excluded") or 0) != excluded_n:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL excluded={summary.get('excluded')} != "
            f"sum(excluded_by_reason)={excluded_n}"
        )
    if total != included + excluded_n:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL weaknesses_total={total} != "
            f"poam_included={included} + sum(excluded_by_reason)={excluded_n}"
        )
    if included != int(summary.get("poam") or 0):
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL poam_included={included} != poam={summary.get('poam')}"
        )
    pending_carried = int(summary.get("pending_carried") or 0)
    kind_excluded = int(summary.get("kind_excluded") or 0)
    if "weaknesses" in summary:
        expected = int(summary.get("weaknesses") or 0) + pending_carried + kind_excluded
        if total != expected:
            raise RegisterShapeError(
                f"COUNT_CONSISTENCY_FAIL weaknesses_total={total} != "
                f"weaknesses={summary.get('weaknesses')}"
                + (f" + kind_excluded={kind_excluded}" if kind_excluded else "")
                + (f" + pending_carried={pending_carried}" if pending_carried else "")
            )
    return {
        "ok": True,
        "weaknesses_total": total,
        "poam_included": included,
        "excluded_by_reason": {str(k): int(v) for k, v in excluded.items()},
    }


class RegisterShapeError(ValueError):
    """CISO risk register or POA&M is missing, header-wrong, or empty when findings exist."""


def assert_input_export_accounting(
    parsed: list[dict[str, Any]],
    poam_rows: list[dict[str, Any]],
    excluded_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Every finding/excluded input record is in exactly one of poam.csv or excluded.csv."""
    keys: list[str] = []
    for rec in parsed:
        if rec.get("kind") not in {"finding", "excluded"}:
            continue
        key = str(rec.get("ref_id") or "").strip()
        if key:
            keys.append(key)
    unique = list(dict.fromkeys(keys))
    poam_ids = {
        str(row.get("finding_ref_id") or row.get("id") or "").strip()
        for row in poam_rows
    }
    poam_ids.discard("")
    ex_ids = {
        str(row.get("finding_ref_id") or row.get("id") or "").strip()
        for row in excluded_rows
    }
    ex_ids.discard("")
    both = sorted(poam_ids & ex_ids)
    if both:
        raise RegisterShapeError(
            f"ACCOUNTING_FAIL in both poam.csv and excluded.csv: {both}"
        )
    exported = poam_ids | ex_ids
    missing = [key for key in unique if key not in exported]
    if missing:
        raise RegisterShapeError(
            f"ACCOUNTING_FAIL missing record keys: {missing}"
        )
    return {
        "ok": True,
        "parsed": len(unique),
        "poam": len(poam_ids),
        "excluded": len(ex_ids),
    }


def first_nonempty_line(path: Path) -> str:
    """First non-empty line. Import CSVs must start with the exact header."""
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            return line.strip()
    return ""


def csv_rows(path: Path, *, delimiter: str = ",") -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh, delimiter=delimiter))


def resolve_out_dir(ciso_or_out: Path) -> Path:
    """Accept work/out, work/out/ciso-assistant, or prove/work (has out/)."""
    folder = Path(ciso_or_out)
    if folder.name == "ciso-assistant":
        return folder.parent
    if (folder / "ciso-assistant").is_dir():
        return folder
    nested = folder / "out"
    if (nested / "ciso-assistant").is_dir() or (nested / "ciso-assistant").is_file():
        return nested
    return folder


def ciso_dir_of(ciso_or_out: Path) -> Path:
    out = resolve_out_dir(ciso_or_out)
    return out / "ciso-assistant"


def poam_path_of(ciso_or_out: Path) -> Path:
    return resolve_out_dir(ciso_or_out) / POAM_REL


def poam_md_path_of(ciso_or_out: Path) -> Path:
    return resolve_out_dir(ciso_or_out) / POAM_MD_REL


def _delimiter_for(name: str) -> str:
    return ";" if name == "risk_scenarios.csv" else ","


def assert_ciso_register(ciso: Path) -> dict[str, Any]:
    """Risk register = findings + risk_scenarios. Vulns may be header-only (CVE-class)."""
    folder = Path(ciso)
    if folder.name != "ciso-assistant" and (folder / "ciso-assistant").is_dir():
        folder = folder / "ciso-assistant"
    missing = [name for name in MUST_EXIST_CSVS if not (folder / name).is_file()]
    if missing:
        raise RegisterShapeError(f"REGISTER_SHAPE_FAIL missing CISO CSVs: {missing}")
    empty: list[str] = []
    bad_headers: dict[str, str] = {}
    counts: dict[str, int] = {}
    check_names = [name for name in list(MUST_EXIST_CSVS) + list(OPTIONAL_CSVS) if (folder / name).is_file()]
    for name in check_names:
        path = folder / name
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            empty.append(name)
            continue
        expected = CISO_HEADERS[name]
        first = first_nonempty_line(path)
        if first != expected:
            bad_headers[name] = first
            continue
        rows = csv_rows(path, delimiter=_delimiter_for(name))
        counts[name] = len(rows)
    if empty:
        raise RegisterShapeError(f"REGISTER_SHAPE_FAIL empty CISO CSVs: {empty}")
    if bad_headers:
        raise RegisterShapeError(f"REGISTER_SHAPE_FAIL header mismatch: {bad_headers}")
    findings_n = int(counts.get("findings.csv") or 0)
    scenarios_n = int(counts.get("risk_scenarios.csv") or 0)
    if findings_n > 0 and scenarios_n <= 0:
        raise RegisterShapeError(
            f"REGISTER_SHAPE_FAIL findings={findings_n} but risk_scenarios has 0 rows "
            "(risk register is findings.csv + risk_scenarios.csv, not vulnerabilities.csv)"
        )
    hollow = [
        name
        for name in ROW_REQUIRED_WHEN_FINDINGS
        if findings_n > 0 and int(counts.get(name) or 0) <= 0
    ]
    if hollow:
        raise RegisterShapeError(
            f"REGISTER_SHAPE_FAIL findings={findings_n} but hollow register files: {hollow}"
        )
    return {
        "ok": True,
        "counts": counts,
        "ciso": str(folder),
        "findings": findings_n,
        "risk_scenarios": scenarios_n,
        "vulnerabilities": int(counts.get(CVE_CLASS_CSV) or 0),
        "vulns_cve_class_only": True,
    }


def assert_poam_for_findings(
    ciso_or_out: Path,
    *,
    findings_count: int | None = None,
) -> dict[str, Any]:
    """POA&M must exist with schema columns; findings>0 and zero POA&M rows is fail-closed."""
    out = resolve_out_dir(ciso_or_out)
    ciso = ciso_dir_of(out)
    findings_path = ciso / "findings.csv"
    if findings_count is None:
        if findings_path.is_file() and first_nonempty_line(findings_path) == CISO_HEADERS["findings.csv"]:
            findings_count = len(csv_rows(findings_path))
        else:
            findings_count = 0
    poam = poam_path_of(out)
    if not poam.is_file():
        if findings_count > 0:
            raise RegisterShapeError(
                f"REGISTER_SHAPE_FAIL findings={findings_count} but POA&M missing ({poam})"
            )
        return {"ok": True, "poam_rows": 0, "findings": findings_count, "poam": str(poam)}
    if not poam.read_text(encoding="utf-8").strip():
        if findings_count > 0:
            raise RegisterShapeError(
                f"REGISTER_SHAPE_FAIL findings={findings_count} but POA&M empty"
            )
        return {"ok": True, "poam_rows": 0, "findings": findings_count, "poam": str(poam)}
    first = first_nonempty_line(poam)
    if first != POAM_HEADER:
        raise RegisterShapeError(f"REGISTER_SHAPE_FAIL POA&M header mismatch: {first!r}")
    rows = csv_rows(poam)
    if findings_count > 0 and not rows:
        raise RegisterShapeError(
            f"REGISTER_SHAPE_FAIL findings={findings_count} but POA&M has 0 rows"
        )
    md = poam_md_path_of(out)
    if rows and (not md.is_file() or not md.read_text(encoding="utf-8").strip()):
        raise RegisterShapeError(f"REGISTER_SHAPE_FAIL POA&M md missing ({md})")
    return {
        "ok": True,
        "poam_rows": len(rows),
        "findings": findings_count,
        "poam": str(poam),
        "poam_md": str(md) if md.is_file() else "",
        "rows": rows,
    }


def assert_risk_register_and_poam(ciso_or_out: Path) -> dict[str, Any]:
    """Usable risk register + POA&M, not merely N CSV files exist."""
    register = assert_ciso_register(ciso_dir_of(ciso_or_out))
    poam = assert_poam_for_findings(
        ciso_or_out,
        findings_count=int(register["counts"].get("findings.csv") or 0),
    )
    return {
        "ok": True,
        "ciso": register["ciso"],
        "counts": register["counts"],
        "poam_rows": poam["poam_rows"],
        "findings": poam["findings"],
        "risk_scenarios": register.get("risk_scenarios"),
        "vulnerabilities": register.get("vulnerabilities"),
        "vulns_cve_class_only": True,
        "poam": poam["poam"],
        "poam_md": poam.get("poam_md"),
    }


def write_minimal_register(ciso: Path, *, with_poam: bool = True) -> None:
    """Schema-shaped SAMPLE stub (honesty tests). Not a client estate."""
    folder = Path(ciso)
    folder.mkdir(parents=True, exist_ok=True)
    payloads = {
        "assets.csv": (
            CISO_HEADERS["assets.csv"]
            + "\nDEMO-A,sample-asset,SAMPLE stub,Global,PR,,,demo,\n"
        ),
        "findings.csv": (
            CISO_HEADERS["findings.csv"]
            + "\nDEMO-F,sample-finding,SAMPLE stub,high,identified,demo\n"
        ),
        "vulnerabilities.csv": (
            CISO_HEADERS["vulnerabilities.csv"]
            + "\nDEMO-V,sample-vuln,SAMPLE stub,Exploitable,High,sample-asset,\n"
        ),
        "applied_controls.csv": (
            CISO_HEADERS["applied_controls.csv"]
            + "\nDEMO-C,sample-control,SAMPLE stub,Global,to_do,technical,1,protect\n"
        ),
        "evidences.csv": CISO_HEADERS["evidences.csv"] + "\nSAMPLE evidence,not a client\n",
        "risk_scenarios.csv": (
            CISO_HEADERS["risk_scenarios.csv"]
            + "\nDEMO-S;sample-asset;;sample-scenario;SAMPLE stub;;High;High;High;;Moderate;Moderate;Low;mitigate\n"
        ),
    }
    for name, text in payloads.items():
        (folder / name).write_text(text, encoding="utf-8")
    if with_poam:
        poam = folder.parent / "poam" / "poam.csv"
        poam.parent.mkdir(parents=True, exist_ok=True)
        poam.write_text(
            POAM_HEADER
            + "\nsample-finding,sample-asset,high,cpg_2_W csf_PR,restrict exposure,,,open,SAMPLE,"
            + "POAM-DEMO-F,DEMO-F,SC-7,SAMPLE stub,sample,,2026-01-01,2026-01-31,2026-01-01,"
            + "M1 2026-01-08 Validate; M2 2026-01-24 Apply fix; M3 2026-01-31 Rescan,High,,\n",
            encoding="utf-8",
        )
        (folder.parent / "poam" / "poam.md").write_text(
            "# POA&M (operator draft)\nSAMPLE stub. Not a client.\n",
            encoding="utf-8",
        )
        (folder.parent / "poam" / "excluded.csv").write_text(
            EXCLUDED_HEADER + "\n"
            "DEMO-I,DEMO-I,sample-info,sample-asset,info,severity_info,\n"
            "DEMO-H,DEMO-H,sample-honeypot,sample-asset,high,honeypot,\n",
            encoding="utf-8",
        )
