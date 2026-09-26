"""Risk-register + POA&M shape for SAMPLE, farm_drop, and lab prove SoR outputs.

Column contract matches schemas/ciso-assistant.md and collectors/grc_loader.py.
Lab prove (`--use-existing-in`) also calls assert_risk_register_and_poam on out/.
Dest_in LAB.txt / DEMO-adapter fail-closed lives in scripts/prove_ciso.py
(LAB_SHAPE_FAIL). Not an operator entrypoint. SAMPLE/DEMO/LAB labels stay honest.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

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
POAM_REL = Path("poam") / "poam.csv"
POAM_MD_REL = Path("poam") / "poam.md"
FINDING_SEV = frozenset({"low", "medium", "high", "critical"})
VULN_SEV = frozenset({"Information", "Low", "Medium", "High", "Critical"})
SCENARIO_LEVELS = frozenset({"Low", "Moderate", "High", "Very High"})

# ASCII-only: Windows cp1252 consoles cannot print U+2260 / U+2192.
REGISTER_OK_LINE = "REGISTER_SHAPE=ok findings_to_poam != empty paying_day=FAIL"

# Documented count relationship after weakness dedupe:
#   weaknesses == risk_scenarios == findings.csv + vulnerabilities.csv
#   POA&M == open_risks (include_poam). findings.csv is non-CVE; vulns are CVE-class.


def assert_count_consistency(ciso_or_out: Path, summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """Risk register, POA&M, and summary must derive from the same deduped set."""
    out = resolve_out_dir(ciso_or_out)
    register = assert_ciso_register(ciso_dir_of(out))
    poam = assert_poam_for_findings(out, findings_count=int(register.get("findings") or 0))
    findings_n = int(register.get("findings") or 0)
    vulns_n = int(register.get("vulnerabilities") or 0)
    scenarios_n = int(register.get("risk_scenarios") or 0)
    poam_n = int(poam.get("poam_rows") or 0)
    weaknesses = findings_n + vulns_n
    if scenarios_n != weaknesses:
        raise RegisterShapeError(
            f"COUNT_CONSISTENCY_FAIL risk_scenarios={scenarios_n} != "
            f"findings+vulnerabilities={weaknesses} (deduped weaknesses)"
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
        if "weaknesses" in summary and int(summary.get("weaknesses") or 0) != weaknesses:
            raise RegisterShapeError(
                f"COUNT_CONSISTENCY_FAIL summary.weaknesses={summary.get('weaknesses')} "
                f"!= findings+vulns={weaknesses}"
            )
    return {
        "ok": True,
        "findings": findings_n,
        "vulnerabilities": vulns_n,
        "weaknesses": weaknesses,
        "risk_scenarios": scenarios_n,
        "poam": poam_n,
        "open_risks": poam_n,
        "relationship": "POA&M is 1:1 with open risks (include_poam); register is 1:1 with weaknesses",
    }


class RegisterShapeError(ValueError):
    """CISO risk register or POA&M is missing, header-wrong, or empty when findings exist."""


def first_nonempty_line(path: Path) -> str:
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
