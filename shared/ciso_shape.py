"""Risk-register + POA&M shape for SAMPLE and farm_drop SoR outputs.

Column contract matches schemas/ciso-assistant.md and collectors/grc_loader.py.
Not an operator entrypoint. SAMPLE/DEMO labels stay honest.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

REGISTER_CSVS = (
    "assets.csv",
    "findings.csv",
    "vulnerabilities.csv",
    "applied_controls.csv",
)
OPTIONAL_CSVS = (
    "evidences.csv",
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
POAM_HEADER = "weakness,asset,severity,framework_refs,recommended_fix,owner,due,status"
POAM_REL = Path("poam") / "poam.csv"
FINDING_SEV = frozenset({"low", "medium", "high", "critical"})
VULN_SEV = frozenset({"Information", "Low", "Medium", "High", "Critical"})

# ASCII-only: Windows cp1252 consoles cannot print U+2260 / U+2192.
REGISTER_OK_LINE = "REGISTER_SHAPE=ok findings_to_poam != empty paying_day=FAIL"


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


def _delimiter_for(name: str) -> str:
    return ";" if name == "risk_scenarios.csv" else ","


def assert_ciso_register(ciso: Path) -> dict[str, Any]:
    """Required risk-register CSVs exist, are non-empty, and match schema headers."""
    folder = Path(ciso)
    if folder.name != "ciso-assistant" and (folder / "ciso-assistant").is_dir():
        folder = folder / "ciso-assistant"
    missing = [name for name in REGISTER_CSVS if not (folder / name).is_file()]
    if missing:
        raise RegisterShapeError(f"REGISTER_SHAPE_FAIL missing CISO CSVs: {missing}")
    empty: list[str] = []
    bad_headers: dict[str, str] = {}
    counts: dict[str, int] = {}
    check_names = [name for name in list(REGISTER_CSVS) + list(OPTIONAL_CSVS) if (folder / name).is_file()]
    for name in check_names:
        path = folder / name
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            if name in REGISTER_CSVS:
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
    return {"ok": True, "counts": counts, "ciso": str(folder)}


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
    return {
        "ok": True,
        "poam_rows": len(rows),
        "findings": findings_count,
        "poam": str(poam),
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
        "poam": poam["poam"],
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
            + "\nsample-finding,sample-asset,high,cpg_2_W csf_PR,restrict exposure,,,open\n",
            encoding="utf-8",
        )
