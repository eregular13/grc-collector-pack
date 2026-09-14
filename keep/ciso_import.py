"""CISO Assistant import bundle next to keep-lab CSVs. File-drop only. No HTTP."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import write_json

CISO_REQUIRED = (
    "assets.csv",
    "findings.csv",
    "vulnerabilities.csv",
    "applied_controls.csv",
)
CISO_OPTIONAL = (
    "evidences.csv",
    "risk_scenarios.csv",
)
CISO_HEADERS = {
    "assets.csv": "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets",
    "applied_controls.csv": "ref_id,name,description,domain,status,category,priority,csf_function",
    "evidences.csv": "name,description",
    "findings.csv": "ref_id,name,description,severity,status,filtering_labels",
    "vulnerabilities.csv": "ref_id,name,description,status,severity,assets,applied_controls",
    "risk_scenarios.csv": "ref_id;assets;threats;name;description;existing_controls;current_impact;current_proba;current_risk;additional_controls;residual_impact;residual_proba;residual_risk;treatment",
}


def read_paying_day(root: Path) -> str:
    paying = "FAIL"
    status = Path(root) / "STATUS.md"
    if not status.is_file():
        return paying
    for line in status.read_text(encoding="utf-8").splitlines():
        if line.startswith("paying_day:"):
            return line.split(":", 1)[1].strip() or paying
    return paying


def ciso_dir(out: Path) -> Path:
    return Path(out) / "ciso-assistant"


def listed_ciso_files(out: Path) -> list[str]:
    folder = ciso_dir(out)
    names = list(CISO_REQUIRED) + list(CISO_OPTIONAL)
    return [name for name in names if (folder / name).is_file()]


def missing_required_ciso(out: Path) -> list[str]:
    folder = ciso_dir(out)
    return [name for name in CISO_REQUIRED if not (folder / name).is_file()]


def header_mismatch(out: Path) -> dict[str, str]:
    folder = ciso_dir(out)
    bad: dict[str, str] = {}
    for name, expected in CISO_HEADERS.items():
        path = folder / name
        if not path.is_file():
            continue
        first = ""
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                first = line.strip()
                break
        if first != expected:
            bad[name] = first
    return bad


def build_ciso_import_manifest(
    out: Path,
    *,
    sample: bool,
    client_keep: bool,
    paying_day: str,
    origin: str,
) -> dict[str, Any]:
    folder = ciso_dir(out)
    files = listed_ciso_files(out)
    honest_sample = bool(sample or not client_keep)
    return {
        "shape": "ciso-assistant",
        "consumer": "ciso-assistant",
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "demo": True if honest_sample else False,
        "sample": honest_sample,
        "client_keep": bool(client_keep) and not honest_sample,
        "paying_day": paying_day,
        "estate": (
            "SAMPLE — redacted KEEP-chain fixtures. Not a client KEEP drop."
            if honest_sample
            else "Client KEEP file-drop. Human reviews before CISO import."
        ),
        "origin": origin,
        "dir": str(folder),
        "files": files,
        "required": list(CISO_REQUIRED),
        "import": (
            "clica or CISO Assistant UI CSV import of keep/work/out/ciso-assistant/*.csv. "
            "Do not invent FindingsAssessment UUIDs."
        ),
        "note": (
            "SAMPLE ≠ client KEEP. keep-lab never writes pack in/. "
            "posted stays false unless CISO_PUSH=1 and DRY_RUN!=1. "
            "This pack does not POST /api/risks."
        ),
    }


def write_ciso_import_manifest(
    out: Path,
    *,
    sample: bool,
    client_keep: bool,
    paying_day: str,
    origin: str,
) -> Path:
    folder = ciso_dir(out)
    folder.mkdir(parents=True, exist_ok=True)
    payload = build_ciso_import_manifest(
        out,
        sample=sample,
        client_keep=client_keep,
        paying_day=paying_day,
        origin=origin,
    )
    dest = folder / "IMPORT.json"
    write_json(dest, payload)
    guide = folder / "IMPORT.md"
    lines = [
        "# CISO Assistant import",
        "",
        payload["estate"],
        "",
        f"- demo: `{str(payload['demo']).lower()}`",
        f"- sample: `{str(payload['sample']).lower()}`",
        f"- client_keep: `{str(payload['client_keep']).lower()}`",
        f"- paying_day: `{payload['paying_day']}`",
        f"- posted / http: `false`",
        "",
        "Import these CSVs with **clica** or the CISO Assistant UI:",
        "",
    ]
    for name in payload["files"]:
        lines.append(f"- `{name}`")
    lines.extend(
        [
            "",
            "Do not invent FindingsAssessment UUIDs. RiskReady wrap stays review-only.",
            "This pack does not POST `/api/risks`.",
            "",
        ]
    )
    guide.write_text("\n".join(lines), encoding="utf-8")
    return dest
