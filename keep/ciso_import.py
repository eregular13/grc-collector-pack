"""CISO Assistant import bundle next to keep-lab CSVs. File-drop only. No HTTP."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.ciso_shape import (
    CISO_HEADERS,
    REGISTER_CSVS,
    RegisterShapeError,
    assert_risk_register_and_poam,
)
from shared.io_util import write_json

CISO_REQUIRED = REGISTER_CSVS
CISO_OPTIONAL = (
    "evidences.csv",
    "risk_scenarios.csv",
)


def read_paying_day(root: Path) -> str:
    paying = "FAIL"
    status = Path(root) / "STATUS.md"
    if not status.is_file():
        return paying
    for line in status.read_text(encoding="utf-8").splitlines():
        if line.startswith("paying_day:"):
            return line.split(":", 1)[1].strip() or paying
    return paying


def honest_paying_day(paying_day: str | None = None, *, sample: bool = True) -> str:
    """SAMPLE/DEMO cannot emit paying_day PASS. This pack never invents PASS."""
    raw = str(paying_day or "FAIL").strip() or "FAIL"
    if sample or raw.upper() == "PASS":
        return "FAIL"
    return raw


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
    paying = honest_paying_day(paying_day, sample=honest_sample)
    return {
        "shape": "ciso-assistant",
        "consumer": "ciso-assistant",
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "demo": True if honest_sample else False,
        "sample": honest_sample,
        "client_keep": bool(client_keep) and not honest_sample,
        "paying_day": paying,
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


class SampleHonestyError(ValueError):
    """SAMPLE SoR bundle is missing files or honesty stamps."""


def verify_sample_sor(ciso: Path) -> dict[str, Any]:
    """Fail-closed SAMPLE honesty for the operator entrypoint.

    Requires demo/sample true, paying_day FAIL, client_keep false,
    posted/http false, required CISO CSVs with schema columns, and
    POA&M rows when findings exist. SAMPLE != client KEEP.
    This pack never invents paying_day PASS.
    """
    folder = Path(ciso)
    errors: list[str] = []
    import_path = folder / "IMPORT.json"
    if not import_path.is_file():
        raise SampleHonestyError(f"missing {import_path}")
    try:
        doc = json.loads(import_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SampleHonestyError(f"IMPORT.json is not JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise SampleHonestyError("IMPORT.json must be an object")

    if doc.get("demo") is not True:
        errors.append("demo must be true")
    if doc.get("sample") is not True:
        errors.append("sample must be true")
    if doc.get("client_keep") is not False:
        errors.append("client_keep must be false")
    paying = str(doc.get("paying_day") or "").strip()
    if paying != "FAIL":
        errors.append("paying_day must be FAIL (SAMPLE cannot PASS)")
    if doc.get("posted") is not False:
        errors.append("posted must be false")
    if "http" in doc and doc.get("http") is not False:
        errors.append("http must be false")
    wrap = str(doc.get("wrap") or "")
    if wrap and wrap != "review-only":
        errors.append("wrap must stay review-only")

    shape: dict[str, Any] = {}
    try:
        shape = assert_risk_register_and_poam(folder)
    except RegisterShapeError as exc:
        errors.append(str(exc))

    if errors:
        raise SampleHonestyError("; ".join(errors))
    return {
        "ok": True,
        "ciso": str(folder),
        "import": str(import_path),
        "demo": True,
        "sample": True,
        "client_keep": False,
        "paying_day": "FAIL",
        "posted": False,
        "files": [name for name in list(CISO_REQUIRED) + list(CISO_OPTIONAL) if (folder / name).is_file()],
        "findings": shape.get("findings"),
        "poam_rows": shape.get("poam_rows"),
    }


def verify_main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="keep verify",
        description="Fail-closed SAMPLE honesty on keep/work/out/ciso-assistant/IMPORT.json",
    )
    parser.add_argument(
        "--ciso",
        required=True,
        help="ciso-assistant directory with IMPORT.json + CSVs",
    )
    args = parser.parse_args(argv)
    try:
        result = verify_sample_sor(Path(args.ciso))
    except SampleHonestyError as exc:
        print(f"SAMPLE_HONESTY_FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0
