#!/usr/bin/env python3
"""SAMPLE/DEMO CISO prove: fixture Covey pack_drop + honeypot → out/ciso-assistant.

Uses the existing operator SoR path (`run_ciso_path` / `python3 -m dropbox ciso`).
Not a client estate. Never writes pack in/. Never POSTs. Paying-day stays FAIL.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.ciso_shape import RegisterShapeError, assert_risk_register_and_poam

SCOPE = ROOT / "dropbox" / "SCOPE.yaml"
CISO_CSVS = (
    "assets.csv",
    "applied_controls.csv",
    "evidences.csv",
    "findings.csv",
    "vulnerabilities.csv",
    "risk_scenarios.csv",
)
# Shared all-16 pack_drop inventory. Fixtures, seed_prove_in, and honesty
# tests must stay 1:1 with this set — no missing adapter, no 17th.
E2E_PROVEN_PACK_DROP_ADAPTERS = (
    "nmap",
    "rustscan",
    "fping",
    "naabu",
    "nping",
    "httpx",
    "sslscan",
    "tlsx",
    "whatweb",
    "hping3",
    "onesixtyone",
    "nbtscan",
    "braa",
    "ike-scan",
    "svmap",
    "unicornscan",
)
E2E_PROVEN_PACK_DROP_NAMED = " + ".join(E2E_PROVEN_PACK_DROP_ADAPTERS)
SAMPLE_BANNER = (
    "SAMPLE/DEMO — not a client estate.\n"
    f"Fixture Covey pack_drop ({E2E_PROVEN_PACK_DROP_NAMED}) + honeypot file_drop. Not a client export.\n"
    "Not a paying-day stamp. RiskReady wrap stays review-only.\n"
)
# Lab/live dest_in is operator-populated. Not SAMPLE fixture reseed. Not a client.
LAB_BANNER = (
    "LAB/DEMO -- not a client estate.\n"
    "Operator-populated dest_in (no fixture reseed). Not SAMPLE fixtures. Not a client export.\n"
    "Not a paying-day stamp. RiskReady wrap stays review-only.\n"
)
SKIP_EXISTING_IN_NAMES = frozenset(
    {".gitkeep", ".DS_Store", "SAMPLE.txt", "LAB.txt", "README.md", "MANIFEST"}
)

ENV_KEYS = (
    "IN_DIR",
    "OUT_DIR",
    "DRY_RUN",
    "GRC_LIVE_SCAN",
    "CISO_PUSH",
    "RISKREADY_PUSH",
    "DROPBOX_LIVE",
    "DROPBOX_DEMO",
    "PYTHONPATH",
    "GRC_ESTATE_LABEL",
)

PAYING_PASS_RE = re.compile(r"paying[_ ]day[\"'\s:=]+pass", re.IGNORECASE)


class FarmDropHonestyError(RuntimeError):
    """prove JSON / CISO outputs claimed a client estate or paying_day PASS."""


class ExistingInError(RuntimeError):
    """--use-existing-in requires dest_in already populated; will not reseed."""


class LabShapeError(RuntimeError):
    """LAB dest_in mixed with DEMO seed adapters or seeded=true (silent reseed)."""


# ASCII-only: Windows cp1252 consoles cannot print U+2260.
HONESTY_OK_LINE = "FARM_DROP_HONESTY=ok SAMPLE/DEMO != client paying_day=FAIL"
LAB_HONESTY_OK_LINE = "LAB_DROP_HONESTY=ok LAB/DEMO != client SAMPLE != LAB paying_day=FAIL"
LAB_SHAPE_FAIL = "LAB_SHAPE_FAIL"
# Operator nmap leaf is dest_in/nmap/pack_drop/. Sibling dirs under that leaf
# (rustscan, httpx, ...) are fixture-seed trees, not compose-lab dest_in.
LAB_OPERATOR_NMAP_LEAF = "nmap"
LAB_ALLOWED_PACK_DROP_DIRS = frozenset({"evidence"})


def _copy_tree(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        target = dest / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def pack_drop_seed_dest(dest_in: Path, name: str) -> Path:
    """nmap lands at dest_in/nmap/pack_drop/; siblings nest under that dir."""
    nmap_drop = Path(dest_in) / "nmap" / "pack_drop"
    return nmap_drop if name == "nmap" else nmap_drop / name


def dest_in_is_populated(dest_in: Path) -> bool:
    """True when dest_in already holds sensor/pack_drop files (not banners)."""
    dest_in = Path(dest_in)
    if not dest_in.is_dir():
        return False
    for path in dest_in.rglob("*"):
        if path.is_file() and path.name not in SKIP_EXISTING_IN_NAMES:
            return True
    return False


def require_existing_in(dest_in: Path) -> Path:
    """Fail closed unless dest_in is already populated. Never rmtree/reseed."""
    dest_in = Path(dest_in)
    if dest_in_is_populated(dest_in):
        return dest_in
    raise ExistingInError(
        "EXISTING_IN_FAIL dest_in is empty or missing; "
        "--use-existing-in / --no-seed will not seed fixtures/pack_drop. "
        f"Populate {dest_in} first (LAB compose pack_drop or operator copy)."
    )


def dest_in_has_lab_stamp(dest_in: Path) -> bool:
    """True when dest_in carries LAB.txt or nmap pack_drop meta lab:true."""
    dest_in = Path(dest_in)
    if not dest_in.is_dir():
        return False
    if (dest_in / "LAB.txt").is_file():
        return True
    for path in dest_in.rglob("LAB.txt"):
        if path.is_file():
            return True
    meta = dest_in / "nmap" / "pack_drop" / "meta.json"
    if not meta.is_file():
        return False
    try:
        data = json.loads(meta.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return isinstance(data, dict) and data.get("lab") is True


def unexpected_demo_adapter_trees(dest_in: Path) -> list[str]:
    """DEMO/SAMPLE fixture trees that mean a silent reseed on a LAB dest_in.

    Operator lab dest_in is LAB.txt + nmap/pack_drop leaf. Honeypot and
    fixtures/pack_drop siblings (rustscan, httpx, ...) are SAMPLE seed.
    """
    dest_in = Path(dest_in)
    unexpected: list[str] = []
    honeypot = dest_in / "honeypot"
    if honeypot.is_dir():
        unexpected.append("honeypot")
    nmap_drop = dest_in / "nmap" / "pack_drop"
    if nmap_drop.is_dir():
        for child in sorted(nmap_drop.iterdir()):
            if not child.is_dir():
                continue
            if child.name in LAB_ALLOWED_PACK_DROP_DIRS:
                continue
            sibling = f"nmap/pack_drop/{child.name}"
            if (child / "meta.json").is_file() or child.name in E2E_PROVEN_PACK_DROP_ADAPTERS:
                unexpected.append(sibling)
    return unexpected


def assert_lab_dest_in_shape(
    dest_in: Path,
    *,
    seeded: bool | None = None,
) -> dict[str, Any]:
    """If LAB.txt / lab stamp is present, refuse seeded=true and DEMO seed trees."""
    dest_in = Path(dest_in)
    if not dest_in_has_lab_stamp(dest_in):
        return {"ok": True, "lab": False, "unexpected": []}
    if seeded is True:
        raise LabShapeError(
            f"{LAB_SHAPE_FAIL} LAB.txt/lab stamp present but seeded=true "
            "(silent fixture reseed). LAB dest_in requires --use-existing-in."
        )
    unexpected = unexpected_demo_adapter_trees(dest_in)
    if unexpected:
        raise LabShapeError(
            f"{LAB_SHAPE_FAIL} unexpected DEMO adapter trees on LAB dest_in: "
            f"{unexpected} (honeypot / fixtures pack_drop siblings beyond "
            "operator nmap leaf). LAB dest_in must not be fixture-reseeded."
        )
    return {
        "ok": True,
        "lab": True,
        "seeded": False,
        "unexpected": [],
        "dest_in": str(dest_in),
    }


def inspect_existing_in(dest_in: Path) -> dict[str, Any]:
    """Describe operator dest_in without copying or wiping it."""
    dest_in = Path(dest_in)
    adapters: dict[str, str] = {}
    nmap_drop = dest_in / "nmap" / "pack_drop"
    if nmap_drop.is_dir():
        adapters[LAB_OPERATOR_NMAP_LEAF] = str(nmap_drop)
        for child in sorted(nmap_drop.iterdir()):
            if child.is_dir() and (child / "meta.json").is_file():
                adapters[child.name] = str(child)
    honeypot = dest_in / "honeypot"
    unexpected = unexpected_demo_adapter_trees(dest_in)
    return {
        "dest_in": str(dest_in),
        "seeded": False,
        "use_existing_in": True,
        "lab": True,
        "lab_stamp": dest_in_has_lab_stamp(dest_in),
        "sample": False,
        "client": False,
        "adapters": adapters,
        "honeypot": str(honeypot) if honeypot.is_dir() else "",
        "unexpected_demo_adapters": unexpected,
        "note": "operator dest_in; no fixture reseed",
    }


def seed_prove_in(dest_in: Path, root: Path | None = None) -> dict[str, Any]:
    """Copy labeled fixtures into dest_in. Never touches pack in/."""
    root = Path(root or ROOT)
    dest_in = Path(dest_in)
    if dest_in.exists():
        shutil.rmtree(dest_in)
    dest_in.mkdir(parents=True)
    adapters: dict[str, str] = {}
    for name in E2E_PROVEN_PACK_DROP_ADAPTERS:
        dest = pack_drop_seed_dest(dest_in, name)
        _copy_tree(root / "fixtures" / "pack_drop" / name, dest)
        (dest / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
        adapters[name] = str(dest)
    honeypot = dest_in / "honeypot"
    beelzebub = dest_in / "honeypot" / "pack_drop"
    _copy_tree(root / "fixtures" / "demo" / "honeypot", honeypot)
    _copy_tree(root / "fixtures" / "demo" / "honeypot_beelzebub", beelzebub)
    (dest_in / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (honeypot / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    (beelzebub / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")
    seeded = {name: adapters[name] for name in E2E_PROVEN_PACK_DROP_ADAPTERS if name != "nmap"}
    return {
        "dest_in": str(dest_in),
        "covey": adapters["nmap"],
        **seeded,
        "honeypot": str(honeypot),
        "beelzebub": str(beelzebub),
        "sample": True,
        "client": False,
        "adapters": adapters,
    }


def verify_farm_drop_sor(dest: Path) -> dict[str, Any]:
    """Fail-closed if prove JSON / CISO outputs claim client estate or paying_day PASS."""
    dest = Path(dest)
    stamp_path = dest / "prove-ciso.json"
    if not stamp_path.is_file():
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL missing prove-ciso.json")
    raw = stamp_path.read_text(encoding="utf-8")
    try:
        stamp = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FarmDropHonestyError(f"FARM_DROP_HONESTY_FAIL prove-ciso.json: {exc}") from exc
    if not isinstance(stamp, dict):
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL prove-ciso.json not an object")

    paying = str(stamp.get("paying_day") or "").strip()
    if paying.upper() == "PASS":
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL paying_day PASS")
    if paying != "FAIL":
        raise FarmDropHonestyError(f"FARM_DROP_HONESTY_FAIL paying_day {paying or 'missing'}")
    if stamp.get("client") is True or stamp.get("client_keep") is True:
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL client estate claim")
    lab = stamp.get("lab") is True or stamp.get("use_existing_in") is True
    dest_in = dest / "in"
    if dest_in_has_lab_stamp(dest_in):
        assert_lab_dest_in_shape(dest_in, seeded=stamp.get("seeded"))
    if lab:
        if stamp.get("lab") is not True:
            raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL lab must be true")
        if stamp.get("seeded") is True:
            raise LabShapeError(
                f"{LAB_SHAPE_FAIL} lab stamp present but seeded=true "
                "(silent fixture reseed)"
            )
    elif stamp.get("sample") is not True:
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL sample must be true")
    if stamp.get("demo") is not True:
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL demo must be true")
    estate = str(stamp.get("estate") or "")
    estate_low = estate.lower()
    if "client" in estate_low and "not a client" not in estate_low:
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL estate claims client")
    if lab:
        if "lab" not in estate_low and "demo" not in estate_low:
            raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL estate missing LAB/DEMO")
        if "sample" in estate_low and "lab" not in estate_low:
            raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL lab estate stamped SAMPLE")
    elif "sample" not in estate_low and "demo" not in estate_low:
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL estate missing SAMPLE/DEMO")
    if stamp.get("posted") is True:
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL posted true")
    if PAYING_PASS_RE.search(raw):
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL prove JSON paying_day PASS")

    ciso = dest / "out" / "ciso-assistant"
    if not ciso.is_dir():
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL missing out/ciso-assistant/")
    try:
        shape = assert_risk_register_and_poam(dest / "out")
    except RegisterShapeError as exc:
        raise FarmDropHonestyError(f"FARM_DROP_HONESTY_FAIL {exc}") from exc
    present = [name for name in CISO_CSVS if (ciso / name).is_file()]
    if not present:
        raise FarmDropHonestyError("FARM_DROP_HONESTY_FAIL missing CISO CSVs")

    for folder in (dest, dest / "out", ciso):
        if not folder.is_dir():
            continue
        for path in folder.iterdir():
            if not path.is_file() or path.suffix.lower() not in {".json", ".csv", ".md", ".txt"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            low = text.lower()
            if PAYING_PASS_RE.search(text):
                raise FarmDropHonestyError(
                    f"FARM_DROP_HONESTY_FAIL {path.name} claims paying_day PASS"
                )
            if "client estate" in low and "not a client" not in low and "sample" not in low:
                raise FarmDropHonestyError(
                    f"FARM_DROP_HONESTY_FAIL {path.name} claims client estate"
                )
    stamp_poam = (stamp.get("counts") or {}).get("poam")
    if stamp_poam is not None and int(stamp_poam) != int(shape.get("poam_rows") or 0):
        raise FarmDropHonestyError(
            f"FARM_DROP_HONESTY_FAIL counts.poam={stamp_poam} != poam_rows={shape.get('poam_rows')}"
        )
    return {
        "ok": True,
        "stamp": stamp,
        "ciso_dir": str(ciso),
        "ciso_files": present,
        "findings": shape.get("findings"),
        "risk_scenarios": shape.get("risk_scenarios"),
        "poam_rows": shape.get("poam_rows"),
        "poam": shape.get("poam"),
        "poam_md": shape.get("poam_md"),
    }


def prove_ciso(
    root: Path | None = None,
    dest: Path | None = None,
    *,
    use_existing_in: bool = False,
) -> dict[str, Any]:
    """Fixture seed (default) or operator dest_in → run_ciso_path → out/ciso-assistant.

    Default reseeds fixtures/pack_drop into dest/in (SAMPLE != client).
    --use-existing-in / --no-seed keeps dest/in as-is (LAB/DEMO != SAMPLE != client).
    """
    from dropbox.orchestrator.ciso_path import run_ciso_path
    from dropbox.orchestrator.estate import fingerprint, pack_in_dir

    root = Path(root or ROOT)
    dest = Path(dest or (root / "prove" / "work"))
    dest_in = dest / "in"
    dest_out = dest / "out"
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    pack = pack_in_dir()
    before = fingerprint(pack)
    try:
        os.environ["DRY_RUN"] = "1"
        os.environ["GRC_LIVE_SCAN"] = "0"
        os.environ["CISO_PUSH"] = "0"
        os.environ["RISKREADY_PUSH"] = "0"
        os.environ["DROPBOX_LIVE"] = "0"
        os.environ["DROPBOX_DEMO"] = "1"
        os.environ.setdefault("PYTHONPATH", str(root))
        # Export watermark (poam estate column + banner). LAB != SAMPLE != client.
        os.environ["GRC_ESTATE_LABEL"] = "LAB" if use_existing_in else "SAMPLE"
        if use_existing_in:
            require_existing_in(dest_in)
            seed = inspect_existing_in(dest_in)
            assert_lab_dest_in_shape(dest_in, seeded=seed.get("seeded"))
        else:
            seed = seed_prove_in(dest_in, root)
            seed = {**seed, "seeded": True, "use_existing_in": False, "lab": False}
            # Default seed wipes dest_in first; LAB.txt gone => no-op.
            # If a lab stamp somehow survived the wipe, refuse seeded=true.
            assert_lab_dest_in_shape(dest_in, seeded=seed.get("seeded"))
        if dest_out.exists():
            shutil.rmtree(dest_out)
        dest_out.mkdir(parents=True)
        result = run_ciso_path(dest_in, dest_out, scope_path=SCOPE, write_pack_in=False)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    after = fingerprint(pack)
    ciso_dir = dest_out / "ciso-assistant"
    ciso_files = [name for name in CISO_CSVS if (ciso_dir / name).is_file()]
    findings_text = ""
    assets_text = ""
    if (ciso_dir / "findings.csv").is_file():
        findings_text = (ciso_dir / "findings.csv").read_text(encoding="utf-8")
    if (ciso_dir / "assets.csv").is_file():
        assets_text = (ciso_dir / "assets.csv").read_text(encoding="utf-8")
    summary: dict[str, Any] = {}
    if (dest_out / "summary.json").is_file():
        summary = json.loads((dest_out / "summary.json").read_text(encoding="utf-8"))
    paying = "FAIL"
    for line in (root / "STATUS.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("paying_day:"):
            paying = line.split(":", 1)[1].strip()
            break
    try:
        register_shape = assert_risk_register_and_poam(dest_out)
        shape_ok = True
    except RegisterShapeError:
        register_shape = {}
        shape_ok = False
    fixture_ok = (
        "filesrv.corp.local" in assets_text
        and "10.9.8.7" in assets_text
        and "10.9.8.20" in assets_text
        and "10.9.8.40" in assets_text
        and "10.9.8.50" in assets_text
        and "10.9.8.60" in assets_text
        and "10.9.8.70" in assets_text
        and "10.9.8.80" in assets_text
        and "10.9.8.81" in assets_text
        and "10.9.8.90" in assets_text
        and "10.9.8.91" in assets_text
        and "10.9.8.10" in assets_text
        and "10.9.8.11" in assets_text
        and "10.9.8.30" in assets_text
        and "10.9.8.31" in assets_text
        and "10.9.8.32" in assets_text
        and "10.9.8.33" in assets_text
        and "10.9.8.34" in assets_text
        and "10.9.8.35" in assets_text
        and "10.9.8.92" in assets_text
        and "10.9.8.93" in assets_text
        and "10.9.8.94" in assets_text
        and "10.9.8.95" in assets_text
        and "10.9.8.96" in assets_text
        and "10.9.8.97" in assets_text
        and "SMB" in findings_text
        and (
            "open_port_observed" in findings_text.lower()
            or "tcp/80" in findings_text.lower()
            or "open tcp/80" in findings_text.lower()
        )
        and "deception-sensor" in findings_text.lower()
        and ("beelzebub" in findings_text.lower() or "beelzebub" in assets_text.lower())
        and result.get("sample") is True
    )
    findings_n = int(register_shape.get("findings") or 0)
    scenarios_n = int(register_shape.get("risk_scenarios") or 0)
    poam_n = int(register_shape.get("poam_rows") or 0)
    lab_ok = findings_n >= 1 and scenarios_n >= 1 and poam_n >= 1
    common_ok = (
        bool(ciso_files)
        and shape_ok
        and result.get("posted") is False
        and result.get("http") is False
        and after == before
        and paying == "FAIL"
        and result.get("client_keep") is False
        and result.get("pack_in_written") is False
    )
    ok = common_ok and (lab_ok if use_existing_in else fixture_ok)
    estate = (
        "LAB/DEMO — not a client estate"
        if use_existing_in
        else "SAMPLE/DEMO — not a client estate"
    )
    stamp = {
        "status": "pass" if ok else "fail",
        "demo": True,
        "sample": False if use_existing_in else True,
        "lab": bool(use_existing_in),
        "seeded": not use_existing_in,
        "use_existing_in": bool(use_existing_in),
        "client": False,
        "client_keep": False,
        "estate": estate,
        "paying_day": paying,
        "posted": result.get("posted"),
        "http": result.get("http"),
        "wrap": "review-only",
        "sor": "ciso-assistant",
        "pack_in_used": False,
        "pack_in_written": after != before,
        "file_drop_read_only": True,
        "live": False,
        "hitl": True,
        "sensors": result.get("sensors"),
        "collectors": result.get("collectors"),
        "ciso_dir": str(ciso_dir),
        "ciso_files": [str(ciso_dir / name) for name in ciso_files],
        "poam": str(dest_out / "poam" / "poam.csv"),
        "poam_md": str(dest_out / "poam" / "poam.md"),
        "counts": {
            **(
                result.get("counts")
                or {
                    "assets": summary.get("assets", 0),
                    "findings": summary.get("findings", 0),
                    "poam": summary.get("poam", register_shape.get("poam_rows", 0)),
                    "demo": summary.get("demo"),
                }
            ),
            "risk_scenarios": register_shape.get("risk_scenarios"),
            "vulnerabilities": register_shape.get("vulnerabilities"),
        },
        "seed": seed,
        "in_dir": str(dest_in),
        "out_dir": str(dest_out),
        "note": (
            (
                "Operator dest_in (no fixture reseed) -> existing collectors -> "
                "grc_loader -> out/ciso-assistant. LAB/DEMO != SAMPLE != client. "
                "This prove is not a paying-day PASS."
            )
            if use_existing_in
            else (
                f"Fixture Covey pack_drop ({E2E_PROVEN_PACK_DROP_NAMED} stdout-class) + honeypot -> "
                "existing collectors -> grc_loader -> out/ciso-assistant. SAMPLE != client. "
                "This prove is not a paying-day PASS."
            )
        ),
    }
    if (ciso_dir / "findings.csv").is_file() or (ciso_dir / "assets.csv").is_file():
        from exporters.model import load_pack_estate
        from exporters.opengrc import write_opengrc
        from exporters.probo import write_probo

        lab_sink = dest_in_has_lab_stamp(dest_in)
        estate = load_pack_estate(dest_out)
        estate.lab = bool(lab_sink)
        estate.sample = False if lab_sink else True
        estate.demo = True
        estate.client = False
        estate.posted = False
        estate.origin = "lab-dest-in" if lab_sink else estate.origin
        opengrc = write_opengrc(dest_out, estate=estate)
        probo = write_probo(dest_out, estate=estate)
        from shared.estate_pages import write_export_manifest

        write_export_manifest(dest_out)
        stamp["opengrc"] = opengrc.get("dir")
        stamp["probo"] = str(probo)
        stamp["sinks_posted"] = False
    if not ok:
        stamp["reason"] = {
            "ciso_files": ciso_files,
            "posted": result.get("posted"),
            "http": result.get("http"),
            "pack_in_written": after != before,
            "paying_day": paying,
            "sample": result.get("sample"),
            "client_keep": result.get("client_keep"),
            "register_shape": shape_ok,
            "use_existing_in": use_existing_in,
            "findings": findings_n,
            "risk_scenarios": scenarios_n,
            "poam": poam_n,
        }
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "prove-ciso.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    return stamp


def _resolve_work(raw: str | None) -> Path:
    if not raw:
        return ROOT / "prove" / "work"
    path = Path(raw)
    return path if path.is_absolute() else ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "SAMPLE/DEMO Covey pack_drop + honeypot -> prove/work/out/ciso-assistant "
            "(default seeds fixtures). --use-existing-in keeps dest/in (LAB/DEMO). "
            "Never writes pack in/. Not a client estate. Paying-day stays FAIL."
        )
    )
    parser.add_argument(
        "--work",
        default="",
        help="Isolation dir (default: prove/work). Never pack in/.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Check existing prove-ciso.json + CISO outputs; do not re-seed.",
    )
    parser.add_argument(
        "--use-existing-in",
        "--no-seed",
        dest="use_existing_in",
        action="store_true",
        help=(
            "Do not rmtree/reseed dest/in. Require dest/in already populated "
            "(LAB compose pack_drop or operator copy). LAB/DEMO != SAMPLE != client."
        ),
    )
    args = parser.parse_args(argv)
    dest = _resolve_work(args.work)
    if args.verify_only:
        try:
            verified = verify_farm_drop_sor(dest)
        except FarmDropHonestyError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except LabShapeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        stamp = verified.get("stamp") or {}
        if stamp.get("lab") is True or stamp.get("use_existing_in") is True:
            print(LAB_HONESTY_OK_LINE)
        else:
            print(HONESTY_OK_LINE)
        return 0

    try:
        stamp = prove_ciso(dest=dest, use_existing_in=args.use_existing_in)
    except ExistingInError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except LabShapeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(stamp, indent=2, default=str))
    print(
        f"PROVE_CISO={stamp['status']} sample={stamp['sample']} lab={stamp.get('lab')} "
        f"client={stamp['client']} paying_day={stamp['paying_day']} posted={stamp['posted']} "
        f"assets={stamp['counts'].get('assets')} findings={stamp['counts'].get('findings')} "
        f"poam={stamp['counts'].get('poam')}"
    )
    print(f"POAM={stamp.get('poam') or (dest / 'out' / 'poam' / 'poam.csv')}")
    if stamp.get("status") != "pass":
        return 1
    try:
        verify_farm_drop_sor(dest)
    except FarmDropHonestyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except LabShapeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.use_existing_in:
        print("Estate is LAB/DEMO dest_in. Not SAMPLE fixture reseed. Not a client. Paying-day stays FAIL.")
    else:
        print("Estate is SAMPLE/DEMO fixtures. Not a client. Paying-day stays FAIL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
