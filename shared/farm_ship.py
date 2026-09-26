"""Farm wipe/clone ship-gate surface. CI/lab only.

A ship event is pack HEAD of this assertion surface changing — not an
identical re-PASS of the same files. Not an operator entrypoint.
SAMPLE/DEMO != client. paying_day FAIL. Not client KEEP.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Iterable

from shared.ciso_shape import (
    CISO_HEADERS,
    POAM_HEADER,
    RegisterShapeError,
    assert_risk_register_and_poam,
    first_nonempty_line,
)

# Paths whose content change is a farm ship event. Unrelated commits
# (STATUS restamp, docs vanity, collector comments) are not a ship.
FARM_SHIP_PATHS: tuple[str, ...] = (
    ".github/workflows/lab.yml",
    "scripts/farm_drop_to_sor.sh",
    "scripts/farm_drop_to_sor.ps1",
    "scripts/prove_ciso.py",
    "scripts/ci/farm_drop_wipe_clone_ship.sh",
    "scripts/ci/farm_ship_surface.py",
    "shared/ciso_shape.py",
    "shared/estate_pages.py",
    "shared/farm_ship.py",
    "collectors/grc_loader.py",
    "docs/FARM_SHIP_GATE.md",
    "tests/test_farm_ship_gate.py",
)
FARM_SHIP_TREES: tuple[str, ...] = ("fixtures/pack_drop",)

ZERO_SHA = "0" * 40
SHIP_YES = "yes"
SHIP_SKIP = "skip"
# ASCII-only: Windows cp1252 cannot print U+2260 / U+2192.
FARM_SHIP_OK_LINE = "FARM_SHIP=yes LAB=farm_wipe_clone SAMPLE=true paying_day=FAIL != client KEEP"


class FarmShipError(ValueError):
    """Wipe/clone farm SoR failed honesty or register shape."""


def git_head(root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def iter_surface_relpaths(root: Path) -> list[str]:
    """Committed + working-tree files on the farm assertion surface."""
    seen: set[str] = set()
    out: list[str] = []
    for rel in FARM_SHIP_PATHS:
        if rel not in seen:
            seen.add(rel)
            out.append(rel.replace("\\", "/"))
    pack = root / "fixtures" / "pack_drop"
    if pack.is_dir():
        for path in sorted(pack.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if rel not in seen:
                seen.add(rel)
                out.append(rel)
    return out


def surface_fingerprint(root: Path) -> str:
    """sha256 of surface file bytes. HEAD is metadata, not the product."""
    digest = hashlib.sha256()
    for rel in iter_surface_relpaths(root):
        path = root / rel
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        if path.is_file():
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def is_zero_sha(ref: str | None) -> bool:
    if ref is None:
        return True
    text = ref.strip()
    if not text or text.lower() in {"null", "none", ""}:
        return True
    return set(text) <= {"0"}


def ref_exists(root: Path, ref: str) -> bool:
    if is_zero_sha(ref):
        return False
    proc = _git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    return proc.returncode == 0


def surface_changed_paths(root: Path, compare_ref: str) -> list[str]:
    """Files on the ship surface whose trees differ vs compare_ref."""
    if is_zero_sha(compare_ref) or not ref_exists(root, compare_ref):
        return list(iter_surface_relpaths(root))
    specs: list[str] = list(FARM_SHIP_PATHS)
    specs.extend(f"{tree}/" for tree in FARM_SHIP_TREES)
    proc = _git(root, "diff", "--name-only", compare_ref, "HEAD", "--", *specs)
    if proc.returncode != 0:
        return list(iter_surface_relpaths(root))
    changed = []
    for line in (proc.stdout or "").splitlines():
        rel = line.strip().replace("\\", "/")
        if rel:
            changed.append(rel)
    return changed


def decide_ship(root: Path, compare_ref: str | None) -> dict[str, Any]:
    """yes = HEAD/assertion surface changed. skip = identical re-PASS, not a ship."""
    head = git_head(root)
    fingerprint = surface_fingerprint(root)
    if is_zero_sha(compare_ref):
        return {
            "ship": SHIP_YES,
            "reason": "no-compare-ref",
            "head": head,
            "surface": fingerprint,
            "changed": [],
            "compare_ref": compare_ref or "",
        }
    ref = (compare_ref or "").strip()
    if not ref_exists(root, ref):
        return {
            "ship": SHIP_YES,
            "reason": "compare-ref-unresolved",
            "head": head,
            "surface": fingerprint,
            "changed": [],
            "compare_ref": ref,
        }
    if head and ref_exists(root, ref) and git_rev(root, ref) == head:
        return {
            "ship": SHIP_SKIP,
            "reason": "compare-ref-is-head",
            "head": head,
            "surface": fingerprint,
            "changed": [],
            "compare_ref": ref,
        }
    changed = surface_changed_paths(root, ref)
    if changed:
        return {
            "ship": SHIP_YES,
            "reason": "surface-changed",
            "head": head,
            "surface": fingerprint,
            "changed": changed,
            "compare_ref": ref,
        }
    return {
        "ship": SHIP_SKIP,
        "reason": "surface-unchanged",
        "head": head,
        "surface": fingerprint,
        "changed": [],
        "compare_ref": ref,
    }


def git_rev(root: Path, ref: str) -> str:
    proc = _git(root, "rev-parse", ref)
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def assert_farm_ship_sor(work: Path) -> dict[str, Any]:
    """Honesty + risk-register/POA&M shape. Fail closed on garbage."""
    dest = Path(work)
    stamp_path = dest / "prove-ciso.json"
    if not stamp_path.is_file():
        raise FarmShipError(f"FARM_SHIP_FAIL missing prove-ciso.json ({stamp_path})")
    try:
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FarmShipError(f"FARM_SHIP_FAIL prove-ciso.json garbage: {exc}") from exc
    if stamp.get("sample") is not True:
        raise FarmShipError("FARM_SHIP_FAIL sample must be true (SAMPLE/DEMO != client)")
    if stamp.get("demo") is not True:
        raise FarmShipError("FARM_SHIP_FAIL demo must be true")
    if stamp.get("client") is True or stamp.get("client_keep") is True:
        raise FarmShipError("FARM_SHIP_FAIL client/client_keep claimed on SAMPLE/DEMO")
    if stamp.get("paying_day") != "FAIL":
        raise FarmShipError("FARM_SHIP_FAIL paying_day FAIL expected for SAMPLE/DEMO")
    if stamp.get("posted") is True:
        raise FarmShipError("FARM_SHIP_FAIL posted must be false")
    try:
        shape = assert_risk_register_and_poam(dest / "out")
    except RegisterShapeError as exc:
        raise FarmShipError(f"FARM_SHIP_FAIL {exc}") from exc
    if int(shape.get("findings") or 0) < 1:
        raise FarmShipError(f"FARM_SHIP_FAIL empty findings register: {shape}")
    if int(shape.get("risk_scenarios") or 0) < int(shape["findings"]):
        raise FarmShipError(f"FARM_SHIP_FAIL risk_scenarios < findings: {shape}")
    if int(shape.get("poam_rows") or 0) < 1:
        raise FarmShipError(f"FARM_SHIP_FAIL empty POA&M: {shape}")
    counts = stamp.get("counts") or {}
    if "poam" in counts and counts["poam"] != shape["poam_rows"]:
        raise FarmShipError(f"FARM_SHIP_FAIL poam count mismatch {counts} {shape}")
    if shape.get("vulnerabilities") not in (0, None) and int(shape.get("vulnerabilities") or 0) != 0:
        raise FarmShipError("FARM_SHIP_FAIL farm_drop pack_drop is exposure, not CVE-class")
    ciso = dest / "out" / "ciso-assistant"
    for name in (
        "assets.csv",
        "findings.csv",
        "vulnerabilities.csv",
        "applied_controls.csv",
        "risk_scenarios.csv",
    ):
        path = ciso / name
        if not path.is_file():
            raise FarmShipError(f"FARM_SHIP_FAIL missing {name}")
        first = first_nonempty_line(path)
        if first != CISO_HEADERS[name]:
            raise FarmShipError(f"FARM_SHIP_FAIL header mismatch {name}: {first}")
    poam = dest / "out" / "poam" / "poam.csv"
    if not poam.is_file():
        raise FarmShipError(f"FARM_SHIP_FAIL missing POA&M csv ({poam})")
    if first_nonempty_line(poam) != POAM_HEADER:
        raise FarmShipError("FARM_SHIP_FAIL POA&M header mismatch")
    if not (dest / "out" / "poam" / "poam.md").is_file():
        raise FarmShipError("FARM_SHIP_FAIL missing POA&M md")
    excluded_path = dest / "out" / "poam" / "excluded.csv"
    if not excluded_path.is_file():
        raise FarmShipError("FARM_SHIP_FAIL missing poam/excluded.csv")
    with excluded_path.open(encoding="utf-8", newline="") as fh:
        excluded_rows = list(csv.DictReader(fh))
    if not excluded_rows:
        raise FarmShipError("FARM_SHIP_FAIL farm_drop excluded.csv is empty")
    reasons = {str(row.get("excluded_reason") or "") for row in excluded_rows}
    if "severity_info" not in reasons:
        raise FarmShipError(
            f"FARM_SHIP_FAIL excluded.csv missing infos: {sorted(reasons)}"
        )
    if "honeypot" not in reasons:
        raise FarmShipError(
            f"FARM_SHIP_FAIL excluded.csv missing honeypot: {sorted(reasons)}"
        )
    try:
        from shared.estate_pages import assert_client_export_honesty

        assert_client_export_honesty(dest / "out")
    except AssertionError as exc:
        raise FarmShipError(f"FARM_SHIP_FAIL {exc}") from exc
    return {
        "ok": True,
        "sample": True,
        "demo": True,
        "client": False,
        "paying_day": "FAIL",
        "posted": False,
        "findings": shape["findings"],
        "risk_scenarios": shape["risk_scenarios"],
        "poam_rows": shape["poam_rows"],
        "vulnerabilities": shape.get("vulnerabilities"),
    }


def format_github_output(decision: dict[str, Any]) -> str:
    changed = decision.get("changed") or []
    if isinstance(changed, Iterable) and not isinstance(changed, (str, bytes)):
        changed_s = ",".join(str(item) for item in changed)
    else:
        changed_s = str(changed)
    lines = [
        f"ship={decision.get('ship')}",
        f"reason={decision.get('reason')}",
        f"head={decision.get('head')}",
        f"surface={decision.get('surface')}",
        f"changed={changed_s}",
    ]
    return "\n".join(lines) + "\n"


def write_github_output(decision: dict[str, Any], dest: Path | None) -> None:
    text = format_github_output(decision)
    if dest is None:
        env_path = os.environ.get("GITHUB_OUTPUT")
        if not env_path:
            return
        dest = Path(env_path)
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text)
