"""Create an isolated engagements/<slug>/ kit. Lab SCOPE cannot be client_facing_ready."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dropbox.orchestrator.scope import ScopeError, load_scope

PACK = Path(__file__).resolve().parents[1]
SENSOR_EVIDENCE = (
    "cloud",
    "nmap",
    "vuln",
    "wazuh",
    "identity",
    "easm",
    "k8s",
    "code",
    "saas",
)
SLUG_OK = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class EngagementError(SystemExit):
    """Factory refuse. Not a scanner failure."""


def engagement_root() -> Path:
    raw = os.environ.get("ENGAGEMENT_ROOT")
    return Path(raw).resolve() if raw else (PACK / "engagements")


def _copy_tree(src: Path, dest: Path) -> None:
    if not src.is_dir():
        return
    dest.mkdir(parents=True, exist_ok=True)
    for path in src.iterdir():
        if path.name.startswith("."):
            continue
        target = dest / path.name
        if path.is_dir():
            _copy_tree(path, target)
        else:
            shutil.copy2(path, target)


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _summary() -> dict[str, Any]:
    path = PACK / "out" / "summary.json"
    data = _read_json(path) or {}
    return data


def leftover_discover_brake(scope_client: str) -> tuple[str | None, str]:
    """Reuse leftover-estate names. Other-client discover is not this slug's evidence."""
    blob = _read_json(PACK / "dropbox" / "out" / "discover.json")
    if not blob:
        return None, ""
    client = str(blob.get("client") or "").strip()
    if not client:
        return "discover_client_missing", client
    if client != scope_client:
        return "discover_client_mismatch", client
    return None, client


def _poam_dir(src: Path) -> Path:
    if (src / "poam").is_dir():
        return src / "poam"
    return src


def new_engagement(
    slug: str,
    scope_path: Path,
    *,
    archive_leftover: bool = False,
    evidence_label: str | None = None,
    artifact_src: Path | None = None,
    counts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    slug = (slug or "").strip().lower()
    if not SLUG_OK.fullmatch(slug):
        raise EngagementError("slug must be lowercase letters, digits, hyphen")
    scope_path = Path(scope_path)
    scope = load_scope(scope_path)
    root = engagement_root()
    dest = root / slug
    dest.mkdir(parents=True, exist_ok=True)

    shutil.copy2(scope_path, dest / "SCOPE.yaml")

    if archive_leftover:
        from dropbox.archive_out import archive_dropbox_out

        archive_dropbox_out(current_client=scope.client_legal_name, clear=False)

    label = (evidence_label or "fixture").strip() or "fixture"
    estate = artifact_src is not None
    evidence_paths: list[str] = []
    if estate:
        for sub in ("ciso-assistant", "poam", "quote", "simplerisk", "evidence"):
            stale = dest / "out" / sub
            if stale.is_dir():
                shutil.rmtree(stale)
        src = Path(artifact_src)
        poam_src = _poam_dir(src)
        (dest / "out" / "poam").mkdir(parents=True, exist_ok=True)
        for name in ("poam.csv", "control_map.json", "MANIFEST.json"):
            f = poam_src / name
            if f.is_file():
                shutil.copy2(f, dest / "out" / "poam" / name)
        quote_src = src / "quote" if (src / "quote").is_dir() else src
        if (quote_src / "quote.csv").is_file():
            (dest / "out" / "quote").mkdir(parents=True, exist_ok=True)
            shutil.copy2(quote_src / "quote.csv", dest / "out" / "quote" / "quote.csv")
            if (quote_src / "MANIFEST.json").is_file():
                shutil.copy2(quote_src / "MANIFEST.json", dest / "out" / "quote" / "MANIFEST.json")
        sr = src / "simplerisk" / "risks_import.csv"
        if not sr.is_file():
            sr = src / "simplerisk_import.csv"
        if sr.is_file():
            (dest / "out" / "simplerisk").mkdir(parents=True, exist_ok=True)
            shutil.copy2(sr, dest / "out" / "simplerisk" / "risks_import.csv")
        ciso_note = dest / "out" / "ciso-assistant"
        ciso_note.mkdir(parents=True, exist_ok=True)
        (ciso_note / "README.md").write_text(
            "Estate kit. Do not copy leftover Litware pack `out/ciso-assistant` (132/155/9) as this estate.\n"
            "CISO auto-push remains assets.csv + evidences.csv from a real loader run.\n"
            "Findings/POA&M for this slug are HITL: out/poam/poam.csv.\n",
            encoding="utf-8",
        )
    else:
        ciso_src = PACK / "out" / "ciso-assistant"
        poam_src = PACK / "out" / "poam"
        quote_src = PACK / "out" / "quote"
        sr_src = PACK / "out" / "simplerisk"
        if not ciso_src.is_dir():
            raise EngagementError("run_lab.ps1 / ingest first: missing out/ciso-assistant")
        _copy_tree(ciso_src, dest / "out" / "ciso-assistant")
        _copy_tree(poam_src, dest / "out" / "poam")
        _copy_tree(quote_src, dest / "out" / "quote")
        _copy_tree(sr_src, dest / "out" / "simplerisk")
        ev_dest = dest / "out" / "evidence"
        ev_dest.mkdir(parents=True, exist_ok=True)
        for name in SENSOR_EVIDENCE:
            src = PACK / "out" / "evidence" / f"{name}.md"
            if src.is_file():
                shutil.copy2(src, ev_dest / f"{name}.md")
                evidence_paths.append(f"out/evidence/{name}.md")

    brake, leftover_client = leftover_discover_brake(scope.client_legal_name)
    orch = PACK / "dropbox" / "out"
    if not brake and (orch / "discover.json").is_file():
        (dest / "out" / "orchestrator").mkdir(parents=True, exist_ok=True)
        shutil.copy2(orch / "discover.json", dest / "out" / "orchestrator" / "discover.json")

    summary = counts if isinstance(counts, dict) else (_summary() if not estate else {})
    findings = int(summary.get("findings") or summary.get("poam_rows") or 0)
    evidence_n = len(evidence_paths)
    facing = False
    blocked_by = "fixture_not_client_estate"
    if label.lower() in {"lab-sim", "docker-lab", "docker-sim", "live-byo"}:
        blocked_by = "lab_sim_not_client_estate"
        if "docker estate" not in scope.client_legal_name.lower() and label.lower() == "live-byo":
            blocked_by = "fixture_not_client_estate"
    if not scope.integrity.allow_live_exec:
        blocked_by = "live_exec_not_allowed"
    if brake:
        blocked_by = brake
    refuse = scope.refuse_live()
    if refuse:
        blocked_by = refuse
        facing = False
    if "docker estate" in scope.client_legal_name.lower():
        blocked_by = "lab_sim_not_client_estate"
        facing = False

    note = (
        "Lab-sim estate kit. Not a customer estate. Not a paying-day PASS. POA&M from this run, not Litware fixture CSVs."
        if estate
        else "Lab/fixture kit. Not a client estate. Not a paying-day PASS."
    )
    manifest = {
        "slug": slug,
        "client": scope.client_legal_name,
        "scope": str(scope_path),
        "written_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_label": label,
        "client_facing_ready": False,
        "blocked_by": blocked_by,
        "leftover_discover_brake": brake,
        "leftover_discover_client": leftover_client,
        "allow_live_exec": bool(scope.integrity.allow_live_exec),
        "counts": {
            "assets": summary.get("assets"),
            "findings": findings,
            "evidence": evidence_n,
            "incidents": summary.get("incidents"),
            "vulnerabilities": summary.get("vulnerabilities"),
            "pack_mapped": summary.get("pack_mapped"),
            "poam_rows": summary.get("poam_rows"),
        },
        "pytest_stamp": "see pack run_lab.ps1 / CHANGELOG",
        "note": note,
    }
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    exec_lines = [
        "# Engagement executive — " + slug,
        "",
        f"client: {scope.client_legal_name}",
        f"label: **{label}** (not a customer estate)",
        "client_facing_ready: **false**",
        f"blocked_by: {blocked_by}",
        "",
        f"findings: {findings}",
        f"evidence_files: {evidence_n}",
    ]
    if estate:
        exec_lines.extend(
            [
                "Estate POA&M is out/poam/poam.csv from this run. Pack loader 132/155/9 is not this estate.",
                "",
            ]
        )
    else:
        exec_lines.extend(
            [
                "known demo smell: nine sensor evidence.md files vs 155 findings. Do not invent screenshots.",
                "",
                "Nine evidence paths:",
            ]
        )
        exec_lines.extend(f"- {p}" for p in evidence_paths)
    exec_lines.extend(
        [
            "",
            "Brakes: unsigned/empty/window/`allow_tools` refuse live; leftover other-client discover is not this slug.",
            "Quote hours/rate/total are blank. RiskReady WRAP_DEAD. No live scan in this kit.",
            "",
        ]
    )
    (dest / "EXECUTIVE.md").write_text("\n".join(exec_lines), encoding="utf-8")

    runbook = f"""# OPERATOR_RUN — {slug}

Fixture Litware-style kit unless Reid replaces SCOPE.yaml with a signed live SCOPE.

```powershell
cd "{PACK}"
$env:PYTHONPATH = (Get-Location)
powershell -ExecutionPolicy Bypass -File .\\run_lab.ps1
python -m dropbox.orchestrator plan --scope engagements\\{slug}\\SCOPE.yaml
python -m dropbox.new_engagement --slug {slug} --scope engagements\\{slug}\\SCOPE.yaml
python -m dropbox.package_engagement --slug {slug}
```

Say out loud: this is fixture, not a customer. client_facing_ready is false.
"""
    (dest / "OPERATOR_RUN.md").write_text(runbook, encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create engagements/<slug>/ kit (fixture cannot be client-facing).")
    parser.add_argument("--slug", required=True)
    parser.add_argument("--scope", default=str(PACK / "dropbox" / "SCOPE.example.yaml"))
    parser.add_argument(
        "--archive-leftover",
        action="store_true",
        help="Copy leftover dropbox/out into engagements/_archive if client mismatches.",
    )
    args = parser.parse_args(argv)
    try:
        manifest = new_engagement(args.slug, Path(args.scope), archive_leftover=args.archive_leftover)
    except (EngagementError, ScopeError) as exc:
        print(f"ENGAGEMENT_FAIL: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    if manifest.get("client_facing_ready"):
        print("P0: fixture kit must not be client_facing_ready", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
