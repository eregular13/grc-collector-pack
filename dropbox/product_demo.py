"""One-command product demo against the isolated Docker estate. Not cycle 11. Not a paying client."""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from dropbox.new_engagement import new_engagement
from dropbox.orchestrator.plan import build_plan
from dropbox.orchestrator.run import run
from dropbox.orchestrator.scope import load_scope
from dropbox.package_engagement import package_slug

PACK = Path(__file__).resolve().parents[1]
SCOPE = PACK / "dropbox" / "SCOPE.docker-estate.yaml"
HITL_LAB = PACK / "dropbox" / "HITL.docker-estate.json"
ESTATE_OUT = PACK / "out-estate"
WEB = "http://127.0.0.1:18081/"
API = "http://127.0.0.1:18082/"
SINK = os.environ.get("SINK_URL", "http://127.0.0.1:18080").rstrip("/")
PT = timezone(timedelta(hours=-7))
SLUG = "docker-estate-product"


class EstateDown(SystemExit):
    """estate-web did not answer. Do not compose c11."""


def _curl_head(url: str, timeout: int = 8) -> tuple[int, str]:
    exe = "curl.exe" if sys.platform.startswith("win") else "curl"
    proc = subprocess.run(
        [exe, "-sS", "-I", "--max-time", str(timeout), "--max-redirs", "0", "--", url],
        capture_output=True,
        text=True,
        timeout=timeout + 4,
        check=False,
        shell=False,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, blob


def estate_up() -> bool:
    code, blob = _curl_head(WEB)
    return code == 0 and "HTTP/" in blob


def _health() -> str:
    try:
        with urlopen(SINK + "/health", timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return f"sink_error:{type(exc).__name__}"


def _post_importer(csv_path: Path) -> int:
    if not csv_path.is_file():
        return 0
    data = csv_path.read_bytes()
    boundary = "----grcpackdemo"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{csv_path.name}"\r\n'
        "Content-Type: text/csv\r\n\r\n"
    ).encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    req = Request(
        SINK + "/api/importer/",
        data=body,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urlopen(req, timeout=15) as resp:
            return int(resp.status)
    except Exception:  # noqa: BLE001
        return 0


def _write_hitl(dest: Path) -> dict[str, Any]:
    now = datetime.now(PT).strftime("%Y-%m-%dT%H:%M:%S-07:00")
    blob = {
        "attested": True,
        "client": "Evergreen Docker Estate LLC",
        "reviewer": "Reid Schram",
        "timestamp": now,
        "slug": SLUG,
        "evidence_label": "lab-sim",
    }
    if HITL_LAB.is_file():
        try:
            prior = json.loads(HITL_LAB.read_text(encoding="utf-8"))
            if isinstance(prior, dict) and prior.get("client"):
                blob["client"] = str(prior.get("client") or blob["client"])
                blob["attested"] = prior.get("attested") is True
                if prior.get("reviewer"):
                    blob["reviewer"] = str(prior["reviewer"])
        except json.JSONDecodeError:
            pass
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "HITL.json").write_text(json.dumps(blob, indent=2), encoding="utf-8")
    HITL_LAB.write_text(json.dumps(blob, indent=2), encoding="utf-8")
    return blob


def _scope_ok() -> None:
    text = SCOPE.read_text(encoding="utf-8")
    if "192.168.10.0/24" in text:
        raise SystemExit("SCOPE.docker-estate.yaml drifted onto office LAN")
    if "172.28.90.0/24" not in text:
        raise SystemExit("SCOPE.docker-estate.yaml missing isolated 172.28.90.0/24")
    load_scope(SCOPE)
    if "127.0.0.1:18081" not in text or "127.0.0.1:18082" not in text:
        raise SystemExit("SCOPE.docker-estate.yaml missing loopback publishes")
    if "127.0.0.1:18443" not in text:
        raise SystemExit("SCOPE.docker-estate.yaml missing TLS loopback 18443")
    parsed = urlparse(WEB)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise SystemExit("demo loopback drifted")


def _export_estate_out(orch: Path) -> Path:
    """Live POA&M from dropbox/out. Pack out/poam is fixture after run_lab.ps1."""
    ESTATE_OUT.mkdir(parents=True, exist_ok=True)
    poam = ESTATE_OUT / "poam"
    poam.mkdir(exist_ok=True)
    mapping = (
        (orch / "poam.csv", poam / "poam.csv"),
        (orch / "control_map.json", poam / "control_map.json"),
        (orch / "poam_MANIFEST.json", poam / "MANIFEST.json"),
        (orch / "quote.csv", ESTATE_OUT / "quote" / "quote.csv"),
        (orch / "simplerisk_import.csv", ESTATE_OUT / "simplerisk" / "risks_import.csv"),
    )
    for src, dest in mapping:
        if not src.is_file():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    (ESTATE_OUT / "README.md").write_text(
        "Estate-run artifacts. Not pack `out/` (fixture Litware after run_lab.ps1).\n"
        "See docs/OUT_DIR.md.\n",
        encoding="utf-8",
    )
    return ESTATE_OUT


def mapped_classes_from_poam(path: Path) -> list[str]:
    """POA&M weakness names that are mapped (not UNMAPPED). Order preserved."""
    if not path.is_file():
        return []
    names: list[str] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            name = (row.get("weakness") or "").strip()
            refs = row.get("control_refs") or ""
            if not name or name in seen or "UNMAPPED" in refs:
                continue
            seen.add(name)
            names.append(name)
    return names


def plan_only() -> dict[str, Any]:
    """--dry-run / plan: no sink POST, no zip, no orchestrator run."""
    _scope_ok()
    scope = load_scope(SCOPE)
    plan = build_plan(scope)
    rec = {
        "ok": True,
        "dry_run": True,
        "command": "plan",
        "estate_up": estate_up(),
        "client": plan.get("client"),
        "label": plan.get("label"),
        "refuse_live": (plan.get("brakes") or {}).get("refuse_live") if isinstance(plan.get("brakes"), dict) else None,
        "note": "plan only; no sink POST; no engagements zip",
    }
    print(json.dumps(rec, indent=2, default=str))
    return rec


def run_demo() -> dict[str, Any]:
    _scope_ok()
    if not estate_up():
        print(json.dumps({"ok": False, "error": "estate_down", "web": WEB}))
        raise EstateDown("estate_down")
    dest = PACK / "dropbox" / "out"
    hitl = _write_hitl(dest)
    env_was = os.environ.get("EVERGREEN_ORCH_LIVE")
    os.environ["EVERGREEN_ORCH_LIVE"] = "1"
    try:
        payload = run(SCOPE, "all", dest=dest)
    finally:
        if env_was is None:
            os.environ.pop("EVERGREEN_ORCH_LIVE", None)
        else:
            os.environ["EVERGREEN_ORCH_LIVE"] = env_was
    ingest = payload.get("ingest") if isinstance(payload.get("ingest"), dict) else {}
    ge = payload.get("grc_export") if isinstance(payload.get("grc_export"), dict) else {}
    mapped = int(ingest.get("pack_mapped") or 0)
    poam_rows = int(ingest.get("poam_rows") or 0)
    facing = bool(ge.get("client_facing_ready"))
    blocked = (ge.get("hitl") or {}).get("blocked_by") if isinstance(ge.get("hitl"), dict) else None

    estate_out = _export_estate_out(dest)
    classes = mapped_classes_from_poam(estate_out / "poam" / "poam.csv")
    posted: list[str] = []
    manifest = new_engagement(
        SLUG,
        SCOPE,
        evidence_label="lab-sim",
        artifact_src=estate_out,
        counts={"pack_mapped": mapped, "poam_rows": poam_rows, "findings": poam_rows},
    )
    slug_dir = PACK / "engagements" / SLUG
    run_md = slug_dir / "PRODUCT_RUN.md"
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    zpath = PACK / "engagements" / f"engagement-{SLUG}-{day}.zip"
    lines = [
        "# PRODUCT_RUN — docker-estate-product",
        "",
        "Isolated Docker estate. Not a client LAN. Not cycle 11. Not a paying client.",
        "",
        "```powershell",
        'cd "C:\\GRC Collector\\grc-collector-pack"',
        "$env:PYTHONPATH = (Get-Location)",
        "$env:DRY_RUN = \"1\"; $env:CISO_PUSH = \"0\"; $env:RISKREADY_PUSH = \"0\"; $env:GRC_LIVE_SCAN = \"0\"",
        "python -m dropbox.product_demo --help",
        "python -m dropbox.product_demo",
        "```",
        "",
        f"web: {WEB}",
        f"api: {API}",
        f"pack_mapped: {mapped}",
        f"mapped_classes: {'; '.join(classes)}",
        f"poam_rows: {poam_rows}",
        f"ingest_label: {ingest.get('label')}",
        f"client_facing_ready: {facing}",
        f"blocked_by: {blocked}",
        f"hitl_attested: {hitl.get('attested')} evidence_label={hitl.get('evidence_label')}",
        "sink: not posted from pack Litware CSVs (see docs/OUT_DIR.md)",
        f"mock_push: {posted or 'skipped'}",
        f"zip: {zpath}",
        f"kit_facing: {manifest.get('client_facing_ready')}",
        f"kit_blocked_by: {manifest.get('blocked_by')}",
        f"kit_evidence_label: {manifest.get('evidence_label')}",
        "",
        "Findings/POA&M stay HITL. Risks API is WRAP_DEAD (no POST). WRAP_DEAD.",
        "",
    ]
    run_md.write_text("\n".join(lines), encoding="utf-8")
    zpath = package_slug(SLUG)
    rec = {
        "ok": True,
        "slug": SLUG,
        "pack_mapped": mapped,
        "mapped_classes": classes,
        "poam_rows": poam_rows,
        "client_facing_ready": facing,
        "blocked_by": blocked,
        "hitl": hitl,
        "zip": str(zpath),
        "product_run": str(run_md),
        "posted": posted,
        "estate_web": WEB,
        "evidence_label": manifest.get("evidence_label"),
        "kit_facing": manifest.get("client_facing_ready"),
    }
    return rec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dropbox.product_demo",
        description="Isolated Docker estate demo. Lab-sim. Not a paying client. --help does not hit the sink.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="run",
        choices=["run", "plan"],
        help="run (default) or plan",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan only: no orchestrator run, no sink POST, no zip.",
    )
    args = parser.parse_args(argv)
    if args.dry_run or args.command == "plan":
        plan_only()
        return 0
    try:
        rec = run_demo()
    except EstateDown:
        return 2
    print(json.dumps(rec, indent=2, default=str))
    if int(rec.get("pack_mapped") or 0) < 1:
        print("P0: pack_mapped still 0 — mapping did not land", file=sys.stderr)
        return 2
    if rec.get("client_facing_ready") is True:
        print("P0: docker-sim must not be client_facing_ready", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
