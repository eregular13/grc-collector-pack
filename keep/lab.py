"""KEEP-chain lab: samples or pack in/ → Layer C → Eval handoff. Not pack in/."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keep.adapters import (
    KEEP_FAMILIES,
    client_keep_ready,
    keep_collectors,
    land_keep_files,
    scan_keep_dir,
)
from keep.handoff import write_eval_handoff

ENV_KEYS = (
    "IN_DIR",
    "OUT_DIR",
    "DRY_RUN",
    "GRC_LIVE_SCAN",
    "CISO_PUSH",
    "RISKREADY_PUSH",
    "PYTHONPATH",
    "DROPBOX_LIVE",
    "DROPBOX_DEMO",
)

SAMPLE_BANNER = (
    "SAMPLE — redacted KEEP-chain fixtures. Not a client KEEP drop.\n"
    "keep-lab uses fixtures/keep-samples/ until pack in/ has all four families.\n"
    "Do not market this as a client estate. Do not POST /api/risks.\n"
)


def _stamp_sample_labels(out: Path) -> None:
    folder = out / "canonical"
    if not folder.is_dir():
        return
    for path in folder.glob("*.jsonl"):
        lines: list[str] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                lines.append(raw)
                continue
            if isinstance(rec, dict):
                labels = rec.setdefault("labels", [])
                if isinstance(labels, list):
                    for stamp in ("demo", "sample"):
                        if stamp not in labels:
                            labels.append(stamp)
            lines.append(json.dumps(rec, separators=(",", ":")))
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _choose_sources(root: Path, pack_in: Path) -> tuple[list[dict[str, Any]], bool, str]:
    pack_rows = scan_keep_dir(pack_in)
    if client_keep_ready(pack_rows):
        return pack_rows, True, "pack-in"
    samples = root / "fixtures" / "keep-samples"
    sample_rows = scan_keep_dir(samples)
    return sample_rows, False, "keep-samples"


def keep_lab(
    root: Path | None = None,
    *,
    pack_in: Path | None = None,
    work: Path | None = None,
) -> dict[str, Any]:
    root = Path(root or ROOT)
    pack_in = Path(pack_in or (root / "in"))
    work = Path(work or (root / "keep" / "work"))
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    try:
        return _run(root, pack_in, work)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _run(root: Path, pack_in: Path, work: Path) -> dict[str, Any]:
    work_in = work / "in"
    work_out = work / "out"
    for folder in (work_in, work_out):
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)

    sources, client_keep, origin = _choose_sources(root, pack_in)
    landed = land_keep_files(sources, work_in)
    groups = {str(row.get("group") or "") for row in landed}
    missing = [name for name in KEEP_FAMILIES if name not in groups]
    sample = (not client_keep) or any(row.get("sample") for row in landed)

    for sensor in ("identity", "saas", "vuln", "cloud"):
        dest = work_in / sensor
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "SAMPLE.txt").write_text(SAMPLE_BANNER, encoding="utf-8")

    os.environ["IN_DIR"] = str(work_in)
    os.environ["OUT_DIR"] = str(work_out)
    os.environ["DRY_RUN"] = "1"
    os.environ["GRC_LIVE_SCAN"] = "0"
    os.environ["CISO_PUSH"] = "0"
    os.environ["RISKREADY_PUSH"] = "0"
    os.environ["DROPBOX_LIVE"] = "0"
    os.environ["DROPBOX_DEMO"] = "1" if sample else "0"
    os.environ.setdefault("PYTHONPATH", str(root))

    ran: list[str] = []
    env = os.environ.copy()
    env["IN_DIR"] = str(work_in)
    env["OUT_DIR"] = str(work_out)
    env["PYTHONPATH"] = str(root)
    for _source, name in keep_collectors():
        proc = subprocess.run(
            [sys.executable, str(root / "collectors" / name)],
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"{name} exit {proc.returncode}: {(proc.stderr or proc.stdout)[-400:]}")
        ran.append(name)

    if sample:
        _stamp_sample_labels(work_out)

    loader = subprocess.run(
        [sys.executable, str(root / "collectors" / "grc_loader.py")],
        cwd=str(root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if loader.returncode != 0:
        raise RuntimeError(f"grc_loader exit {loader.returncode}: {(loader.stderr or loader.stdout)[-400:]}")
    ran.append("grc_loader.py")

    handoff_path = write_eval_handoff(
        work_out,
        sample=sample,
        client_keep=client_keep,
        sources=landed,
    )
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    summary_path = work_out / "summary.json"
    counts = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
    wrote_pack = False
    if (root / "in").is_dir() and origin == "keep-samples":
        for p in (root / "in").rglob("*"):
            if p.is_file() and p.name not in {".gitkeep", ".DS_Store"}:
                wrote_pack = True
                break

    stamp = {
        "status": "pass",
        "demo": True if sample else bool(counts.get("demo")),
        "sample": sample,
        "client_keep": bool(client_keep) and not sample,
        "label": handoff.get("label"),
        "origin": origin,
        "pack_in_used": origin == "pack-in",
        "pack_in_written": wrote_pack,
        "in_dir": str(work_in),
        "out_dir": str(work_out),
        "handoff": str(handoff_path),
        "families": sorted(groups),
        "missing_families": missing,
        "landed": [row.get("name") for row in landed],
        "collectors": ran,
        "posted": False,
        "http": False,
        "wrap": "review-only",
        "counts": {
            "assets": counts.get("assets"),
            "findings": counts.get("findings"),
            "vulnerabilities": counts.get("vulnerabilities"),
            "evidences": counts.get("evidences"),
            "poam": counts.get("poam"),
            "handoff_findings": handoff.get("counts", {}).get("findings_selected"),
            "handoff_assets": handoff.get("counts", {}).get("assets_selected"),
            "demo": counts.get("demo"),
        },
        "note": "SAMPLE ≠ client KEEP unless pack in/ has all four non-sample families.",
    }
    if missing:
        stamp["status"] = "fail"
        stamp["reason"] = f"KEEP families missing: {missing}"
    elif not landed:
        stamp["status"] = "fail"
        stamp["reason"] = "no KEEP files landed"
    elif not handoff.get("findings"):
        stamp["status"] = "fail"
        stamp["reason"] = "Eval handoff has no findings"
    elif int(handoff.get("counts", {}).get("findings_selected") or 0) > 5:
        stamp["status"] = "fail"
        stamp["reason"] = "Eval handoff exceeded max-5 findings"
    elif handoff.get("posted") or handoff.get("http"):
        stamp["status"] = "fail"
        stamp["reason"] = "handoff must stay file-drop (no HTTP)"
    elif sample and counts.get("demo") is not True:
        stamp["status"] = "fail"
        stamp["reason"] = "sample keep-lab must stamp summary.demo true"
    elif wrote_pack and origin == "keep-samples":
        stamp["status"] = "fail"
        stamp["reason"] = "keep-lab wrote pack in/"
    (work / "keep-lab.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    return stamp


def main() -> int:
    stamp = keep_lab()
    print(json.dumps(stamp, indent=2))
    print(
        f"KEEP_LAB={stamp['status']} sample={stamp['sample']} "
        f"client_keep={stamp['client_keep']} "
        f"handoff_findings={stamp['counts'].get('handoff_findings')} "
        f"origin={stamp['origin']}"
    )
    if stamp.get("status") != "pass":
        return 1
    if stamp.get("sample"):
        print("Estate is SAMPLE KEEP-chain fixtures. Not a client KEEP drop.")
    return 0
