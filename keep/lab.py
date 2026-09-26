"""KEEP-chain lab: samples or pack in/ → Layer C → Eval handoff. Not pack in/."""

from __future__ import annotations

import hashlib
import json
import os
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
    pack_in_is_lab,
    sample_as_client_reason,
    scan_keep_dir,
)
from keep.ciso_import import (
    header_mismatch,
    honest_paying_day,
    listed_ciso_files,
    missing_required_ciso,
    read_paying_day,
    write_ciso_import_manifest,
)
from shared.ciso_shape import RegisterShapeError, assert_risk_register_and_poam
from keep.export import export_keep_sinks
from keep.handoff import write_eval_handoff
from keep.wipe import reset_dir
from dropbox.keep_preflight import (
    KEEP_FAIL_WRONG_SCHEMA,
    KeepFixtureError,
    require_keep_samples,
)

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


_PACK_SKIP = frozenset({".gitkeep", ".DS_Store"})


def _pack_tree_fingerprint(folder: Path) -> dict[str, str]:
    """Relative path → sha256 for non-skip files. Used to detect THIS-run writes."""
    out: dict[str, str] = {}
    if not folder.is_dir():
        return out
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name in _PACK_SKIP:
            continue
        rel = str(path.relative_to(folder)).replace("\\", "/")
        out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def _watched_pack_dirs(root: Path, pack_in: Path) -> list[Path]:
    watched = [Path(pack_in)]
    repo_in = root / "in"
    if repo_in.resolve() != Path(pack_in).resolve():
        watched.append(repo_in)
    return watched


def _choose_sources(root: Path, pack_in: Path) -> tuple[list[dict[str, Any]], bool, str]:
    # LAB dest_in never becomes client KEEP and never counts toward keep_real.
    if pack_in_is_lab(pack_in):
        samples = root / "fixtures" / "keep-samples"
        return scan_keep_dir(samples), False, "keep-samples"
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


def _reset_keep_work_trees(work: Path) -> tuple[Path, Path]:
    """Wipe keep/work/{in,out} with the shared Windows-safe helper. Twin of keep_ciso."""
    work = Path(work)
    work_in = reset_dir(work / "in")
    work_out = reset_dir(work / "out")
    return work_in, work_out


def _run(root: Path, pack_in: Path, work: Path) -> dict[str, Any]:
    last: dict[str, Any] | None = None
    for attempt in range(2):
        last = _run_once(root, pack_in, work)
        if last.get("status") == "pass":
            return last
        reason = str(last.get("reason") or "")
        if "CISO Assistant CSVs missing" not in reason:
            return last
        # Windows pending-delete after a stranger wipe of keep/work can eat a
        # just-written out/ tree. One retry on a fresh reset.
        _reset_keep_work_trees(work)
    return last or {}


def _run_once(root: Path, pack_in: Path, work: Path) -> dict[str, Any]:
    work_in, work_out = _reset_keep_work_trees(work)
    before = {str(path): _pack_tree_fingerprint(path) for path in _watched_pack_dirs(root, pack_in)}

    sources, client_keep, origin = _choose_sources(root, pack_in)
    if origin == "keep-samples":
        try:
            require_keep_samples(root)
        except KeepFixtureError as exc:
            stamp = {
                "status": "fail",
                "demo": True,
                "sample": True,
                "client_keep": False,
                "paying_day": "FAIL",
                "origin": origin,
                "posted": False,
                "http": False,
                "wrap": "review-only",
                "reason": str(exc),
                "fail_code": getattr(exc, "code", "") or KEEP_FAIL_WRONG_SCHEMA,
                "counts": {},
                "ciso_files": [],
            }
            work.mkdir(parents=True, exist_ok=True)
            (work / "keep-lab.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
            return stamp
        sample_groups = {str(row.get("group") or "") for row in sources}
        unparseable = [name for name in KEEP_FAMILIES if name not in sample_groups]
        if unparseable:
            stamp = {
                "status": "fail",
                "demo": True,
                "sample": True,
                "client_keep": False,
                "paying_day": "FAIL",
                "origin": origin,
                "posted": False,
                "http": False,
                "wrap": "review-only",
                "fail_code": KEEP_FAIL_WRONG_SCHEMA,
                "counts": {},
                "ciso_files": [],
                "reason": (
                    f"{KEEP_FAIL_WRONG_SCHEMA}: keep fixture malformed: "
                    f"families not parseable: {unparseable}. "
                    "SAMPLE keep-samples must include all four families."
                ),
            }
            work.mkdir(parents=True, exist_ok=True)
            (work / "keep-lab.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
            return stamp
    landed = land_keep_files(sources, work_in)
    groups = {str(row.get("group") or "") for row in landed}
    missing = [name for name in KEEP_FAMILIES if name not in groups]
    sample = (not client_keep) or any(row.get("sample") for row in landed)

    if sample:
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

    sinks = export_keep_sinks(work_out, sample=sample)
    handoff_path = write_eval_handoff(
        work_out,
        sample=sample,
        client_keep=client_keep,
        sources=landed,
        sinks={
            "opengrc": sinks.get("opengrc", {}).get("dir") if isinstance(sinks.get("opengrc"), dict) else "",
            "probo": sinks.get("probo"),
            "posted": False,
            "demo": True,
            "sample": True,
            "riskready": "stay-out",
        },
    )
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    paying = honest_paying_day(read_paying_day(root), sample=sample)
    import_path = write_ciso_import_manifest(
        work_out,
        sample=sample,
        client_keep=client_keep,
        paying_day=paying,
        origin=origin,
    )
    summary_path = work_out / "summary.json"
    counts = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
    after = {str(path): _pack_tree_fingerprint(path) for path in _watched_pack_dirs(root, pack_in)}
    wrote_pack = before != after
    preexisting = sum(len(fp) for fp in before.values())
    ciso_files = listed_ciso_files(work_out)
    honest_client = bool(client_keep) and not sample
    stamp = {
        "status": "pass",
        "demo": True if sample else bool(counts.get("demo")),
        "sample": sample,
        "client_keep": honest_client,
        "paying_day": paying,
        "label": handoff.get("label"),
        "origin": origin,
        "pack_in_used": origin == "pack-in",
        "pack_in_written": wrote_pack,
        "pack_in_preexisting": preexisting,
        "in_dir": str(work_in),
        "out_dir": str(work_out),
        "handoff": str(handoff_path),
        "ciso_dir": str(work_out / "ciso-assistant"),
        "ciso_files": ciso_files,
        "ciso_import": str(import_path),
        "opengrc": sinks.get("opengrc", {}).get("dir") if isinstance(sinks.get("opengrc"), dict) else "",
        "probo": sinks.get("probo"),
        "sinks_posted": False,
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
        "note": (
            "SAMPLE keep-lab -> keep/work/out/ciso-assistant/*.csv. "
            "SAMPLE != client KEEP unless pack in/ has all four non-sample families."
        ),
    }
    as_client = sample_as_client_reason(landed, sample=sample, client_keep=honest_client)
    missing_ciso = missing_required_ciso(work_out)
    bad_headers = header_mismatch(work_out)
    shape_error = ""
    try:
        assert_risk_register_and_poam(work_out)
    except RegisterShapeError as exc:
        shape_error = str(exc)
    if missing:
        stamp["status"] = "fail"
        stamp["reason"] = f"KEEP families missing: {missing}"
    elif not landed:
        stamp["status"] = "fail"
        stamp["reason"] = "no KEEP files landed"
    elif missing_ciso:
        stamp["status"] = "fail"
        stamp["reason"] = f"CISO Assistant CSVs missing: {missing_ciso}"
    elif bad_headers:
        stamp["status"] = "fail"
        stamp["reason"] = f"CISO Assistant CSV headers mismatch: {bad_headers}"
    elif shape_error:
        stamp["status"] = "fail"
        stamp["reason"] = shape_error
    elif as_client:
        stamp["status"] = "fail"
        stamp["reason"] = as_client
    elif sample and paying != "FAIL":
        stamp["status"] = "fail"
        stamp["reason"] = "SAMPLE KEEP cannot stamp paying_day PASS"
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
        stamp["reason"] = "keep-lab wrote pack in/ this run"
    (work / "keep-lab.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    return stamp


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="keep lab",
        description=(
            "SAMPLE KEEP-chain → CISO Assistant CSVs + OpenGRC/Probo files. "
            "Forces DRY_RUN=1 CISO_PUSH=0. SAMPLE ≠ client. paying_day cannot PASS."
        ),
    )
    parser.add_argument(
        "--pack-in",
        dest="pack_in",
        help="KEEP file-drop dir (default: pack in/). Never written by keep-lab.",
    )
    parser.add_argument(
        "--work",
        dest="work",
        help="Isolated work dir (default: keep/work/). Not pack out/.",
    )
    args = parser.parse_args(argv)
    stamp = keep_lab(
        pack_in=Path(args.pack_in) if args.pack_in else None,
        work=Path(args.work) if args.work else None,
    )
    print(json.dumps(stamp, indent=2))
    counts = stamp.get("counts") if isinstance(stamp.get("counts"), dict) else {}
    print(
        f"KEEP_LAB={stamp['status']} sample={stamp['sample']} "
        f"client_keep={stamp['client_keep']} paying_day={stamp['paying_day']} "
        f"ciso_files={len(stamp.get('ciso_files') or [])} "
        f"handoff_findings={counts.get('handoff_findings')} "
        f"origin={stamp['origin']}"
    )
    if stamp.get("status") != "pass":
        return 1
    if stamp.get("sample"):
        print(
            "Estate is SAMPLE KEEP-chain fixtures. Not a client KEEP drop. "
            "Import keep/work/out/ciso-assistant/*.csv (see IMPORT.md)."
        )
    return 0
