#!/usr/bin/env python3
"""prior-unit pack-local fix stack: PQ-2 testssl cleanup + PQ-1 pkg rollup + migration map.

Runs on pack out/ after prove_ciso. Stdlib only. Does not modify the pack source tree.
Order A (prior-unit): testssl_fix then rollup.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from fixstack.build_migration_map import (  # type: ignore
        build_migration_map,
        load_port_map,
        write_migration_map,
    )
except ImportError:  # package layout fallback
    from scripts.fixstack.build_migration_map import (  # type: ignore
        build_migration_map,
        load_port_map,
        write_migration_map,
    )


def _sh(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, check=False)
    if r.returncode != 0:
        raise SystemExit(r.returncode)


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fields = list(reader.fieldnames or [])
        return fields, list(reader)


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})


def _load_map(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _earliest_iso(values: list[str]) -> str:
    clean = [v for v in values if v and str(v).lower() not in {"not recorded", "n/a"}]
    return sorted(clean)[0] if clean else ""


def _excluded_reason_for_disp(disp: str, reason: str, new_id: str) -> str:
    """Explicit excluded_reason for every retired old ID (no silent skip)."""
    d = (disp or "").strip()
    r = (reason or "").strip().lower()
    if new_id:
        return f"rolled_into:{new_id}"
    if "grade" in d or "grade" in r:
        return "retired_grade_row"
    if "failed" in d or "failed" in r or "scan" in r:
        return "coverage_gap_failed_connect"
    if d == "retired_dropped" or not new_id:
        return "retired_dropped"
    return d or "retired_dropped"


def _derive_parent_status(kids: list[dict]) -> tuple[str, str]:
    """Parent status from children; record derivation (no silent open-wins)."""
    statuses = [str(k.get("status") or "open").strip().lower() or "open" for k in kids]
    if not statuses:
        return "open", "empty_children_default_open"
    if any(s in {"open", "reopened"} for s in statuses):
        return "open", "child_open_or_reopened"
    if any(s == "pending_verification" for s in statuses):
        return "pending_verification", "child_pending_verification"
    if all(s == "closed" for s in statuses):
        return "closed", "all_children_closed"
    # mixed non-open (e.g. closed + accepted) — prefer first non-empty
    return statuses[0], f"first_child_status:{statuses[0]}"


def _merge_earliest_fields(base: dict, donors: list[dict]) -> None:
    """Keep earliest first_seen / original_detection_date; never clobber with later."""
    firsts = [str(k.get("first_seen") or "") for k in donors if k.get("first_seen")]
    if base.get("first_seen"):
        firsts.append(str(base.get("first_seen")))
    earliest_fs = _earliest_iso(firsts)
    if earliest_fs:
        base["first_seen"] = earliest_fs
    odds = [
        str(k.get("original_detection_date") or "")
        for k in donors
        if k.get("original_detection_date")
        and str(k.get("original_detection_date")).lower() not in {"not recorded", "n/a", ""}
    ]
    if base.get("original_detection_date") and str(base.get("original_detection_date")).lower() not in {
        "not recorded",
        "n/a",
        "",
    }:
        odds.append(str(base.get("original_detection_date")))
    earliest_odd = _earliest_iso(odds)
    if earliest_odd:
        base["original_detection_date"] = earliest_odd


def apply_migration_to_ledger(
    ledger_path: Path,
    map_rows: list[dict[str, str]],
    new_poam_ids: set[str],
    report: dict,
) -> None:
    """Rewrite prior ledger items via old_id->new_id map; merge carry onto parents.

    prior-unit rules:
    - every retired old ID is carried closed/excluded with explicit excluded_reason
    - parent status derives from children; derivation recorded
    - earliest first_seen / original_detection_date wins (run2 must not clobber)
    - re-sign payload_sha256 after rewrite (never leave unsigned)

    prior-unit:
    - closed/fp_migrations are idempotent: an old ID already closed/excluded is
      never appended again (re-migration / --prior-out safe)
    """
    if not ledger_path.is_file():
        report["ledger"] = "missing"
        return
    doc = json.loads(ledger_path.read_text(encoding="utf-8"))
    items = doc.get("items") if isinstance(doc.get("items"), dict) else {}
    closed = list(doc.get("closed") or []) if isinstance(doc.get("closed"), list) else []
    closed_pids: set[str] = set()
    closed_fps: set[str] = set()
    for c in closed:
        if not isinstance(c, dict):
            continue
        pid = str(c.get("poam_id") or "").strip()
        fp = str(c.get("fp") or "").strip()
        if pid:
            closed_pids.add(pid)
        if fp:
            closed_fps.add(fp)

    def _append_closed(item: dict) -> None:
        pid = str(item.get("poam_id") or "").strip()
        fp = str(item.get("fp") or "").strip()
        if pid and pid in closed_pids:
            return
        if fp and fp in closed_fps and not pid:
            return
        closed.append(item)
        if pid:
            closed_pids.add(pid)
        if fp:
            closed_fps.add(fp)

    by_old: dict[str, dict] = {}
    by_fp: dict[str, dict] = {}
    for fp, item in items.items():
        if not isinstance(item, dict):
            continue
        by_fp[str(fp)] = item
        pid = str(item.get("poam_id") or "").strip()
        if pid:
            by_old.setdefault(pid, item)

    children_by_new: dict[str, list[dict]] = defaultdict(list)
    kept_items: dict[str, dict] = {}
    retired_closed = 0
    kept = 0
    rolled = 0
    skipped_already_closed = 0
    mapped_old_ids: set[str] = set()
    id_migration_map: list[dict[str, str]] = []

    for row in map_rows:
        old_id = str(row.get("old_id") or "").strip()
        new_id = str(row.get("new_id") or "").strip()
        disp = str(row.get("disposition") or "").strip()
        reason = str(row.get("reason") or "").strip()
        if not old_id:
            continue
        mapped_old_ids.add(old_id)
        id_migration_map.append(
            {
                "old_id": old_id,
                "new_id": new_id,
                "disposition": disp,
                "reason": reason,
            }
        )
        if old_id in closed_pids:
            skipped_already_closed += 1
            # drop live twin if fresh prove re-minted the old ID
            twin = by_old.get(old_id)
            if twin is not None:
                tfp = str(twin.get("fp") or "")
                if tfp and tfp in items:
                    # leave closed as-is; strip twin from live items path below via mapped_old_ids
                    pass
            continue
        child = by_old.get(old_id)
        if child is None:
            continue
        if disp == "retired_dropped" or not new_id:
            retired_closed += 1
            closed_item = dict(child)
            closed_item["status"] = "closed"
            closed_item["excluded_reason"] = _excluded_reason_for_disp(disp, reason, new_id)
            closed_item["migration_disposition"] = disp or "retired_dropped"
            if reason:
                closed_item["migration_reason"] = reason
            _append_closed(closed_item)
            continue
        if disp == "kept_same_id":
            kept += 1
            fp = str(child.get("fp") or "").strip()
            if not fp:
                for ifp, it in items.items():
                    if isinstance(it, dict) and str(it.get("poam_id") or "") == old_id:
                        fp = str(ifp)
                        child = it
                        break
            if fp:
                kept_items[fp] = dict(child)
                kept_items[fp]["poam_id"] = new_id or old_id
                kept_items[fp]["excluded_reason"] = ""
            continue
        rolled += 1
        kid = dict(child)
        kid["excluded_reason"] = f"rolled_into:{new_id}"
        kid["migration_disposition"] = disp
        children_by_new[new_id].append(kid)

    new_items: dict[str, dict] = dict(kept_items)
    migrations = list(doc.get("fp_migrations") or [])
    mig_keys: set[tuple[str, str, str]] = set()
    for m in migrations:
        if isinstance(m, dict):
            mig_keys.add(
                (
                    str(m.get("from") or ""),
                    str(m.get("to") or ""),
                    str(m.get("poam_id") or ""),
                )
            )

    def _append_mig(row: dict) -> None:
        key = (str(row.get("from") or ""), str(row.get("to") or ""), str(row.get("poam_id") or ""))
        if key in mig_keys:
            return
        mig_keys.add(key)
        migrations.append(row)

    for new_id, kids in children_by_new.items():
        parent_fp = hashlib.sha256(f"mig-parent|{new_id}".encode()).hexdigest()
        existing = None
        for it in new_items.values():
            if str(it.get("poam_id") or "") == new_id:
                existing = it
                parent_fp = str(it.get("fp") or parent_fp)
                break
        if existing is None:
            for it in by_fp.values():
                if str(it.get("poam_id") or "") == new_id:
                    existing = dict(it)
                    parent_fp = str(it.get("fp") or parent_fp)
                    break
        base = dict(existing) if existing is not None else dict(kids[0])
        donors = kids + ([existing] if existing is not None else [])
        _merge_earliest_fields(base, donors)
        status, derivation = _derive_parent_status(kids if kids else donors)
        if existing is not None:
            prior_status = str(existing.get("status") or "open").strip().lower()
            if status == "open" or prior_status in {"", "open"}:
                base["status"] = status
            elif status == "closed" and prior_status == "closed":
                base["status"] = "closed"
            else:
                base["status"] = status
        else:
            base["status"] = status
        base["status_derivation"] = derivation
        base["poam_id"] = new_id
        base["excluded_reason"] = ""
        prior_ids = [str(k.get("poam_id") or "") for k in kids if k.get("poam_id")]
        if prior_ids and prior_ids[0] != new_id:
            base["prior_poam_id"] = prior_ids[0]
        base["rolled_into"] = new_id
        base["fp"] = parent_fp
        base["child_count"] = len(kids)
        new_items[parent_fp] = base
        for k in kids:
            old_fp = str(k.get("fp") or "")
            old_pid = str(k.get("poam_id") or "")
            closed_child = dict(k)
            closed_child["status"] = "closed"
            closed_child["excluded_reason"] = f"rolled_into:{new_id}"
            _append_closed(closed_child)
            if old_fp and old_pid != new_id:
                _append_mig(
                    {
                        "from": old_fp,
                        "to": parent_fp,
                        "poam_id": new_id,
                        "original_detection_date": base.get("original_detection_date") or "",
                        "reason": f"prior-unit-migration-map:{old_pid}->{new_id}",
                        "excluded_reason": f"rolled_into:{new_id}",
                    }
                )

    existing_pids = {str(x.get("poam_id") or "") for x in new_items.values()}
    for fp, item in items.items():
        if not isinstance(item, dict):
            continue
        if fp in new_items:
            _merge_earliest_fields(new_items[fp], [item, new_items[fp]])
            continue
        pid = str(item.get("poam_id") or "").strip()
        if pid and pid in mapped_old_ids:
            continue
        if pid and pid in new_poam_ids and pid not in existing_pids:
            new_items[fp] = dict(item)
            existing_pids.add(pid)
        elif pid and pid not in mapped_old_ids and pid in new_poam_ids and pid not in existing_pids:
            new_items[fp] = dict(item)
            existing_pids.add(pid)

    doc["items"] = new_items
    doc["closed"] = closed
    doc["fp_migrations"] = migrations
    doc["id_migration_map"] = id_migration_map
    doc["_id_migration_applied"] = True
    doc["warnings"] = [
        w
        for w in (doc.get("warnings") or [])
        if w
        not in {
            "LEDGER_LOST",
            "LEDGER_LOST (first run: no prior ledger)",
            "first run: no prior ledger",
        }
        and not str(w).startswith("new ledger created")
    ]
    try:
        sys.path.insert(0, str(ROOT))
        from shared.poam_ledger import payload_sha256  # type: ignore

        if doc.get("sha256"):
            doc["prev_sha256"] = doc.get("sha256")
        doc["sha256"] = payload_sha256(doc)
    except Exception as exc:  # noqa: BLE001
        report["resign_error"] = str(exc)
        if doc.get("sha256"):
            doc["prev_sha256"] = doc.get("sha256")
        body = {
            "items": doc.get("items") or {},
            "closed": doc.get("closed") or [],
            "events": doc.get("events") or [],
            "fp_migrations": doc.get("fp_migrations") or [],
        }
        blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        doc["sha256"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    ledger_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["ledger"] = {
        "path": str(ledger_path),
        "parents": len(new_items),
        "kept_items_fps": len(kept_items),
        "retired_closed_seen": retired_closed,
        "kept_same_id_seen": kept,
        "rolled_seen": rolled,
        "skipped_already_closed": skipped_already_closed,
        "map_rows": len(map_rows),
        "sha256": doc.get("sha256"),
        "closed_count": len(closed),
    }



def main() -> int:
    if len(sys.argv) < 2:
        print("usage: fixstack_apply.py WORK_DIR", file=sys.stderr)
        return 2
    work = Path(sys.argv[1]).resolve()
    out = work / "out"
    poam_path = out / "poam" / "poam.csv"
    vulns_path = out / "ciso-assistant" / "vulnerabilities.csv"
    if not poam_path.is_file():
        print(f"fixstack_apply: missing {poam_path}", file=sys.stderr)
        return 2

    staging = work / "fixstack_staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    in_dir = staging / "in"
    mid = staging / "mid"
    final = staging / "final"
    in_dir.mkdir()
    mid.mkdir()
    final.mkdir()

    # Stage inputs like prior-unit
    shutil.copy2(poam_path, in_dir / "poam.csv")
    if vulns_path.is_file():
        shutil.copy2(vulns_path, in_dir / "vulnerabilities.csv")
    # raw testssl helpers if present under work/in (shape: raw/ + raw_in/ or nested)
    raw_parsed = in_dir / "raw"
    raw_in = in_dir / "raw_in"
    raw_parsed.mkdir(exist_ok=True)
    raw_in.mkdir(exist_ok=True)
    raw_src = work / "in"
    for p in raw_src.rglob("testssl*"):
        if not p.is_file():
            continue
        name = p.name
        try:
            if name.endswith(".parsed.json"):
                shutil.copy2(p, raw_parsed / name)
            elif name.endswith(".json"):
                shutil.copy2(p, raw_in / name)
                if ".parsed." in name:
                    shutil.copy2(p, raw_parsed / name)
        except OSError:
            pass
    # optional extra raw donors via env (lab-local only; never hardcoded paths)
    extra = (os.environ.get("FIXSTACK_TESTSSL_DONOR") or "").strip()
    if extra:
        donor = Path(extra)
        if donor.is_dir():
            d_raw = donor / "raw"
            d_in = donor / "raw_in"
            if d_raw.is_dir():
                for p in d_raw.glob("testssl*"):
                    dest = raw_parsed / p.name
                    if not dest.exists():
                        shutil.copy2(p, dest)
            if d_in.is_dir():
                for p in d_in.glob("testssl*"):
                    dest = raw_in / p.name
                    if not dest.exists():
                        shutil.copy2(p, dest)

    testssl = ROOT / "scripts" / "fixstack" / "testssl_fix.py"
    rollup = ROOT / "scripts" / "fixstack" / "rollup.py"
    if not testssl.is_file() or not rollup.is_file():
        print("fixstack_apply: missing fixstack scripts under scripts/fixstack/", file=sys.stderr)
        return 2

    # PQ-2
    _sh([PY, str(testssl), str(in_dir), str(mid)])
    # mid expected files from prior-unit script interface - adapt if needed
    # prior-unit testssl_fix takes in_dir out_dir
    mid_poam = mid / "poam_fixed.csv"
    if not mid_poam.is_file():
        # some versions write poam.csv
        alt = mid / "poam.csv"
        if alt.is_file():
            mid_poam = alt
        else:
            print(f"fixstack_apply: PQ-2 missing poam out in {mid}", file=sys.stderr)
            print("contents:", list(mid.iterdir()), file=sys.stderr)
            return 2

    # PQ-1
    _sh([PY, str(rollup), str(mid_poam), str(final)])
    final_poam = final / "poam_rolled.csv"
    if not final_poam.is_file():
        alt = final / "poam.csv"
        if alt.is_file():
            final_poam = alt
        else:
            print(f"fixstack_apply: PQ-1 missing poam out in {final}", file=sys.stderr)
            return 2

    fields, rows = _read_csv(final_poam)
    # prior-unit: deterministic row order so run1/run2 poam.csv are byte-identical when IDs match
    rows = sorted(rows, key=lambda r: (str(r.get("poam_id") or ""), str(r.get("asset") or ""), str(r.get("weakness") or "")))
    # Backup raw prove POA&M
    raw_bak = out / "poam" / "poam.pre-fixstack.csv"
    if not raw_bak.exists():
        shutil.copy2(poam_path, raw_bak)
    _write_csv(poam_path, fields, rows)

    # Copy vulns if PQ-2 produced them
    mid_vuln = mid / "vulnerabilities_fixed.csv"
    if mid_vuln.is_file() and vulns_path.is_file():
        shutil.copy2(vulns_path, out / "ciso-assistant" / "vulnerabilities.pre-fixstack.csv")
        shutil.copy2(mid_vuln, vulns_path)

    # TLS posture findings sidecar
    posture = mid / "tls_posture_findings.csv"
    if posture.is_file():
        shutil.copy2(posture, out / "poam" / "tls_posture_findings.csv")

    new_ids = {(r.get("poam_id") or "").strip() for r in rows if (r.get("poam_id") or "").strip()}

    # Runtime migration map (prior-unit rules): prior per-finding IDs -> current parents.
    # Always write into run out/ - never ship a static lab map in the pack repo.
    old_fields, old_rows = _read_csv(raw_bak if raw_bak.is_file() else poam_path)
    posture_path = out / "poam" / "tls_posture_findings.csv"
    if not posture_path.is_file() and posture.is_file():
        posture_path = posture
    posture_rows: list[dict[str, str]] = []
    if posture_path.is_file():
        _, posture_rows = _read_csv(posture_path)
    # also accept mid name from PQ-2
    mid_posture = mid / "tls_posture_findings.csv"
    if not posture_rows and mid_posture.is_file():
        _, posture_rows = _read_csv(mid_posture)
    # prior-unit naming
    mid_posture2 = mid / "testssl_tls_posture_findings.csv"
    if not posture_rows and mid_posture2.is_file():
        _, posture_rows = _read_csv(mid_posture2)

    ports = load_port_map(raw_in, raw_parsed)
    # also scan work/in for nested testssl names
    if not ports:
        ports = load_port_map(work / "in", work / "in")

    map_rows = build_migration_map(old_rows, rows, posture_rows, ports)
    map_path = out / "poam" / "poam-id-migration.csv"
    write_migration_map(map_path, map_rows)

    report: dict = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "work": str(work),
        "poam_rows": len(rows),
        "poam_ids": len(new_ids),
        "map_path": str(map_path),
        "map_rows": len(map_rows),
        "map_source": "runtime:build_migration_map",
    }
    ledger_path = out / "poam" / "poam-ledger.json"
    apply_migration_to_ledger(ledger_path, map_rows, new_ids, report)

    # prior-unit: regenerate FedRAMP twin from post-fixstack ledger + plan so Open count
    # matches poam.csv (pre-fixstack twin left 5441 rows).
    try:
        sys.path.insert(0, str(ROOT))
        from shared.poam_fedramp import plan_by_poam_id, write_fedramp_poam  # type: ignore

        if ledger_path.is_file():
            led = json.loads(ledger_path.read_text(encoding="utf-8"))
            header = list(fields)
            plan_rows = [[r.get(h, "") for h in header] for r in rows]
            plan = plan_by_poam_id(header, plan_rows)
            paths = write_fedramp_poam(out / "poam", led, plan_by_id=plan)
            # mitigate+accept gap (CR7 B1): plan IDs vs open FedRAMP
            open_path = paths.get("open")
            fed_open = 0
            if open_path and Path(open_path).is_file():
                with Path(open_path).open(encoding="utf-8", newline="") as fh:
                    fed_open = max(0, sum(1 for _ in csv.DictReader(fh)))
            report["fedramp"] = {
                "open_rows": fed_open,
                "poam_rows": len(rows),
                "mitigate_accept_gap": abs(fed_open - len(rows)),
                "note": "Open tab restricted to post-fixstack poam.csv plan IDs",
            }
    except Exception as exc:  # noqa: BLE001
        report["fedramp_error"] = str(exc)

    # Intentional retired_dropped from map
    retired = [
        r
        for r in map_rows
        if str(r.get("disposition") or "") == "retired_dropped"
        or not str(r.get("new_id") or "").strip()
    ]
    report["retired_dropped_intentional"] = len(retired)
    report["retired_dropped_ids"] = [str(r.get("old_id") or "") for r in retired[:20]]

    # LEDGER_LOST unexplained: old ids whose disposition is unknown
    known = 0
    unknown = 0
    for r in map_rows:
        d = str(r.get("disposition") or "").strip()
        if d in {
            "rolled_into_pkg_parent",
            "rolled_into_tls_posture",
            "kept_same_id",
            "retired_dropped",
        }:
            known += 1
        else:
            unknown += 1
    report["ledger_lost"] = {
        "with_map_unexplained": unknown,
        "with_map_known": known,
        "intentional_retired_dropped": len(retired),
    }

    # Sample carry examples: up to 5 parent IDs present on the new POA&M (no hard-coded lab IDs)
    examples = []
    if ledger_path.is_file():
        doc = json.loads(ledger_path.read_text(encoding="utf-8"))
        by_pid = {
            str(it.get("poam_id") or ""): it
            for it in (doc.get("items") or {}).values()
            if isinstance(it, dict) and str(it.get("poam_id") or "").strip()
        }
        sample_pids = sorted(new_ids)[:5]
        for pid in sample_pids:
            it = by_pid.get(pid)
            if not it:
                examples.append({"poam_id": pid, "found": False})
            else:
                examples.append(
                    {
                        "poam_id": pid,
                        "found": True,
                        "first_seen": it.get("first_seen"),
                        "status": it.get("status"),
                        "original_detection_date": it.get("original_detection_date"),
                        "prior_poam_id": it.get("prior_poam_id"),
                    }
                )
    report["carry_examples"] = examples

    # Keep prove-ciso honesty: stamp counts.poam must match on-disk poam rows
    stamp_path = work / "prove-ciso.json"
    if stamp_path.is_file():
        try:
            stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
            if isinstance(stamp, dict):
                counts = stamp.get("counts") if isinstance(stamp.get("counts"), dict) else {}
                report["prove_poam_before"] = counts.get("poam")
                counts["poam"] = len(rows)
                counts["poam_fixstack"] = len(rows)
                stamp["counts"] = counts
                stamp["fixstack"] = {
                    "applied": True,
                    "order": "PQ-2 testssl then PQ-1 rollup",
                    "poam_rows": len(rows),
                    "migration_map_rows": len(map_rows),
                }
                stamp_path.write_text(
                    json.dumps(stamp, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                report["prove_poam_after"] = len(rows)
        except (json.JSONDecodeError, OSError) as exc:
            report["prove_stamp_error"] = str(exc)

    rep_path = out / "poam" / "fixstack_report.json"
    rep_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"fixstack_apply: poam_rows={len(rows)} ids={len(new_ids)} report={rep_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
