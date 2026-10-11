#!/usr/bin/env python3
"""Runtime old_id->new_id migration map (prior-unit rules).

Build when prior POA&M holds per-finding IDs and the current fixstack emits
package parents / TLS posture / keep / retire dispositions.

Writes CSV into the *run output* folder - never a static lab map in the pack
repo. Stdlib only.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SEV_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "undefined": 0,
    "": 0,
}

UPGRADE_RE = re.compile(
    r"(?:Upgrade|upgrade|Patch|patch)\s+([A-Za-z0-9_./@+-]+)\s+to\b"
)
GRADE_IDS = frozenset(
    {
        "overall_grade",
        "overall-grade",
        "grade",
        "final_score",
        "final-score",
        "rating",
        "score",
    }
)
GRADE_NAME_RE = re.compile(r"^(overall\s*grade|final\s*score|grade|rating)$", re.I)
POSTURE_ID_RE = re.compile(
    r"^(cert[_-].*|cipher[_-].*|cipherlist[_-].*|fs|dns[_-]?caa.*)$",
    re.I,
)
POSTURE_NAME_RE = re.compile(
    r"^(cert\b|cipher\b|cipherlist\b|fs$|caa\b|dns\s*caa)",
    re.I,
)
FAIL_BLOB_RE = re.compile(
    r"(couldn.?t connect|could not connect|doesn.?t seem to be a tls|"
    r"not a tls/ssl|openssl handshake didn.?t succeed|"
    r"no server certificate could be retrieved|check failed)",
    re.I,
)
# prior-unit: secure_renego / fallback_scsv OUT of FAIL_IDS (keep inventory path).
FAIL_IDS = frozenset(
    {
        "optimal_proto",
        "optimal-proto",
        "scanproblem",
        "scan_problem",
        "scan-problem",
    }
)


def _norm_id(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (s or "").strip().lower()).strip("_")


def _strip_testssl_prefix(source_id: str) -> str:
    s = (source_id or "").strip()
    low = s.lower()
    if low.startswith("testssl:"):
        return s.split(":", 1)[1].strip()
    if low.startswith("testssl_"):
        return s[8:].lstrip("_-")
    return s


def classify_testssl(sid_raw: str, nm: str, desc: str) -> str:
    sid_raw = _strip_testssl_prefix(sid_raw)
    sid = _norm_id(sid_raw)
    blob = f"{sid_raw} {nm} {desc}"
    if sid in GRADE_IDS or GRADE_NAME_RE.match((nm or "").strip()):
        return "grade_drop"
    if sid in FAIL_IDS or FAIL_BLOB_RE.search(blob):
        return "failed_drop"
    if POSTURE_ID_RE.match(sid_raw or "") or POSTURE_ID_RE.match(sid) or POSTURE_NAME_RE.match(
        nm or ""
    ):
        return "posture_roll"
    if (nm or "").lower() in {"fs"} or sid in {"fs"}:
        return "posture_roll"
    return "keep_real"


def is_trivy(row: dict[str, str]) -> bool:
    return "trivy" in (row.get("detector_source") or "").lower()


def is_testssl(row: dict[str, str]) -> bool:
    if "testssl" in (row.get("detector_source") or "").lower():
        return True
    wsid = (row.get("weakness_source_id") or "").strip().lower()
    return wsid.startswith("testssl:") or wsid.startswith("testssl_")


def package_of(row: dict[str, str]) -> str:
    weakness = (row.get("weakness") or "").strip()
    if ":" in weakness:
        left = weakness.split(":", 1)[0].strip()
        if (
            left
            and len(left) <= 80
            and " " not in left
            and not left.lower().startswith("in the")
        ):
            return left
        if left.lower() in {"kernel", "linux", "openssl", "glibc", "curl"}:
            return left.lower() if left.lower() != "linux" else "kernel"
    action = row.get("recommended_action") or ""
    m = UPGRADE_RE.search(action)
    if m:
        return m.group(1)
    token = (weakness.split() or ["unparsed-package"])[0].strip(",.;:")
    if token.lower().startswith("in"):
        return "unparsed-package"
    return token[:80] or "unparsed-package"


def image_of(row: dict[str, str]) -> str:
    return (row.get("asset") or "").strip() or "unknown-image"


def stable_pkg_id(image: str, package: str) -> str:
    payload = f"trivy-pkg-v1|{image}|{package}".encode("utf-8")
    return "EGP-" + hashlib.sha256(payload).hexdigest()[:10].upper()


def host_from_asset(asset: str) -> str:
    a = (asset or "").strip().split(",")[0].strip()
    return a.split(":")[0].strip() if a else ""


def load_port_map(raw_in: Path, parsed_dir: Path) -> dict[str, str]:
    """host/ip -> port from raw testssl JSON (list, scanResult, or filename).

    prior-unit: also read plain testssl.json / *testssl*.json scanResult shapes and
    default TLS port 443 when omitted (demo fixtures often lack port).
    """
    ports: dict[str, str] = {}

    def _put(key: str, port: str) -> None:
        k = (key or "").strip()
        p = (port or "").strip()
        if not k or not p:
            return
        if k not in ports:
            ports[k] = p

    def _ingest_payload(data: object) -> None:
        if isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                ip = str(row.get("ip") or "").split("/")[0].strip()
                host = str(
                    row.get("targetHost") or row.get("host") or row.get("ip") or ""
                ).split("/")[0].split(":")[0].strip()
                port = str(row.get("port") or row.get("Port") or "").strip() or "443"
                if ip:
                    _put(ip, port)
                if host:
                    _put(host, port)
            return
        if isinstance(data, dict) and isinstance(data.get("scanResult"), list):
            for scan in data["scanResult"]:
                if not isinstance(scan, dict):
                    continue
                ip = str(scan.get("ip") or "").split("/")[0].strip()
                host = str(
                    scan.get("targetHost") or scan.get("host") or scan.get("ip") or ""
                ).split("/")[0].split(":")[0].strip()
                port = str(scan.get("port") or scan.get("Port") or "").strip() or "443"
                # row-level port override if present in section findings
                for key, val in scan.items():
                    if not isinstance(val, list):
                        continue
                    for row in val:
                        if isinstance(row, dict):
                            rp = str(row.get("port") or row.get("Port") or "").strip()
                            if rp:
                                port = rp
                                break
                if ip:
                    _put(ip, port)
                if host:
                    _put(host, port)
            return
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            _ingest_payload(data["findings"])

    # Prefer broad testssl*.json (includes testssl.json), not only testssl-*.json
    for base in (raw_in, parsed_dir):
        if not base.is_dir():
            continue
        for p in sorted(base.glob("testssl*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                data = None
            if data is not None:
                _ingest_payload(data)
            m = re.search(r"testssl-(\d+\.\d+\.\d+\.\d+)-(\d+)", p.name)
            if m:
                _put(m.group(1), m.group(2))
        for p in sorted(base.glob("testssl-*.parsed.json")):
            m = re.search(r"testssl-(\d+\.\d+\.\d+\.\d+)-(\d+)", p.name)
            if m:
                _put(m.group(1), m.group(2))
    return ports


def posture_egp(hostport: str) -> str:
    h = hashlib.sha256(f"tls-posture-v1|{hostport}".encode()).hexdigest()[:10].upper()
    return f"EGP-{h}"


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def build_migration_map(
    old_rows: list[dict[str, str]],
    new_rows: list[dict[str, str]],
    posture_rows: list[dict[str, str]] | None = None,
    ports: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Return map rows with old_id,new_id,disposition,reason (+ optional debug cols)."""
    posture_rows = posture_rows or []
    ports = ports or {}

    new_ids = {(r.get("poam_id") or "").strip() for r in new_rows}
    new_ids.discard("")

    # posture proposal id: prefer explicit column, else assets hostport hash
    posture_by_hp: dict[str, str] = {}
    posture_ids: set[str] = set()
    for r in posture_rows:
        hp = (r.get("assets") or r.get("asset") or "").strip()
        pid = (r.get("poam_id_proposal") or r.get("poam_id") or "").strip()
        if not pid and hp:
            pid = posture_egp(hp)
        if hp and pid:
            posture_by_hp[hp] = pid
            posture_ids.add(pid)

    map_rows: list[dict[str, str]] = []
    for r in old_rows:
        oid = (r.get("poam_id") or "").strip()
        if not oid:
            continue
        ds = (r.get("detector_source") or "").lower()
        reason = ""
        new_id = ""
        disposition = ""

        if is_trivy(r):
            image = image_of(r)
            package = package_of(r)
            new_id = stable_pkg_id(image, package)
            disposition = "rolled_into_pkg_parent"
            reason = f"trivy-pkg-v1|{image}|{package}"
        elif is_testssl(r):
            cat = classify_testssl(
                r.get("weakness_source_id") or "",
                r.get("weakness") or "",
                r.get("weakness_description") or "",
            )
            host = host_from_asset(r.get("asset") or "")
            port = ports.get(host, "")
            # if asset already host:port, prefer that
            asset = (r.get("asset") or "").strip()
            if ":" in asset.split(",")[0]:
                hp = asset.split(",")[0].strip()
            else:
                hp = f"{host}:{port}" if host and port else host
            if cat == "posture_roll":
                new_id = posture_by_hp.get(hp, "")
                if not new_id and hp:
                    # fall back to deterministic hash (matches testssl_fix scheme)
                    new_id = posture_egp(hp if ":" in hp else f"{hp}:{port}" if port else hp)
                    # try with host:port variants
                    if not posture_by_hp:
                        new_id = posture_egp(hp)
                    else:
                        # try alternate keys
                        alts = [hp]
                        if host and port:
                            alts.append(f"{host}:{port}")
                        if host:
                            alts.append(host)
                        for a in alts:
                            if a in posture_by_hp:
                                new_id = posture_by_hp[a]
                                hp = a
                                break
                        else:
                            new_id = posture_egp(hp if ":" in (hp or "") else (f"{host}:{port}" if host and port else hp))
                disposition = "rolled_into_tls_posture"
                reason = f"testssl posture -> {hp or 'unknown-host'}"
            elif cat in {"grade_drop", "failed_drop"}:
                new_id = ""
                disposition = "retired_dropped"
                reason = f"testssl {cat}"
            else:
                new_id = oid if oid in new_ids else oid
                disposition = "kept_same_id"
                reason = "testssl keep_real (host:port asset fix only)"
                if oid not in new_ids:
                    ref = r.get("finding_ref_id") or ""
                    hit = next(
                        (nr for nr in new_rows if (nr.get("finding_ref_id") or "") == ref),
                        None,
                    )
                    if hit:
                        new_id = (hit.get("poam_id") or "").strip()
                        disposition = "kept_same_id"
                        if new_id != oid:
                            reason += f"; ref match -> {new_id}"
                    else:
                        disposition = "retired_dropped"
                        new_id = ""
                        reason = "testssl keep_real but id missing in outA"
        else:
            if oid in new_ids:
                new_id = oid
                disposition = "kept_same_id"
                reason = f"non-trivy passthrough ({ds or 'unknown'})"
            else:
                new_id = ""
                disposition = "retired_dropped"
                reason = f"non-trivy id missing in outA ({ds or 'unknown'})"

        map_rows.append(
            {
                "old_id": oid,
                "new_id": new_id,
                "disposition": disposition,
                "reason": reason,
            }
        )
    return map_rows


def write_migration_map(path: Path, rows: list[dict[str, str]], slim: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["old_id", "new_id", "disposition", "reason"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})


def build_from_paths(
    old_poam: Path,
    new_poam: Path,
    out_csv: Path,
    posture_csv: Path | None = None,
    raw_in: Path | None = None,
    raw_parsed: Path | None = None,
) -> dict:
    old_rows = _read_csv(old_poam)
    new_rows = _read_csv(new_poam)
    posture_rows = _read_csv(posture_csv) if posture_csv and posture_csv.is_file() else []
    ports = load_port_map(raw_in, raw_parsed)
    rows = build_migration_map(old_rows, new_rows, posture_rows, ports)
    write_migration_map(out_csv, rows)
    counts = Counter(r["disposition"] for r in rows)
    return {
        "map_rows": len(rows),
        "dispositions": dict(counts),
        "out_csv": str(out_csv),
        "old_poam": str(old_poam),
        "new_poam": str(new_poam),
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 3:
        print(
            "usage: build_migration_map.py OLD_POAM.csv NEW_POAM.csv OUT.csv "
            "[POSTURE.csv] [RAW_IN_DIR] [RAW_PARSED_DIR]",
            file=sys.stderr,
        )
        return 2
    old_poam = Path(argv[0])
    new_poam = Path(argv[1])
    out_csv = Path(argv[2])
    posture = Path(argv[3]) if len(argv) > 3 and argv[3] else None
    raw_in = Path(argv[4]) if len(argv) > 4 and argv[4] else None
    raw_parsed = Path(argv[5]) if len(argv) > 5 and argv[5] else None
    info = build_from_paths(old_poam, new_poam, out_csv, posture, raw_in, raw_parsed)
    print(json.dumps(info, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
