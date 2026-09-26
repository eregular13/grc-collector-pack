#!/usr/bin/env python3
"""Local operator console for grc-collector-pack.

Binds 127.0.0.1 only. Reads out/. Can refresh collectors on this host.
Never proxies or POSTs /api/risks. Not an eleventh Compose service.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import traceback
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"
COLLECTORS = [
    "cloud_prowler.py",
    "inventory_nmap.py",
    "vuln_scan.py",
    "host_wazuh.py",
    "identity_ad.py",
    "easm.py",
    "k8s_kubescape.py",
    "code_secrets.py",
    "saas_idp.py",
    "dns_email.py",
    "grc_loader.py",
]


# Sibling prove outs: PROVE_WORK_ROOT or parent of OUT_DIR / common layouts.
COMMON_PROVE_ROOTS = (
    "prove-work",
    "lab-estate/out",
    "lab-estate",
    "prove/work",
)
MAX_RUNS = 24


def out_dir() -> Path:
    raw = os.environ.get("OUT_DIR")
    if raw:
        return Path(raw)
    hinted = last_lab_prove_out()
    if hinted:
        return hinted
    return ROOT / "out"


def _read_last_lab_prove_marker(marker: Path) -> Path | None:
    if not marker.is_file():
        return None
    raw = marker.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    cand = Path(text)
    if is_prove_out(cand):
        return cand
    return None


def last_lab_prove_out() -> Path | None:
    """LAST_LAB_PROVE / LAB_ESTATE_OUT / PROVE_WORK_ROOT stamp. Env only.

    Used when OUT_DIR is unset so python -m product can open a lab-prove
    stamp without a hand-typed OUT_DIR. Never invents client=true.
    """
    ordered: list[Path] = []
    for key in ("LAST_LAB_PROVE", "LAB_ESTATE_OUT", "PROVE_WORK_ROOT"):
        raw = (os.environ.get(key) or "").strip()
        if raw:
            ordered.append(Path(raw))
    seen: set[Path] = set()
    for cand in ordered:
        try:
            key = cand.resolve()
        except OSError:
            key = cand
        if key in seen:
            continue
        seen.add(key)
        if cand.is_file():
            marked = _read_last_lab_prove_marker(cand)
            if marked:
                return marked
            continue
        if not cand.is_dir():
            continue
        if is_prove_out(cand):
            return cand
        marked = _read_last_lab_prove_marker(cand / "LAST_LAB_PROVE.txt")
        if marked:
            return marked
        children: list[Path] = []
        try:
            for child in cand.iterdir():
                if not child.is_dir() or not child.name.startswith("lab-prove-"):
                    continue
                if is_prove_out(child):
                    children.append(child)
                nested = child / "out"
                if is_prove_out(nested):
                    children.append(nested)
        except OSError:
            continue
        if children:
            children.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            return children[0]
    return None


def is_prove_out(path: Path) -> bool:
    """True when path looks like a prove out/ (summary.json and/or LAB.txt)."""
    dest = Path(path)
    if not dest.is_dir():
        return False
    return (dest / "summary.json").is_file() or (dest / "LAB.txt").is_file()


def stamp_name(out: Path) -> str:
    dest = Path(out)
    if dest.name == "out":
        parent = dest.parent
        try:
            if parent.resolve() == ROOT.resolve():
                return "out"
        except OSError:
            pass
        return parent.name or "out"
    return dest.name or "out"


def bind_host() -> str:
    return os.environ.get("GRC_PRODUCT_HOST", "127.0.0.1")


def bind_port() -> int:
    return int(os.environ.get("GRC_PRODUCT_PORT", "18765"))


def assert_loopback_host(host: str) -> str:
    raw = (host or "").strip()
    normalized = raw.lower().strip("[]")
    if normalized not in ALLOWED_HOSTS:
        sys.stderr.write("GRC_PRODUCT_HOST must be 127.0.0.1, localhost, or ::1\n")
        raise SystemExit(2)
    return raw


def _read_csv(path: Path, delim: str = ",") -> list[dict]:
    if not path.exists():
        return []
    from shared.estate_pages import csv_rows_skip_comments

    return csv_rows_skip_comments(path, delimiter=delim)


def _read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


CLOSED_POAM_STATUSES = frozenset(
    {"closed", "complete", "completed", "remediated", "resolved", "done"}
)
POAM_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _cell_blank(value) -> bool:
    return not str(value or "").strip()


def _poam_severity(row: dict) -> str:
    return str(row.get("severity") or "").strip().lower()


def _poam_is_open(row: dict) -> bool:
    status = str(row.get("status") or "").strip().lower()
    return status not in CLOSED_POAM_STATUSES


def annotate_poam_row(row: dict) -> dict:
    """Flags empty owner/due so the console can highlight rows for a human."""
    out = dict(row)
    out["blank_owner"] = _cell_blank(row.get("owner"))
    out["blank_due"] = _cell_blank(row.get("due"))
    out["open"] = _poam_is_open(row)
    return out


def sort_poam_rows(rows: list[dict]) -> list[dict]:
    """Critical / high first, then medium / low. Stable on weakness."""
    return sorted(
        rows,
        key=lambda row: (
            POAM_SEV_ORDER.get(_poam_severity(row), 9),
            str(row.get("weakness") or ""),
        ),
    )


def poam_rows(out: Path | None = None) -> list[dict]:
    dest = out if out is not None else out_dir()
    raw = _read_csv(dest / "poam" / "poam.csv")
    return sort_poam_rows([annotate_poam_row(row) for row in raw])


def poam_summary(out: Path | None = None, rows: list[dict] | None = None) -> dict:
    """Open + severity + blank owner/due rollup from poam.csv.

    Owner/due stay blank by design (human / CISO import). Count them; do not fill.
    """
    items = rows if rows is not None else poam_rows(out)
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    open_n = 0
    blank_owner = 0
    blank_due = 0
    for row in items:
        key = _poam_severity(row)
        if key in sev:
            sev[key] += 1
        if row.get("open") if "open" in row else _poam_is_open(row):
            open_n += 1
        if row.get("blank_owner") if "blank_owner" in row else _cell_blank(row.get("owner")):
            blank_owner += 1
        if row.get("blank_due") if "blank_due" in row else _cell_blank(row.get("due")):
            blank_due += 1
    return {
        "total": len(items),
        "open": open_n,
        "critical": sev["critical"],
        "high": sev["high"],
        "medium": sev["medium"],
        "low": sev["low"],
        "severity": sev,
        "blank_owner": blank_owner,
        "blank_due": blank_due,
        "owner_due_blank_for_human": True,
    }


FRAMEWORK_FAMILIES = (
    ("nist_800_53", ("nist80053_",)),
    ("cisa_cpg", ("cpg_", "cisa_")),
    ("nist_csf", ("csf_", "nist_")),
    ("cis", ("cis_",)),
    ("iso", ("iso_", "iso-270", "iso270")),
)
FRAMEWORK_FAMILY_ORDER = tuple(name for name, _ in FRAMEWORK_FAMILIES)
CSF_FUNCTION_TOKEN = {
    "govern": "csf_govern",
    "identify": "csf_ID",
    "protect": "csf_PR",
    "detect": "csf_DE",
    "respond": "csf_RS",
    "recover": "csf_RC",
}


def split_ref_tokens(value) -> list[str]:
    """Split framework_refs / filtering_labels on comma, semicolon, pipe, space."""
    raw = str(value or "").strip().strip('"').strip("'")
    if not raw:
        return []
    tokens: list[str] = []
    buf = []
    for ch in raw:
        if ch in ",;|/ \t\n":
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return [tok.strip() for tok in tokens if tok.strip()]


def classify_framework_token(token: str) -> str | None:
    """NIST/CIS/ISO-ish family for a wizard-safe stamp. None = ignore."""
    key = str(token or "").strip().lower()
    if not key or ":" in key:
        return None
    mapped = CSF_FUNCTION_TOKEN.get(key)
    if mapped:
        key = mapped.lower()
    # cis-cat / ciscat are sensor labels, not CIS control ids (cis_5_1 / cis-1.x).
    if key.startswith("cis-") and len(key) > 4 and key[4].isdigit():
        return "cis"
    for family, prefixes in FRAMEWORK_FAMILIES:
        if any(key.startswith(prefix) for prefix in prefixes):
            return family
    return None


def normalize_framework_token(token: str) -> str:
    raw = str(token or "").strip()
    mapped = CSF_FUNCTION_TOKEN.get(raw.lower())
    return mapped if mapped else raw


def _empty_family() -> dict:
    return {"rows": 0, "hits": 0, "tokens": {}}


def _ingest_framework_source(
    rows: list[dict],
    columns: tuple[str, ...],
    source: str,
    families: dict[str, dict],
    tokens: dict[str, dict],
) -> int:
    """Count framework-ish tokens in the given columns. Returns rows that hit."""
    hit_rows = 0
    for row in rows:
        seen_families: set[str] = set()
        seen_tokens: set[str] = set()
        for col in columns:
            for raw in split_ref_tokens(row.get(col)):
                family = classify_framework_token(raw)
                if family is None:
                    continue
                token = normalize_framework_token(raw)
                key = token.lower()
                if key in seen_tokens:
                    continue
                seen_tokens.add(key)
                seen_families.add(family)
                bucket = tokens.setdefault(
                    key,
                    {
                        "token": token,
                        "family": family,
                        "poam": 0,
                        "findings": 0,
                        "controls": 0,
                        "total": 0,
                    },
                )
                bucket[source] = int(bucket.get(source) or 0) + 1
                bucket["total"] = int(bucket.get("total") or 0) + 1
                fam = families[family]
                fam["tokens"][token] = int(fam["tokens"].get(token) or 0) + 1
                fam["hits"] = int(fam["hits"] or 0) + 1
        if seen_families:
            hit_rows += 1
            for family in seen_families:
                families[family]["rows"] = int(families[family]["rows"] or 0) + 1
    return hit_rows


def framework_coverage(out: Path | None = None) -> dict:
    """Group framework_refs / labels / csf_function into NIST/CIS/ISO-ish counts."""
    dest = out if out is not None else out_dir()
    poam = _read_csv(dest / "poam" / "poam.csv")
    findings = _read_csv(dest / "ciso-assistant" / "findings.csv")
    controls = _read_csv(dest / "ciso-assistant" / "applied_controls.csv")
    scenarios = _read_csv(
        dest / "ciso-assistant" / "risk_scenarios.csv", delim=";"
    )
    families = {name: _empty_family() for name in FRAMEWORK_FAMILY_ORDER}
    tokens: dict[str, dict] = {}
    poam_hits = _ingest_framework_source(
        poam, ("framework_refs",), "poam", families, tokens
    )
    finding_hits = _ingest_framework_source(
        findings, ("filtering_labels", "framework_refs"), "findings", families, tokens
    )
    control_hits = _ingest_framework_source(
        controls, ("csf_function",), "controls", families, tokens
    )
    ranked = sorted(
        tokens.values(),
        key=lambda row: (-int(row["total"]), str(row["family"]), str(row["token"])),
    )
    return {
        "families": families,
        "tokens": ranked,
        "sources": {
            "poam": poam_hits,
            "findings": finding_hits,
            "controls": control_hits,
        },
        "controls": len(controls),
        "scenarios": len(scenarios),
        "poam_rows": len(poam),
        "findings_rows": len(findings),
        "client": False,
    }


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n / (1024 * 1024):.1f} MiB"


def evidence_files(out: Path | None = None) -> list[dict]:
    """Path/size hints from out/evidence (lab-report.md and siblings)."""
    dest = (out if out is not None else out_dir()) / "evidence"
    files: list[dict] = []
    if not dest.is_dir():
        return files
    for path in sorted(dest.rglob("*")):
        if not path.is_file():
            continue
        try:
            nbytes = path.stat().st_size
            rel = path.relative_to(out if out is not None else out_dir()).as_posix()
        except OSError:
            continue
        files.append(
            {
                "name": path.name,
                "path": rel,
                "bytes": nbytes,
                "size": _fmt_bytes(nbytes),
            }
        )
    return files


def annotate_evidence_row(row: dict, files: list[dict]) -> dict:
    """Attach an on-disk path/size when the row names a file under out/evidence."""
    out = dict(row)
    path = ""
    nbytes = None
    size = ""
    name = str(row.get("name") or "")
    desc = str(row.get("description") or "")
    blob = f"{name} {desc}".lower()
    for item in files:
        item_name = str(item.get("name") or "")
        item_path = str(item.get("path") or "")
        if item_name and item_name.lower() in blob:
            path, nbytes, size = item_path, item.get("bytes"), str(item.get("size") or "")
            break
        if item_path and item_path.lower() in blob:
            path, nbytes, size = item_path, item.get("bytes"), str(item.get("size") or "")
            break
    if not path and files:
        if "loader" in blob or "lab report" in blob or "lab-report" in blob:
            hit = next((f for f in files if str(f.get("name") or "") == "lab-report.md"), None)
            if hit:
                path, nbytes, size = hit["path"], hit.get("bytes"), str(hit.get("size") or "")
    if not path and len(files) == 1:
        hit = files[0]
        path, nbytes, size = hit["path"], hit.get("bytes"), str(hit.get("size") or "")
    out["path"] = path
    out["bytes"] = nbytes
    out["size"] = size
    return out


def evidence_rows(out: Path | None = None) -> list[dict]:
    dest = out if out is not None else out_dir()
    files = evidence_files(dest)
    rows = [annotate_evidence_row(row, files) for row in _read_csv(dest / "ciso-assistant" / "evidences.csv")]
    if rows:
        return rows
    return [
        {
            "name": item["name"],
            "description": "on-disk evidence under out/evidence",
            "path": item["path"],
            "bytes": item["bytes"],
            "size": item["size"],
        }
        for item in files
    ]


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes"}


def _marker_present(out: Path, name: str) -> bool:
    if (out / name).is_file():
        return True
    return (out.parent / name).is_file()


def _prove_stamp(out: Path) -> dict:
    for path in (out / "prove-ciso.json", out.parent / "prove-ciso.json"):
        data = _read_json(path)
        if isinstance(data, dict):
            return data
    return {}


def derive_honesty(out: Path | None = None, summary: dict | None = None) -> dict:
    """LAB / SAMPLE / DEMO honesty from summary.json, prove stamp, and markers.

    Reads what prove/lab already writes (summary fields, prove-ciso.json,
    LAB.txt / SAMPLE.txt). Never invents client=true.
    """
    dest = out if out is not None else out_dir()
    summary = summary if summary is not None else (_read_json(dest / "summary.json") or {})
    if not isinstance(summary, dict):
        summary = {}
    stamp = _prove_stamp(dest)
    lab_marker = _marker_present(dest, "LAB.txt")
    sample_marker = _marker_present(dest, "SAMPLE.txt")
    use_existing = (
        _as_bool(summary.get("use_existing_in"))
        or _as_bool(stamp.get("use_existing_in"))
    )
    lab = (
        _as_bool(summary.get("lab"))
        or _as_bool(stamp.get("lab"))
        or use_existing
        or lab_marker
    )
    sample = (
        _as_bool(summary.get("sample"))
        or _as_bool(stamp.get("sample"))
        or sample_marker
    )
    if lab:
        sample = False
        use_existing = True
    demo = _as_bool(summary.get("demo")) or _as_bool(stamp.get("demo"))
    if lab or sample:
        demo = True
    seeded = _as_bool(summary.get("seeded")) or _as_bool(stamp.get("seeded"))
    if lab or use_existing:
        seeded = False
    if lab:
        label = "LAB/DEMO — not a client estate"
    elif sample:
        label = "SAMPLE/DEMO — not a client estate"
    elif demo:
        label = "DEMO — not a client estate"
    else:
        label = "not a client estate"
    return {
        "lab": lab,
        "sample": sample,
        "demo": demo,
        "client": False,
        "seeded": seeded,
        "use_existing_in": use_existing,
        "honesty_label": label,
    }


def refresh_mode_for(honesty: dict, ready: bool) -> str:
    """Collectors only for DEMO/SAMPLE bootstrap. LAB / live out = disk reload."""
    if honesty.get("lab") or honesty.get("use_existing_in"):
        return "reload"
    if ready and not honesty.get("demo"):
        return "reload"
    return "collectors"


class RunSwitchError(ValueError):
    """Operator picked a stamp/out that is not a discovered prove out."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _skip_scan_roots() -> set[Path]:
    skip = {ROOT}
    for rel in ("fixtures", "tests", "in", "collectors", "product", "docs"):
        skip.add(ROOT / rel)
    return skip


def _looks_like_runs_root(path: Path) -> bool:
    if not path.is_dir():
        return False
    try:
        children = [p for p in path.iterdir() if p.is_dir()]
    except OSError:
        return False
    if is_prove_out(path) or is_prove_out(path / "out"):
        return True
    for child in children:
        if child.name.startswith("lab-prove-"):
            return True
        if is_prove_out(child) or is_prove_out(child / "out"):
            return True
    return False


def prove_work_root() -> Path:
    """Configurable stamps parent, else parent of OUT_DIR / common prove-work."""
    raw = (os.environ.get("PROVE_WORK_ROOT") or "").strip()
    if raw:
        return Path(raw)
    current = out_dir()
    parent = current.parent
    skip = _skip_scan_roots()
    ordered: list[Path] = []
    if current.name == "out":
        ordered.append(parent.parent)
        ordered.append(parent)
    else:
        ordered.append(parent)
    for rel in COMMON_PROVE_ROOTS:
        ordered.append(ROOT / rel)
    seen: set[Path] = set()
    for cand in ordered:
        try:
            resolved = cand.resolve()
        except OSError:
            continue
        if resolved in seen or resolved in skip:
            continue
        seen.add(resolved)
        if _looks_like_runs_root(cand):
            return cand
    if parent.exists() and parent.resolve() not in skip:
        return parent
    return parent


def scan_roots() -> list[Path]:
    """Roots to walk for sibling prove outs. PROVE_WORK_ROOT wins when set."""
    raw = (os.environ.get("PROVE_WORK_ROOT") or "").strip()
    if raw:
        path = Path(raw)
        return [path] if path.is_dir() else []
    found: list[Path] = []
    seen: set[Path] = set()
    for cand in [prove_work_root(), *(ROOT / rel for rel in COMMON_PROVE_ROOTS)]:
        if not cand.is_dir():
            continue
        try:
            key = cand.resolve()
        except OSError:
            continue
        if key in seen or key in _skip_scan_roots():
            continue
        seen.add(key)
        found.append(cand)
    return found


def _iter_out_candidates(root: Path) -> list[Path]:
    found: list[Path] = []
    if not root.is_dir():
        return found
    if is_prove_out(root):
        found.append(root)
    nested = root / "out"
    if is_prove_out(nested):
        found.append(nested)
    try:
        children = [p for p in root.iterdir() if p.is_dir()]
    except OSError:
        return found
    for child in children:
        if is_prove_out(child):
            found.append(child)
        child_out = child / "out"
        if is_prove_out(child_out):
            found.append(child_out)
        if child.name == "out":
            try:
                for nested_child in child.iterdir():
                    if nested_child.is_dir() and is_prove_out(nested_child):
                        found.append(nested_child)
            except OSError:
                pass
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in found:
        try:
            key = path.resolve()
        except OSError:
            key = path
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _same_out(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return Path(left) == Path(right)


def describe_run(path: Path, current: Path | None = None) -> dict:
    dest = Path(path)
    summary = _read_json(dest / "summary.json") or {}
    if not isinstance(summary, dict):
        summary = {}
    honesty = derive_honesty(dest, summary)
    try:
        mtime = dest.stat().st_mtime
    except OSError:
        mtime = 0.0
    active = _same_out(dest, current) if current is not None else False
    return {
        "stamp": stamp_name(dest),
        "out_dir": str(dest),
        "honesty_label": honesty["honesty_label"],
        "lab": honesty["lab"],
        "sample": honesty["sample"],
        "demo": honesty["demo"],
        "client": False,
        "seeded": honesty["seeded"],
        "use_existing_in": honesty["use_existing_in"],
        "ready": bool(summary),
        "preferred": False,
        "active": active,
        "mtime": mtime,
    }


def list_runs() -> dict:
    """Recent prove outs under PROVE_WORK_ROOT / inferred sibling roots."""
    current = out_dir()
    catalog: dict[Path, Path] = {}
    for root in scan_roots():
        for cand in _iter_out_candidates(root):
            try:
                catalog[cand.resolve()] = cand
            except OSError:
                catalog[cand] = cand
    try:
        current_key = current.resolve()
    except OSError:
        current_key = current
    if current_key not in catalog:
        catalog[current_key] = current
    runs = [describe_run(path, current) for path in catalog.values()]
    runs.sort(
        key=lambda row: (
            0 if str(row["stamp"]).startswith("lab-prove-") else 1,
            -float(row["mtime"] or 0),
            str(row["stamp"]),
        )
    )
    preferred_stamp = ""
    lab_prove = [row for row in runs if str(row["stamp"]).startswith("lab-prove-")]
    if lab_prove:
        best = max(lab_prove, key=lambda row: float(row["mtime"] or 0))
        best["preferred"] = True
        preferred_stamp = str(best["stamp"])
    trimmed = runs[:MAX_RUNS]
    return {
        "root": str(prove_work_root()),
        "active_out": str(current),
        "active_stamp": stamp_name(current),
        "preferred_stamp": preferred_stamp,
        "client": False,
        "runs": trimmed,
    }


def resolve_run(*, stamp: str | None = None, out_raw: str | None = None) -> Path:
    """Map a stamp or out_dir to a discovered prove out. Never invents paths."""
    stamp_key = (stamp or "").strip()
    out_key = (out_raw or "").strip()
    if not stamp_key and not out_key:
        raise RunSwitchError(400, "stamp or out_dir required")
    catalog = list_runs()["runs"]
    if stamp_key:
        matches = [row for row in catalog if row["stamp"] == stamp_key]
        if not matches:
            raise RunSwitchError(404, "unknown stamp")
        matches.sort(
            key=lambda row: (
                not row["active"],
                not row["preferred"],
                -float(row["mtime"] or 0),
            )
        )
        dest = Path(matches[0]["out_dir"])
        if not is_prove_out(dest):
            raise RunSwitchError(404, "unknown stamp")
        return dest
    target = Path(out_key)
    for row in catalog:
        if _same_out(Path(row["out_dir"]), target):
            dest = Path(row["out_dir"])
            if not is_prove_out(dest):
                raise RunSwitchError(404, "unknown out_dir")
            return dest
    if is_prove_out(target):
        try:
            resolved = target.resolve()
        except OSError as exc:
            raise RunSwitchError(404, "unknown out_dir") from exc
        for root in scan_roots():
            try:
                resolved.relative_to(root.resolve())
                return target
            except (OSError, ValueError):
                continue
    raise RunSwitchError(404, "unknown out_dir")


def switch_active_out(*, stamp: str | None = None, out_raw: str | None = None) -> dict:
    """Process-local OUT_DIR switch. Honesty is re-derived; client stays false."""
    dest = resolve_run(stamp=stamp, out_raw=out_raw)
    os.environ["OUT_DIR"] = str(dest)
    data = estate()
    return {
        "ok": True,
        "switched": True,
        "stamp": stamp_name(dest),
        "out_dir": str(dest),
        "client": False,
        **_honesty_payload(data),
        "ready": data["ready"],
        "summary": data["summary"],
        "severity": data["severity"],
        "poam": data["poam"],
        "coverage": data["coverage"],
    }


def _count_or_zero(value) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, int):
        return value if value >= 0 else 0
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _opengrc_leavebehind(out: Path) -> dict:
    """File-true OpenGRC Data Manager CSVs. Never a live POST /api/risks."""
    dest = out / "opengrc"
    manifest_path = dest / "MANIFEST.json"
    present = manifest_path.is_file() or (dest / "risks.csv").is_file()
    manifest = _read_json(manifest_path) if manifest_path.is_file() else {}
    if not isinstance(manifest, dict):
        manifest = {}
    counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
    risks = _count_or_zero(counts.get("risks"))
    assets = _count_or_zero(counts.get("assets"))
    impls = _count_or_zero(counts.get("implementations"))
    if present and risks == 0 and (dest / "risks.csv").is_file():
        risks = len(_read_csv(dest / "risks.csv"))
    if present and assets == 0 and (dest / "assets.csv").is_file():
        assets = len(_read_csv(dest / "assets.csv"))
    if present and impls == 0 and (dest / "implementations.csv").is_file():
        impls = len(_read_csv(dest / "implementations.csv"))
    return {
        "sink": "opengrc",
        "present": present,
        "posted": False,
        "http": False,
        "client": False,
        "lab": bool(manifest.get("lab")) if present else False,
        "sample": bool(manifest.get("sample")) if present else False,
        "paying_day": str(manifest.get("paying_day") or "FAIL") if present else "FAIL",
        "counts": {
            "risks": risks,
            "assets": assets,
            "implementations": impls,
        },
        "dir": str(dest) if present else "",
    }


def _probo_leavebehind(out: Path) -> dict:
    """File-true Probo drafts. Not a live GraphQL createFinding."""
    path = out / "import_preview" / "probo.json"
    present = path.is_file()
    payload = _read_json(path) if present else {}
    if not isinstance(payload, dict):
        payload = {}
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    add_finding = _count_or_zero(counts.get("addFinding"))
    add_risk = _count_or_zero(counts.get("addRisk"))
    create_risk = _count_or_zero(counts.get("createRisk"))
    if present and add_finding == 0 and isinstance(payload.get("addFinding"), list):
        add_finding = len(payload["addFinding"])
    if present and add_risk == 0 and isinstance(payload.get("addRisk"), list):
        add_risk = len(payload["addRisk"])
    if present and create_risk == 0 and isinstance(payload.get("createRisk"), list):
        create_risk = len(payload["createRisk"])
    org = payload.get("organization_id") if present else None
    if org == "":
        org = None
    return {
        "sink": "probo",
        "present": present,
        "posted": False,
        "http": False,
        "client": False,
        "lab": bool(payload.get("lab")) if present else False,
        "sample": bool(payload.get("sample")) if present else False,
        "paying_day": str(payload.get("paying_day") or "FAIL") if present else "FAIL",
        "organization_id": org if isinstance(org, str) else None,
        "documentation_only": True,
        "counts": {
            "addFinding": add_finding,
            "addRisk": add_risk,
            "createRisk": create_risk,
        },
        "path": str(path) if present else "",
    }


def packaged_drop() -> Path:
    """Offline SAMPLE/DEMO copy under product-lab/drop. Not a LAB dest_in."""
    return ROOT / "product-lab" / "drop"


def leavebehind_sinks(out: Path | None = None) -> dict:
    """OpenGRC/Probo file-true leave-behind rollup. posted and http stay false.

    Prefer OUT_DIR leave-behind. When those files are missing, fall back to
    packaged product-lab/drop so /api/summary KPIs match /export.zip.
    """
    dest = out if out is not None else out_dir()
    og = _opengrc_leavebehind(dest)
    probo = _probo_leavebehind(dest)
    drop = packaged_drop()
    source_og = "out" if og["present"] else ""
    source_probo = "out" if probo["present"] else ""
    if not og["present"] and drop.is_dir():
        packaged_og = _opengrc_leavebehind(drop)
        if packaged_og["present"]:
            og = packaged_og
            source_og = "product-lab/drop"
    if not probo["present"] and drop.is_dir():
        packaged_probo = _probo_leavebehind(drop)
        if packaged_probo["present"]:
            probo = packaged_probo
            source_probo = "product-lab/drop"
    og = dict(og)
    og["source"] = source_og
    probo = dict(probo)
    probo["source"] = source_probo
    return {
        "opengrc": og,
        "probo": probo,
    }


def estate() -> dict:
    out = out_dir()
    summary = _read_json(out / "summary.json") or {}
    if not isinstance(summary, dict):
        summary = {}
    findings = _read_csv(out / "ciso-assistant" / "findings.csv")
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in findings:
        key = str(row.get("severity") or "").lower()
        if key in sev:
            sev[key] += 1
    honesty = derive_honesty(out, summary)
    ready = bool(summary)
    mode = refresh_mode_for(honesty, ready)
    poam = poam_rows(out)
    coverage = framework_coverage(out)
    sinks = leavebehind_sinks(out)
    return {
        "product": "GRC Collector Pack",
        "version": "0.3.0",
        "repo": str(ROOT),
        "out_dir": str(out),
        "active_stamp": stamp_name(out),
        "bind": f"{bind_host()}:{bind_port()}",
        "ready": ready,
        "demo": honesty["demo"],
        "lab": honesty["lab"],
        "sample": honesty["sample"],
        "client": False,
        "seeded": honesty["seeded"],
        "use_existing_in": honesty["use_existing_in"],
        "honesty_label": honesty["honesty_label"],
        "refresh_mode": mode,
        "summary": summary,
        "severity": sev,
        "poam": poam_summary(out, poam),
        "coverage": coverage,
        "opengrc": sinks["opengrc"],
        "probo": sinks["probo"],
        "safety": {
            "dry_run": os.environ.get("DRY_RUN", "1"),
            "ciso_push": os.environ.get("CISO_PUSH", "0"),
            "riskready_push": os.environ.get("RISKREADY_PUSH", "0"),
            "riskready_wrap": False,
            "riskready_review_only": True,
            "live_scan": os.environ.get("GRC_LIVE_SCAN", "0"),
            "posts_api_risks": False,
            "bind": "127.0.0.1",
        },
    }


def payload(kind: str):
    out = out_dir()
    mapping = {
        "assets": out / "ciso-assistant" / "assets.csv",
        "findings": out / "ciso-assistant" / "findings.csv",
        "vulnerabilities": out / "ciso-assistant" / "vulnerabilities.csv",
        "evidences": out / "ciso-assistant" / "evidences.csv",
        "controls": out / "ciso-assistant" / "applied_controls.csv",
        "scenarios": out / "ciso-assistant" / "risk_scenarios.csv",
        "poam": out / "poam" / "poam.csv",
        "incidents": out / "riskready" / "incidents.json",
        "proposed": out / "riskready" / "risks_proposed.json",
        "rr_assets": out / "riskready" / "assets.json",
        "rr_evidence": out / "riskready" / "evidence.json",
    }
    path = mapping.get(kind)
    if path is None:
        return None
    if kind == "poam":
        return poam_rows(out)
    if kind == "evidences":
        return evidence_rows(out)
    if path.suffix == ".json":
        data = _read_json(path)
        return data if data is not None else []
    delim = ";" if path.name == "risk_scenarios.csv" else ","
    return _read_csv(path, delim)


def build_drop_zip() -> bytes:
    out = out_dir()
    buf = io.BytesIO()
    files = [
        out / "summary.json",
        out / "evidence" / "lab-report.md",
        out / "ocsf" / "compliance_findings.json",
    ]
    files.extend(sorted((out / "ciso-assistant").glob("*.csv")))
    files.extend(sorted((out / "poam").glob("*")))
    files.extend(sorted((out / "opengrc").glob("*")))
    files.append(out / "import_preview" / "probo.json")
    files.extend(sorted((out / "probo").glob("*")))
    drop = ROOT / "product-lab" / "drop"
    # Fail closed: packaged SAMPLE product-lab/drop only rides along for a LAB
    # run (arcname stays product-lab/drop/...). A non-LAB run never ships
    # packaged sinks, so demo KPIs cannot pass as this run's leave-behind.
    include_packaged = bool(derive_honesty(out).get("lab"))
    if include_packaged and drop.is_dir():
        files.extend(sorted((drop / "ciso").glob("*.csv")))
        files.extend(sorted((drop / "opengrc").glob("*")))
        files.append(drop / "import_preview" / "probo.json")
        files.extend(sorted((drop / "probo").glob("*")))
    readme = (
        "GRC Collector Pack drop\n"
        "Pentera finds it; Evergreen maps it.\n"
        "Import CISO CSVs with clica or the CISO Assistant UI.\n"
        "POA&M: poam/poam.csv — owner and due are blank for a human.\n"
        "OpenGRC Data Manager CSVs: opengrc/*.csv — file-true leave-behind, posted=false, not live import.\n"
        "Probo drafts: import_preview/probo.json — file-true, posted=false, not live GraphQL.\n"
        "RiskReady is out of scope. This drop does not include RiskReady JSON.\n"
        "Do not POST /api/risks.\n"
    )
    if include_packaged:
        readme += (
            "product-lab/drop/*: SAMPLE packaged sinks (offline demo copy), "
            "not this LAB run's dest_in. SAMPLE packaged != LAB != client.\n"
        )
    else:
        readme += (
            "packaged SAMPLE sinks excluded: this is not a LAB run, so "
            "product-lab/drop is not shipped (fail closed).\n"
        )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("IMPORT.md", readme)
        for path in files:
            if path.is_file():
                try:
                    arc = path.relative_to(out).as_posix()
                except ValueError:
                    arc = path.relative_to(ROOT).as_posix()
                if "riskready" in arc.lower():
                    continue
                zf.write(path, arcname=arc)
    return buf.getvalue()


def _honesty_payload(data: dict) -> dict:
    return {
        "lab": data["lab"],
        "sample": data["sample"],
        "demo": data["demo"],
        "client": False,
        "seeded": data["seeded"],
        "use_existing_in": data["use_existing_in"],
        "honesty_label": data["honesty_label"],
        "refresh_mode": data["refresh_mode"],
    }


def reload_estate() -> dict:
    data = estate()
    return {
        "ok": True,
        "reloaded": True,
        "ran": [],
        "collectors_ran": False,
        "mode": "reload",
        "summary": data["summary"],
        **_honesty_payload(data),
    }


def run_collectors() -> list[str]:
    os.environ["PYTHONPATH"] = str(ROOT)
    os.environ.setdefault("OUT_DIR", str(ROOT / "out"))
    os.environ["DRY_RUN"] = "1"
    os.environ["CISO_PUSH"] = "0"
    os.environ["RISKREADY_PUSH"] = "0"
    os.environ["GRC_LIVE_SCAN"] = "0"
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    ran = []
    for name in COLLECTORS:
        mod = f"collectors.{name.replace('.py', '')}"
        if mod in sys.modules:
            del sys.modules[mod]
        module = __import__(mod, fromlist=["main"])
        module.main()
        ran.append(name)
    return ran


def refresh_estate() -> dict:
    data = estate()
    if data["refresh_mode"] == "reload":
        return reload_estate()
    ran = run_collectors()
    data = estate()
    return {
        "ok": True,
        "reloaded": False,
        "ran": ran,
        "collectors_ran": True,
        "mode": "collectors",
        "summary": data["summary"],
        **_honesty_payload(data),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "GRCCollectorPack/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, code: int, data) -> None:
        raw = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _bytes(self, code: int, body: bytes, content_type: str, filename: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _forbid_risks(self, path: str) -> bool:
        if "/api/risks" in path:
            self._json(403, {"error": "POST /api/risks is forbidden", "posted": False})
            return True
        return False

    def _require_loopback(self, action: str) -> bool:
        peer = (self.client_address[0] if self.client_address else "").strip("[]")
        if peer not in ALLOWED_HOSTS:
            self._json(403, {"error": f"{action} is loopback-only"})
            return True
        return False

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _switch_from_request(self, stamp: str | None, out_raw: str | None) -> None:
        if self._require_loopback("run switch"):
            return
        try:
            result = switch_active_out(stamp=stamp, out_raw=out_raw)
            self._json(200, result)
        except RunSwitchError as exc:
            self._json(exc.code, {"ok": False, "error": str(exc), "client": False})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if self._forbid_risks(path):
            return
        if path in {"/", "/index.html"}:
            html = (STATIC / "index.html").read_bytes()
            self._bytes(200, html, "text/html; charset=utf-8")
            return
        if path == "/static/app.css":
            self._bytes(200, (STATIC / "app.css").read_bytes(), "text/css; charset=utf-8")
            return
        if path == "/static/app.js":
            self._bytes(200, (STATIC / "app.js").read_bytes(), "application/javascript; charset=utf-8")
            return
        if path == "/health":
            self._json(200, {"ok": True, "ready": estate()["ready"]})
            return
        if path == "/api/summary":
            data = estate()
            readyish = data["ready"] or data["lab"] or data["use_existing_in"]
            self._json(200 if readyish else 503, data)
            return
        if path == "/api/poam/summary":
            data = estate()
            self._json(
                200,
                {
                    "poam": data["poam"],
                    "client": False,
                    **_honesty_payload(data),
                },
            )
            return
        if path == "/api/coverage":
            data = estate()
            self._json(
                200,
                {
                    **data["coverage"],
                    "client": False,
                    **_honesty_payload(data),
                },
            )
            return
        if path == "/api/runs":
            self._json(200, list_runs())
            return
        if path == "/api/runs/select":
            qs = parse_qs(parsed.query)
            stamp = (qs.get("stamp") or [None])[0]
            out_raw = (qs.get("out") or qs.get("out_dir") or [None])[0]
            self._switch_from_request(stamp, out_raw)
            return
        table = {
            "/api/assets": "assets",
            "/api/findings": "findings",
            "/api/vulnerabilities": "vulnerabilities",
            "/api/evidences": "evidences",
            "/api/controls": "controls",
            "/api/scenarios": "scenarios",
            "/api/poam": "poam",
            "/api/incidents": "incidents",
            "/api/proposed": "proposed",
        }
        if path in table:
            self._json(200, payload(table[path]))
            return
        if path == "/export.zip":
            blob = build_drop_zip()
            if len(blob) < 64:
                self._json(503, {"error": "no estate yet — refresh first"})
                return
            self._bytes(200, blob, "application/zip", "grc-collector-pack-drop.zip")
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if self._forbid_risks(path):
            return
        if path == "/api/runs":
            body = self._read_json_body()
            stamp = body.get("stamp") if isinstance(body.get("stamp"), str) else None
            out_raw = body.get("out_dir") if isinstance(body.get("out_dir"), str) else None
            if out_raw is None and isinstance(body.get("out"), str):
                out_raw = body.get("out")
            self._switch_from_request(stamp, out_raw)
            return
        if path != "/api/refresh":
            self._json(404, {"error": "not found"})
            return
        if self._require_loopback("refresh"):
            return
        try:
            result = refresh_estate()
            self._json(200, result)
        except Exception:
            traceback.print_exc()
            self._json(500, {"ok": False, "error": "refresh failed"})


def make_server(host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    bound = assert_loopback_host(host if host is not None else bind_host())
    httpd = ThreadingHTTPServer((bound, port if port is not None else bind_port()), Handler)
    httpd.allow_reuse_address = True
    return httpd


def main() -> None:
    os.environ.setdefault("DRY_RUN", "1")
    os.environ.setdefault("CISO_PUSH", "0")
    os.environ.setdefault("RISKREADY_PUSH", "0")
    os.environ.setdefault("GRC_LIVE_SCAN", "0")
    os.environ.setdefault("PYTHONPATH", str(ROOT))
    if not (os.environ.get("OUT_DIR") or "").strip():
        hinted = last_lab_prove_out()
        os.environ["OUT_DIR"] = str(hinted if hinted else ROOT / "out")
    host, port = assert_loopback_host(bind_host()), bind_port()
    httpd = make_server(host, port)
    print(f"GRC Collector Pack  http://{host}:{port}/", flush=True)
    print("Local operator console. Never POSTs /api/risks.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
