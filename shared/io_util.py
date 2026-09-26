"""File I/O, fixture fallback, and secret redaction. No sockets."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from shared.schema import slug

SENSOR_IN = {
    "cloud-prowler": "cloud",
    "inventory-nmap": "nmap",
    "vuln-scan": "vuln",
    "host-wazuh": "wazuh",
    "identity-ad": "identity",
    "easm": "easm",
    "k8s-kubescape": "k8s",
    "code-secrets": "code",
    "saas-idp": "saas",
    "honeypot": "honeypot",
    "dns-email": "dns_email",
}

# Extra operator drop folders that reuse an existing Layer C parser.
# in/mdm/ is an alias for host-wazuh (Intune/Jamf) — not a new catalog sensor.
SENSOR_EXTRA = {
    "host-wazuh": ("mdm",),
}

_SECRET_RES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(password|secret|api[_-]?key|token|authorization)\s*[:=]\s*['\"]?[^'\"\s,;]+"),
]


def root_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return Path(raw) if raw else default


def out_dir() -> Path:
    raw = os.environ.get("OUT_DIR")
    if raw is None or not str(raw).strip():
        raise SystemExit("OUT_DIR is unset; refusing to write a silent empty tree")
    path = Path(raw)
    if not path.parent.exists():
        raise SystemExit(f"OUT_DIR parent missing: {path.parent}")
    return path


def in_dir() -> Path:
    return env_path("IN_DIR", root_dir() / "in")


def fixtures_dir() -> Path:
    return env_path("FIXTURES_DIR", root_dir() / "fixtures" / "demo")


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if not isinstance(value, str):
        return value
    text = value
    for pat in _SECRET_RES:
        text = pat.sub("[REDACTED]", text)
    return text


# Banner / bookkeeping files are not scanner drops. LAB.txt in a sensor
# folder must not count as a live parse target or trigger demo fallback.
SKIP_INPUT_NAMES = frozenset(
    {".gitkeep", ".DS_Store", "SAMPLE.txt", "LAB.txt", "README.md", "MANIFEST"}
)
DEMO_FALLBACK_LABELS = frozenset({"DEMO", "SAMPLE"})
NEVER_DEMO_LABELS = frozenset({"LAB", "CLIENT"})


def _is_input_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name in SKIP_INPUT_NAMES:
        return False
    return True


def list_files(folder: Path, suffixes: Iterable[str] | None = None) -> list[Path]:
    if not folder.exists():
        return []
    suf = {s.lower() for s in (suffixes or [])}
    out: list[Path] = []
    for path in sorted(folder.rglob("*")):
        if not _is_input_file(path):
            continue
        if suf and path.suffix.lower() not in suf and path.name.lower() not in suf:
            continue
        out.append(path)
    return out


def _sensor_folders(source: str) -> list[str]:
    sensor = SENSOR_IN.get(source, source)
    extras = list(SENSOR_EXTRA.get(source, ()))
    return [sensor, *[e for e in extras if e != sensor]]


def estate_hint() -> str:
    """Collector-side estate for demo-fallback policy. Never a client KEEP stamp.

    Mirrors grc_loader.estate_label without reading records. CLIENT is accepted
    only as a refuse-demo signal; exports still watermark UNLABELED.
    """
    raw = str(os.environ.get("GRC_ESTATE_LABEL") or "").strip().upper()
    if raw in {"LAB", "SAMPLE", "DEMO", "CLIENT"}:
        return raw
    try:
        folder = in_dir()
    except Exception:
        folder = None
    if folder is not None and folder.is_dir():
        if (folder / "LAB.txt").is_file() or any(folder.rglob("LAB.txt")):
            return "LAB"
        if (folder / "SAMPLE.txt").is_file() or any(folder.rglob("SAMPLE.txt")):
            return "SAMPLE"
    if os.environ.get("DROPBOX_DEMO") == "1":
        return "SAMPLE"
    return "UNLABELED"


def in_dir_has_live_inputs() -> bool:
    """True when IN_DIR holds any real drop (operator / LAB / live)."""
    folder = in_dir()
    if not folder.is_dir():
        return False
    for path in folder.rglob("*"):
        if _is_input_file(path):
            return True
    return False


def allow_demo_fallback(*, had_live_files: bool) -> bool:
    """DEMO/SAMPLE may load fixtures/demo. LAB / CLIENT / operator drops may not.

    Once in/<sensor> has files, never substitute fixtures — parse failure
    stays empty. Classic empty-in lab (UNLABELED, no drops) is DEMO.
    """
    if had_live_files:
        return False
    label = estate_hint()
    if label in NEVER_DEMO_LABELS:
        return False
    if label in DEMO_FALLBACK_LABELS:
        return True
    return not in_dir_has_live_inputs()


def load_inputs(source: str, suffixes: Iterable[str] | None = None) -> tuple[list[Path], bool]:
    """Return (files, used_demo). Demo fixtures only when fallback is allowed."""
    folders = _sensor_folders(source)
    live: list[Path] = []
    for folder in folders:
        live.extend(list_files(in_dir() / folder, suffixes))
    if live:
        return live, False
    if not allow_demo_fallback(had_live_files=False):
        return [], False
    demo: list[Path] = []
    for folder in folders:
        demo.extend(list_files(fixtures_dir() / folder, suffixes))
    return demo, True


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def read_json(path: Path) -> Any:
    raw = read_text(path).lstrip("\ufeff").strip()
    if not raw:
        raise json.JSONDecodeError("empty", raw, 0)
    return json.loads(raw)


def read_jsonl(path: Path) -> list[Any]:
    rows: list[Any] = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def stable_hash(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return h[:12]


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact(data), indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact(text), encoding="utf-8")


def write_canonical(source: str, records: list[dict[str, Any]]) -> Path:
    dest = out_dir() / "canonical" / f"{slug(source, 64)}.jsonl"
    dest.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for rec in records:
        lines.append(json.dumps(redact(rec), separators=(",", ":")))
    dest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return dest


def write_raw_copy(source: str, path: Path, parsed: Any | None = None) -> None:
    dest_dir = out_dir() / "raw" / slug(source, 64)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if parsed is not None:
        write_json(dest_dir / f"{path.stem}.parsed.json", parsed)
    else:
        text = redact(read_text(path))
        (dest_dir / path.name).write_text(text, encoding="utf-8")


def mark_demo(records: list[dict[str, Any]], used_demo: bool) -> list[dict[str, Any]]:
    if not used_demo:
        return records
    for rec in records:
        labels = rec.setdefault("labels", [])
        if "demo" not in labels:
            labels.append("demo")
    return records


def sensor_status_path(source: str) -> Path:
    return out_dir() / "coverage" / "sensors" / f"{slug(source, 64)}.json"


def write_sensor_status(status: dict[str, Any]) -> Path:
    dest = sensor_status_path(str(status.get("source") or "sensor"))
    write_json(dest, status)
    return dest


def load_sensor_coverage(out: Path | None = None) -> list[dict[str, Any]]:
    root = (out if out is not None else out_dir()) / "coverage" / "sensors"
    rows: list[dict[str, Any]] = []
    if not root.is_dir():
        return rows
    for path in sorted(root.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("source"):
            rows.append(data)
    return rows


def _sensor_rollup(
    source: str,
    *,
    used_demo: bool,
    files: list[Path],
    records: list[dict[str, Any]],
    issues: list[dict[str, str]],
) -> dict[str, Any]:
    n_rec = len(records)
    n_files = len(files)
    if used_demo and n_rec:
        status = "demo"
    elif any(item.get("status") == "parse_error" for item in issues) and n_rec == 0:
        status = "parse_error"
    elif n_files == 0:
        status = "empty" if not issues else "no_records"
    elif n_rec == 0:
        status = "no_records"
    elif issues:
        status = "partial"
    else:
        status = "ok"
    return {
        "source": source,
        "status": status,
        "demo": bool(used_demo),
        "files": n_files,
        "records": n_rec,
        "issues": issues,
    }


def _malformed_reason(path: Path) -> str | None:
    """Name truncated/invalid JSON even when a parser swallows the exception."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff").strip()
    except OSError as exc:
        return f"OSError: {exc}"
    if not raw:
        return None
    suffix = path.suffix.lower()
    if suffix in {".json", ".sarif"} or raw[0] in "{[":
        try:
            json.loads(raw)
        except json.JSONDecodeError as exc:
            return f"JSONDecodeError: {exc}"
    return None


def run_collector(
    source: str,
    suffixes: Iterable[str],
    parse_file,
    finalize=None,
) -> list[dict[str, Any]]:
    files, used_demo = load_inputs(source, suffixes)
    records: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    for path in files:
        error: str | None = None
        try:
            recs = list(parse_file(path) or [])
        except Exception as exc:
            recs = []
            error = f"{type(exc).__name__}: {exc}"
        if recs:
            records.extend(recs)
            write_raw_copy(source, path, recs)
            continue
        malformed = error or _malformed_reason(path)
        status = "parse_error" if malformed else "no_records"
        reason = malformed or "parser yielded no records"
        issues.append({"status": status, "file": path.name, "reason": reason})
        write_raw_copy(source, path, {"error": status, "file": path.name, "reason": reason})
    # Honesty: live files that fail or yield nothing never pull fixtures/demo.
    if not files and not used_demo:
        issues.append(
            {
                "status": "no_records",
                "file": "",
                "reason": "empty sensor; demo substitution refused",
            }
        )
    if callable(finalize):
        records = list(finalize(records) or records)
    # SAMPLE/DEMO copies of fixtures into in/ stay labeled. Substitution above
    # is separate: live parse failure never pulls fixtures/demo.
    estate = estate_hint()
    label_demo = bool(used_demo or (records and estate in DEMO_FALLBACK_LABELS))
    records = mark_demo(records, label_demo)
    write_canonical(source, records)
    write_sensor_status(
        _sensor_rollup(
            source,
            used_demo=label_demo,
            files=files,
            records=records,
            issues=issues,
        )
    )
    return records
