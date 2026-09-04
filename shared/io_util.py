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


def _is_input_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name in {".gitkeep", ".DS_Store"}:
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


def load_inputs(source: str, suffixes: Iterable[str] | None = None) -> tuple[list[Path], bool]:
    """Return (files, used_demo). Empty in/ → fixtures/demo/<sensor>."""
    sensor = SENSOR_IN.get(source, source)
    live = list_files(in_dir() / sensor, suffixes)
    if live:
        return live, False
    demo = list_files(fixtures_dir() / sensor, suffixes)
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


def run_collector(source: str, suffixes: Iterable[str], parse_file) -> list[dict[str, Any]]:
    files, demo = load_inputs(source, suffixes)
    records: list[dict[str, Any]] = []
    parsed_any = False
    for path in files:
        try:
            recs = list(parse_file(path) or [])
        except Exception:
            recs = []
        if recs:
            parsed_any = True
            records.extend(recs)
            write_raw_copy(source, path, recs)
        else:
            write_raw_copy(source, path, {"error": "parse-failed", "file": path.name})
    if not parsed_any:
        demo = True
        sensor = SENSOR_IN.get(source, source)
        for path in list_files(fixtures_dir() / sensor, suffixes):
            try:
                recs = list(parse_file(path) or [])
            except Exception:
                recs = []
            if recs:
                records.extend(recs)
                write_raw_copy(source, path, recs)
    records = mark_demo(records, demo)
    write_canonical(source, records)
    return records
