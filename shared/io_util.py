from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Iterable

from shared.schema import Record

AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
AWS_SECRET = re.compile(
    r'(?i)(aws_secret_access_key\s*[=:]\s*)(["\']?)([A-Za-z0-9/+=]{40})(\2)'
)
GITHUB_PAT = re.compile(r"ghp_[A-Za-z0-9]{20,}")
GENERIC_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{20,}")
JSON_SECRET_FIELD = re.compile(
    r'(?i)("(?:secret|match|aws_secret_access_key)"\s*:\s*")(?:\\.|[^"\\])*"'
)
_SECRET_KEYS = frozenset(
    {"secret", "match", "raw_secret", "plaintext", "aws_secret_access_key"}
)


def get_root() -> Path:
    return Path(os.environ.get("PACK_ROOT", os.getcwd())).resolve()


def get_out() -> Path:
    raw = os.environ.get("OUT_DIR")
    return Path(raw).resolve() if raw else (get_root() / "out")


def env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def live_scan_enabled() -> bool:
    return env_flag("GRC_LIVE_SCAN", "0")


def refuse_live_scan() -> None:
    """Never execute scanners. GRC_LIVE_SCAN=1 is ignored."""
    if live_scan_enabled():
        print("GRC_LIVE_SCAN=1 ignored: this pack parses in/ or fixtures only")


def dry_run() -> bool:
    return env_flag("DRY_RUN", "1")


class exclusive_file_lock:
    """Create-only lock file so two loaders cannot interleave writes."""

    def __init__(self, path: Path, timeout: float = 60.0, stale_after: float = 300.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self.stale_after = stale_after
        self._fd: int | None = None

    def _stale(self) -> bool:
        try:
            age = time.time() - self.path.stat().st_mtime
        except OSError:
            return True
        return age > self.stale_after

    def __enter__(self) -> exclusive_file_lock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(os.fspath(self.path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
                os.write(self._fd, str(os.getpid()).encode("ascii", "replace"))
                return self
            except FileExistsError:
                if self._stale():
                    try:
                        self.path.unlink()
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise SystemExit(
                        f"loader lock timeout: another loader holds {self.path}"
                    )
                time.sleep(0.05)

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        try:
            self.path.unlink()
        except OSError:
            pass


def ensure_out_tree() -> Path:
    out = get_out()
    for sub in ("raw", "canonical", "ciso-assistant", "riskready", "ocsf", "evidence", "opengrc", "probo"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    return out


def _list_input_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    files: list[Path] = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and not path.name.startswith("."):
            files.append(path)
    return files


def discover_input_files(sensor: str) -> list[Path]:
    """Prefer in/<sensor>/ when it has files; otherwise fixtures/demo/<sensor>/."""
    root = get_root()
    in_files = _list_input_files(root / "in" / sensor)
    if in_files:
        return in_files
    return _list_input_files(root / "fixtures" / "demo" / sensor)


def copy_raw(sensor: str, files: Iterable[Path]) -> None:
    dest = get_out() / "raw" / sensor
    dest.mkdir(parents=True, exist_ok=True)
    text_suffixes = {".json", ".jsonl", ".ndjson", ".txt", ".xml", ".csv", ".md", ".yml", ".yaml", ".gnmap", ".nmap", ".sarif"}
    for src in files:
        target = dest / src.name
        if target.exists() and target.resolve() == src.resolve():
            continue
        if src.suffix.lower() in text_suffixes or src.name.endswith(".jsonl"):
            write_text(target, src.read_text(encoding="utf-8-sig", errors="replace"))
            continue
        try:
            shutil.copy2(src, target)
        except OSError:
            target.write_bytes(src.read_bytes())


def redact_text(value: str) -> str:
    text = JSON_SECRET_FIELD.sub(r'\1[REDACTED]"', value)
    text = AWS_ACCESS_KEY.sub("[REDACTED]", text)
    text = AWS_SECRET.sub(r"\1\2[REDACTED]\4", text)
    text = GITHUB_PAT.sub("[REDACTED]", text)
    text = GENERIC_BEARER.sub(r"\1[REDACTED]", text)
    return text


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if str(k).lower() in _SECRET_KEYS:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_obj(v)
        return out
    return value


def load_structured(path: Path) -> list[Any]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return []
    text = text.lstrip("\ufeff")
    if not text.strip():
        return []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return obj
        return [obj]
    except json.JSONDecodeError:
        rows: list[Any] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8-sig", errors="replace").lstrip("\ufeff").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(redact_obj(obj), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(redact_obj(row), ensure_ascii=False) + "\n")
    tmp.replace(path)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(redact_text(content), encoding="utf-8")
    tmp.replace(path)


def emit(sensor: str, records: list[Record], inputs: list[Path]) -> Path:
    refuse_live_scan()
    ensure_out_tree()
    copy_raw(sensor, inputs)
    out = get_out() / "canonical" / f"{sensor}.jsonl"
    canonical = [r.to_canonical() for r in records]
    write_jsonl(out, canonical)
    evidence_rows = [r for r in records if r.kind == "evidence"]
    lines = [f"# Evidence — {sensor}", ""]
    if evidence_rows:
        for row in evidence_rows:
            lines.append(f"## {row.name}")
            lines.append(row.description)
            lines.append("")
    else:
        lines.append("## Collector parse")
        lines.append(
            f"Parsed demo files for sensor {sensor} from in/ or fixtures/demo/. Live scan was not executed."
        )
        lines.append("")
    write_text(get_out() / "evidence" / f"{sensor}.md", "\n".join(lines))
    print(
        f"{sensor}: wrote {len(canonical)} records "
        f"({sum(1 for r in records if r.kind == 'asset')} assets, "
        f"{sum(1 for r in records if r.kind == 'finding')} findings) "
        f"from {len(inputs)} input files"
    )
    return out
