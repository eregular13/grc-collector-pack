"""File I/O, fixture fallback, and secret redaction. No sockets."""

from __future__ import annotations

import hashlib
import logging
import json
import warnings
import os
import re
import xml.etree.ElementTree as ET
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


def utc_now() -> datetime:
    """UTC datetime now, or SOURCE_DATE_EPOCH / GRC_RUN_TS when set.

    Companion to ``iso_now()``. Used by grc_loader.load / apply_ledger so
    ledger ``run_at``, event ``at``, and first_seen/last_seen freeze under
    reproducible runs the same way evidences.csv already does.
    Explicit caller ``run_at=`` still wins at those call sites.
    """
    raw = (os.environ.get("SOURCE_DATE_EPOCH") or os.environ.get("GRC_RUN_TS") or "").strip()
    if raw:
        try:
            if raw.isdigit():
                return datetime.fromtimestamp(int(raw), tz=timezone.utc)
            text = raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (ValueError, OSError, OverflowError):
            pass
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """UTC now, or SOURCE_DATE_EPOCH / GRC_RUN_TS when set (reproducible stamps)."""
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")



_CSV_FORMULA_ALWAYS = frozenset("=@")
_CSV_FORMULA_SIGNED = frozenset("+-")
# Whole-cell safe signed values only: negatives, decimals, phone numbers.
# ``+1+1`` / ``-2+3+cmd|…`` must stay formulas (second-char digit is not enough).
_CSV_SIGNED_SAFE = re.compile(r"^[+-][0-9][0-9 ().-]*$")


def is_csv_formula(value: Any) -> bool:
    """True for spreadsheet-formula cells (``=cmd|' /C calc'!A0`` and kin).

    Bare ``-``, numeric ``-1`` / ``-1.5``, and phone-style ``+44…`` are not
    formulas. ``=``, ``@SUM(``, ``+cmd``, ``-cmd|``, ``+1+1``, ``-1+1``,
    ``-2+3+cmd|…``, ``-(1)``, ``--``, and tab/CR-prefixed forms are.
    """
    text = str(value or "").lstrip("\ufeff \t\r")
    if not text:
        return False
    first = text[0]
    if first in _CSV_FORMULA_ALWAYS:
        return True
    if first in _CSV_FORMULA_SIGNED:
        if _CSV_SIGNED_SAFE.fullmatch(text):
            return False
        return len(text) > 1
    return False


def neutralize_csv_formula(value: Any) -> Any:
    """OWASP CSV-injection: prefix a formula cell with a leading single quote."""
    if not isinstance(value, str) or not is_csv_formula(value):
        return value
    return "'" + value


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
    {
        ".gitkeep",
        ".DS_Store",
        "SAMPLE.txt",
        "LAB.txt",
        "README.md",
        "MANIFEST",
        "poam-ledger.json",
        "asset-ledger.json",
        "AUTHORIZATION.txt",
        "AUTHORIZATION.md",
        "AUTH.txt",
    }
)
DEMO_FALLBACK_LABELS = frozenset({"DEMO", "SAMPLE"})
NEVER_DEMO_LABELS = frozenset({"LAB", "CLIENT"})
UNRECOGNIZED_STATUS = "unrecognized_shape"


class UnrecognizedShape(ValueError):
    """Live drop is a known suffix but not a shape this sensor can parse."""

    def __init__(self, reason: str, *, file: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.file = file


class SidecarSkip(Exception):
    """Known sidecar next to a parsed sibling — not a coverage gap."""

    def __init__(self, reason: str = "", *, file: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.file = file
SENSOR_GAP_STATUSES = frozenset(
    {"parse_error", "no_records", UNRECOGNIZED_STATUS, "empty", "partial"}
)


def _is_input_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name in SKIP_INPUT_NAMES:
        return False
    return True


def _suffix_set(suffixes: Iterable[str] | None) -> set[str]:
    return {s.lower() for s in (suffixes or [])}


def recognized_suffix(path: Path, suffixes: Iterable[str] | None) -> bool:
    suf = _suffix_set(suffixes)
    if not suf:
        return True
    return path.suffix.lower() in suf or path.name.lower() in suf


def list_files(folder: Path, suffixes: Iterable[str] | None = None) -> list[Path]:
    if not folder.exists():
        return []
    out: list[Path] = []
    for path in sorted(folder.rglob("*")):
        if not _is_input_file(path):
            continue
        if suffixes is not None and not recognized_suffix(path, suffixes):
            continue
        out.append(path)
    return out


def unread_input_files(source: str, suffixes: Iterable[str] | None = None) -> list[Path]:
    """Live drops whose type/shape this sensor does not read."""
    unread: list[Path] = []
    for folder in _sensor_folders(source):
        for path in list_files(in_dir() / folder, suffixes=None):
            if not recognized_suffix(path, suffixes):
                if _is_nmap_text_twin(path):
                    continue
                unread.append(path)
    return unread


def _is_nmap_text_twin(path: Path) -> bool:
    """nmap -oA writes .xml/.nmap/.gnmap. XML is the parsed source of truth.

    A .nmap normal-output file is a human-readable copy and is not parsed; it
    is not counted unread when a same-stem .xml sibling exists. Without the
    XML it stays unread (XML is required; see docs/NMAP_INPUT.md).
    """
    if path.suffix.lower() != ".nmap":
        return False
    sibling = path.with_suffix(".xml")
    if not sibling.is_file():
        return False
    try:
        return "<nmaprun" in sibling.read_text(encoding="utf-8", errors="replace")[:4096].lower()
    except OSError:
        return False


def unrecognized_reason(path: Path, suffixes: Iterable[str] | None) -> str:
    suf = sorted(_suffix_set(suffixes))
    suffix = path.suffix.lower() or "(none)"
    accepted = ", ".join(suf) if suf else "(any)"
    return f"unrecognized shape; suffix {suffix} not in {accepted}"


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
    unread = unread_input_files(source, suffixes)
    if unread:
        # A live drop is present; do not hide it behind fixtures/demo.
        return [], False
    if not allow_demo_fallback(had_live_files=False):
        return [], False
    demo: list[Path] = []
    for folder in folders:
        demo.extend(list_files(fixtures_dir() / folder, suffixes))
    return demo, True



def read_csv_dicts(text: str, *, delimiters: str = ",;\t") -> list[dict[str, str]]:
    """Parse CSV text into row dicts.

    Sniffs the delimiter, refuses duplicate header names, and keeps quoted
    newlines (no pre-split). Trailing NULs are stripped by callers via read_text.
    """
    import csv as _csv
    from io import StringIO as _StringIO

    raw = (text or "").lstrip("\ufeff")
    if not raw.strip():
        return []
    sample = raw[:8000]
    dialect = _csv.excel
    if any(d in sample for d in delimiters):
        try:
            dialect = _csv.Sniffer().sniff(sample, delimiters=delimiters)
        except _csv.Error:
            dialect = _csv.excel
    probe = _csv.reader(_StringIO(raw), dialect=dialect)
    try:
        headers = next(probe)
    except StopIteration:
        return []
    headers = [str(h or "").strip() for h in headers]
    seen: set[str] = set()
    dups: list[str] = []
    for h in headers:
        if not h:
            continue
        if h in seen and h not in dups:
            dups.append(h)
        seen.add(h)
    if dups:
        raise ValueError(
            "CSV duplicate header name(s): "
            + ", ".join(dups[:8])
            + "; refusing a silent parse"
        )
    reader = _csv.DictReader(_StringIO(raw), dialect=dialect)
    out: list[dict[str, str]] = []
    for row in reader:
        if not row:
            continue
        out.append(
            {
                str(k).strip(): ("" if v is None else str(v))
                for k, v in row.items()
                if k is not None
            }
        )
    return out


_UTF16_BOMS = ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))


def decode_text(data: bytes) -> str:
    """Decode scanner output.

    UTF-16 (and UTF-32) with a byte-order mark is decoded as that encoding
    (PowerShell ``Out-File`` default). UTF-16 without a BOM is refused with
    UnrecognizedShape so callers never silent-zero or mojibake the file.
    Otherwise decode as UTF-8; a UTF-8 BOM is kept so callers that strip
    ``\ufeff`` keep existing behaviour.
    """
    if data[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return data.decode("utf-32", errors="replace")
    for bom, enc in _UTF16_BOMS:
        if data.startswith(bom):
            return data[len(bom):].decode(enc, errors="replace")
    # UTF-16 without a BOM (NUL in every other byte) -> clear error, no guessing
    head = data[:4096]
    if len(head) >= 8 and b"\x00" in head:
        half = len(head) // 2
        even, odd = head[0::2].count(0), head[1::2].count(0)
        if (odd > 0.3 * half and even < 0.05 * half) or (
            even > 0.3 * half and odd < 0.05 * half
        ):
            raise UnrecognizedShape(
                "looks like UTF-16 without a byte-order mark; re-export as UTF-8 (or UTF-16 with BOM)"
            )
    return data.decode("utf-8", errors="replace")


def read_text(path: Path) -> str:
    # Trailing NUL bytes invent ghost CSV rows under DictReader.
    return decode_text(path.read_bytes()).rstrip("\x00")


def read_json(path: Path) -> Any:
    raw = read_text(path).lstrip("\ufeff").strip()
    if not raw:
        raise json.JSONDecodeError("empty", raw, 0)
    return json.loads(raw)


JSONL_SKIPS: dict[str, list[int]] = {}


def read_jsonl(path: Path) -> list[Any]:
    rows: list[Any] = []
    skipped: list[int] = []
    # Strip a leading UTF-8 BOM so line 1 still parses as JSON.
    for lineno, line in enumerate(read_text(path).lstrip("\ufeff").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            skipped.append(lineno)
    if skipped:
        # Keep good rows; count and report skipped corrupt lines.
        JSONL_SKIPS[str(path)] = skipped
        msg = (
            f"{path.name}: skipped {len(skipped)} corrupt JSONL line(s): "
            f"{', '.join(map(str, skipped[:20]))}"
        )
        warnings.warn(msg, stacklevel=2)
        logging.getLogger("shared.io_util").warning(msg)
    return rows


def stable_hash(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return h[:12]


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact(data), indent=2) + "\n", encoding="utf-8", newline="\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact(text), encoding="utf-8", newline="\n")


def write_canonical(source: str, records: list[dict[str, Any]]) -> Path:
    dest = out_dir() / "canonical" / f"{slug(source, 64)}.jsonl"
    dest.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for rec in records:
        lines.append(json.dumps(redact(rec), separators=(",", ":")))
    dest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", newline="\n")
    return dest


def write_raw_copy(source: str, path: Path, parsed: Any | None = None) -> None:
    dest_dir = out_dir() / "raw" / slug(source, 64)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if parsed is not None:
        write_json(dest_dir / f"{path.stem}.parsed.json", parsed)
    else:
        text = redact(read_text(path))
        (dest_dir / path.name).write_text(text, encoding="utf-8", newline="\n")


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
    unread: list[Path] | None = None,
) -> dict[str, Any]:
    n_rec = len(records)
    unread = list(unread or [])
    n_files = len(files) + len(unread)
    issue_statuses = {str(item.get("status") or "") for item in issues}
    if used_demo and n_rec:
        status = "demo"
    elif "parse_error" in issue_statuses and n_rec == 0:
        status = "parse_error"
    elif UNRECOGNIZED_STATUS in issue_statuses and n_rec == 0:
        status = UNRECOGNIZED_STATUS
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
        "unread": [path.name for path in unread],
        "issues": issues,
    }


def _malformed_reason(path: Path) -> str | None:
    """Name truncated/invalid JSON or XML even when a parser swallows the exception."""
    try:
        raw = read_text(path).lstrip("\ufeff").strip()
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
    if suffix in {".xml", ".xccdf"}:
        try:
            ET.fromstring(raw)
        except ET.ParseError as exc:
            return f"ParseError: {exc}"
    return None


def refuse_if_malformed(path: Path, kind: str) -> None:
    """Raise ValueError naming the file when a parser got 0 rows from truncated/invalid input.

    An empty file stays a quiet 0-row result. Call only after the parser found nothing.
    """
    reason = _malformed_reason(path)
    if reason:
        raise ValueError(f"{path.name}: unparseable {kind} file (truncated or corrupt): {reason}")


def fail_closed(kind: str):
    """Decorator: a parse_file that returns no rows for malformed input raises instead."""

    def wrap(fn):
        def parse_file(path: Path) -> list[dict[str, Any]]:
            rows = fn(path)
            if not rows:
                refuse_if_malformed(Path(path), kind)
            return rows

        parse_file.__name__ = getattr(fn, "__name__", "parse_file")
        parse_file.__doc__ = fn.__doc__
        parse_file.__wrapped__ = fn  # type: ignore[attr-defined]
        return parse_file

    return wrap


def run_collector(
    source: str,
    suffixes: Iterable[str],
    parse_file,
    finalize=None,
) -> list[dict[str, Any]]:
    files, used_demo = load_inputs(source, suffixes)
    unread = unread_input_files(source, suffixes) if not used_demo else []
    records: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    for path in files:
        error: str | None = None
        unrecognized: str | None = None
        sidecar = False
        try:
            recs = list(parse_file(path) or [])
        except SidecarSkip as exc:
            recs = []
            sidecar = True
            write_raw_copy(
                source,
                path,
                {"sidecar": True, "file": path.name, "reason": exc.reason or str(exc)},
            )
        except UnrecognizedShape as exc:
            recs = []
            unrecognized = exc.reason or str(exc)
        except Exception as exc:
            recs = []
            error = f"{type(exc).__name__}: {exc}"
        if sidecar:
            continue
        skipped = JSONL_SKIPS.pop(str(path), None)
        if skipped and recs:
            issues.append(
                {
                    "status": "partial_parse",
                    "file": path.name,
                    "reason": (
                        f"skipped {len(skipped)} corrupt JSONL line(s): "
                        f"{', '.join(map(str, skipped[:20]))}"
                    ),
                }
            )
        if recs:
            records.extend(recs)
            write_raw_copy(source, path, recs)
            continue
        if unrecognized:
            issues.append(
                {"status": UNRECOGNIZED_STATUS, "file": path.name, "reason": unrecognized}
            )
            write_raw_copy(
                source,
                path,
                {"error": UNRECOGNIZED_STATUS, "file": path.name, "reason": unrecognized},
            )
            continue
        malformed = error or _malformed_reason(path)
        status = "parse_error" if malformed else "no_records"
        reason = malformed or "parser yielded no records"
        issues.append({"status": status, "file": path.name, "reason": reason})
        write_raw_copy(source, path, {"error": status, "file": path.name, "reason": reason})
    for path in unread:
        reason = unrecognized_reason(path, suffixes)
        issues.append(
            {"status": UNRECOGNIZED_STATUS, "file": path.name, "reason": reason}
        )
        write_raw_copy(
            source,
            path,
            {"error": UNRECOGNIZED_STATUS, "file": path.name, "reason": reason},
        )
    # Honesty: live files that fail or yield nothing never pull fixtures/demo.
    # Unread files are named above — do not collapse them to "empty sensor".
    if not files and not used_demo and not unread:
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
            unread=unread,
        )
    )
    return records
