"""Estate banner + one-page executive summary + SCOPE_AND_TRUST.md.

Argus drafts (2026-09-25) are the spec. Exactly one allowed label. Fail
closed to the most restrictive when unsure. SAMPLE/DEMO/LAB and any
product-lab/drop fallback cannot be suppressed and cannot become CLIENT.
Missing values print "not recorded". Human narrative slots stay marked
placeholders. No cycle/CoS/adapter-list/agent notes on client pages.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from shared.io_util import SKIP_INPUT_NAMES
from shared.scan_time import extra_scan_raw, format_detection_date

NOT_RECORDED = "not recorded"

# Most restrictive first. Unsure → SAMPLE (never CLIENT).
KIND_ORDER = ("MIXED", "SAMPLE", "DEMO", "LAB", "CLIENT")

LABEL_FOR_KIND = {
    "SAMPLE": "SAMPLE DATA: NOT A CLIENT",
    "DEMO": "DEMO: NOT A CLIENT",
    "LAB": "LAB: TEST ENVIRONMENT",
    "MIXED": "MIXED: REVIEW BEFORE USE",
}

SENTENCE_FOR_KIND = {
    "SAMPLE": (
        "Every finding below comes from bundled example files. "
        "None describes any real organization."
    ),
    "DEMO": (
        "Built from demo fixtures because no scanner output was supplied. "
        "None describes any real organization."
    ),
    "LAB": (
        "From scans of an Evergreen-controlled test environment. "
        "It does not describe your organization."
    ),
    "CLIENT": "From scanner output collected under the scope below.",
    "MIXED": (
        "Some outputs came from bundled sample files ({fallback_files}). "
        "Do not forward until they are removed."
    ),
}

# Human-written slots — never generated prose.
REVIEWER_WHAT_WE_FOUND = (
    "[reviewer: one to three plain sentences — not generated]"
)
REVIEWER_WHY_IT_MATTERS = (
    "[reviewer: one-sentence business impact — not generated]"
)
REVIEWER_NEXT_STEP = "[reviewer: one sentence — not generated]"
REVIEWER_NOT_REVIEWED = "not human-reviewed"

SAMPLE_AUTH = "No client authorization applies. No client systems were touched."

# Bookkeeping files are not scanner drops and are not hashed as fixtures.
_AUTH_FILENAMES = ("AUTHORIZATION.txt", "AUTHORIZATION.md", "AUTH.txt")
_HASH_SKIP_NAMES = frozenset(SKIP_INPUT_NAMES)
_AUTH_PLACEHOLDERS = frozenset(
    {"", "not recorded", "none", "null", "unknown", "n/a", "na", "-"}
)
_FIXTURE_HASH_CACHE: frozenset[str] | None = None
_PACK_DEMO_SCOPE = Path("dropbox") / "SCOPE.yaml"

CLIENT_PAGE_FORBIDDEN = (
    "cycle ",
    "CoS #",
    "COS4",
    "COS48",
    "adapter list",
    "agent process",
    "overnight",
    "pytest",
    "E2E_PROVEN",
    "list every collector folder",
    "if no one did, print",
    'print "not human-reviewed"',
    "print 'not human-reviewed'",
    "fell back to fixtures, by name",
)

# Generator instructions / unfilled template holes. [reviewer: …] slots stay.
INSTRUCTION_LEAKS = (
    "list every collector folder",
    "if no one did, print",
    'print "not human-reviewed"',
    "print 'not human-reviewed'",
    "fell back to fixtures, by name",
    "collected by not recorded",
    "[insert ",
    "[fill in",
    "{{",
    "todo:",
    "fixme",
)

CLIENT_FACING_RELS = (
    "EXECUTIVE_SUMMARY.md",
    "SCOPE_AND_TRUST.md",
    "poam/poam.md",
    "poam/ESTATE.txt",
    "ciso-assistant/ESTATE.txt",
    "opengrc/ESTATE.txt",
    "opengrc/README.md",
    "probo/ESTATE.txt",
    "probo/README.md",
    "MANIFEST",
)

# GNU coreutils: "<hash><two spaces><path>" (text) or "<hash><space>*<path>" (binary).
SHA256SUM_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")

COLLECTOR_AREAS = {
    "cloud": "Cloud configuration",
    "cloud-prowler": "Cloud configuration",
    "nmap": "Host / network exposure",
    "inventory-nmap": "Host / network exposure",
    "vuln": "Vulnerability scan",
    "vuln-scan": "Vulnerability scan",
    "wazuh": "Host coverage",
    "host-wazuh": "Host coverage",
    "mdm": "MDM inventory",
    "identity": "Identity",
    "identity-ad": "Identity",
    "easm": "External exposure",
    "k8s": "Kubernetes",
    "k8s-kubescape": "Kubernetes",
    "code": "Code secrets",
    "code-secrets": "Code secrets",
    "saas": "SaaS / identity",
    "saas-idp": "SaaS / identity",
    "honeypot": "Deception sensors",
    "dns_email": "DNS / email",
    "dns-email": "DNS / email",
}

AREA_HINTS = (
    ("identity", ("identity", "saas", "idp", "ad", "entra", "okta")),
    ("external exposure", ("easm", "nmap", "exposure", "honeypot", "dns")),
    ("cloud configuration", ("cloud", "prowler", "k8s", "kubescape")),
    ("code secrets", ("code", "secret", "gitleaks", "truffle", "sast")),
)

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_TABLE = ("critical", "high", "medium", "low", "info")

MAX_EXEC_BODY_ROWS = {
    "top_n": 5,
    "areas": 4,
}
# One printed page: keep banner + limits; cut table rows if needed.
MAX_PAGE_LINES = 58
MAX_COVERAGE_GAP_ROWS = 4
COVERAGE_GAPS_NONE = "None. Every sensor that received input was assessed."
COVERAGE_GAPS_HEADING = "### Coverage gaps"

EXPORT_CSV_REL = (
    "poam/poam.csv",
    "poam/excluded.csv",
    "ciso-assistant/assets.csv",
    "ciso-assistant/applied_controls.csv",
    "ciso-assistant/evidences.csv",
    "ciso-assistant/findings.csv",
    "ciso-assistant/vulnerabilities.csv",
    "ciso-assistant/risk_scenarios.csv",
    "opengrc/risks.csv",
    "opengrc/assets.csv",
    "opengrc/implementations.csv",
)
EXPORT_MD_REL = (
    "EXECUTIVE_SUMMARY.md",
    "SCOPE_AND_TRUST.md",
    "poam/poam.md",
    "poam/ESTATE.txt",
    "ciso-assistant/ESTATE.txt",
    "opengrc/ESTATE.txt",
    "opengrc/README.md",
    "probo/ESTATE.txt",
    "probo/README.md",
)
EXPORT_OTHER_REL = (
    "import_preview/probo.json",
)


def recorded(value: Any) -> str:
    """Fill a placeholder from run data. Missing → 'not recorded'. Never invent."""
    if value is None:
        return NOT_RECORDED
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    if not text:
        return NOT_RECORDED
    if text.lower() in {"none", "null", "unknown", "n/a", "na", "-"}:
        return NOT_RECORDED
    return text


def _artifact_scan_stamp(rec: dict) -> str:
    """Artifact scan calendar day, or 'not recorded'. Never collected_at / pack now."""
    raw = extra_scan_raw(rec)
    if raw in (None, ""):
        return NOT_RECORDED
    return format_detection_date(raw)


def most_restrictive(*kinds: str) -> str:
    present = {k for k in kinds if k in KIND_ORDER}
    if not present:
        return "SAMPLE"
    for kind in KIND_ORDER:
        if kind in present:
            return kind
    return "SAMPLE"


def _env(env: dict[str, str] | None, key: str, default: str = "") -> str:
    src = env if env is not None else os.environ
    return str(src.get(key) or default).strip()


def _looks_non_client_name(name: str) -> bool:
    blob = name.strip().lower()
    if not blob:
        return True
    return any(tok in blob for tok in ("demo", "sample", "lab", "example", "not a client"))


def _client_name_from_scope() -> str:
    raw = _env(None, "GRC_CLIENT_NAME")
    if raw and not _looks_non_client_name(raw):
        return raw
    scope_path = _env(None, "GRC_SCOPE_PATH")
    candidates = []
    if scope_path:
        candidates.append(Path(scope_path))
    try:
        from shared.io_util import root_dir

        candidates.append(root_dir() / "dropbox" / "SCOPE.yaml")
    except Exception:
        pass
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            if line.strip().startswith("name:"):
                name = line.split(":", 1)[1].strip().strip("\"'")
                if name and not _looks_non_client_name(name):
                    return name
                return ""
    return ""


def pack_commit() -> str:
    raw = _env(None, "PACK_COMMIT") or _env(None, "GRC_PACK_COMMIT")
    if raw:
        return raw
    try:
        from shared.io_util import root_dir

        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(root_dir()),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return NOT_RECORDED
    out = (proc.stdout or "").strip()
    return out or NOT_RECORDED


def generated_at_local(iso_utc: str | None = None) -> str:
    raw = (iso_utc or "").strip()
    if raw:
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            local = stamp.astimezone()
            return local.strftime("%Y-%m-%d %H:%M %Z")
        except ValueError:
            pass
    now = datetime.now().astimezone()
    return now.strftime("%Y-%m-%d %H:%M %Z")


def run_id_from_records(records: list[dict] | None) -> str:
    raw = _env(None, "GRC_RUN_ID")
    if raw:
        return raw
    for rec in records or []:
        extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
        for key in ("run_id", "runId"):
            val = extra.get(key) or rec.get(key)
            if val:
                return str(val).strip()
    return NOT_RECORDED


def _marker_in(folder: Path | None, name: str) -> bool:
    if folder is None or not folder.is_dir():
        return False
    if (folder / name).is_file():
        return True
    try:
        return any(folder.rglob(name))
    except OSError:
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _hashable_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name.startswith("."):
        return False
    return path.name not in _HASH_SKIP_NAMES


def _try_canonical_json(text: str) -> bytes | None:
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        + b"\n"
    )


def _try_canonical_jsonl(text: str) -> bytes | None:
    rows = [ln.strip() for ln in text.split("\n") if ln.strip()]
    if len(rows) < 2:
        return None
    objs: list[Any] = []
    for ln in rows:
        if ln[0] not in "{[":
            return None
        try:
            objs.append(json.loads(ln))
        except (json.JSONDecodeError, ValueError, TypeError):
            return None
    out = bytearray()
    for obj in objs:
        out.extend(
            json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        )
        out.extend(b"\n")
    return bytes(out)


def normalize_fixture_bytes(data: bytes) -> bytes:
    """Strip BOM / EOL / trailing blank lines; canonicalize JSON(L) when parseable.

    Binary (NUL) bytes stay raw. Decode failure returns the original bytes so
    the raw hash still matches an exact fixture copy.
    """
    if b"\x00" in data[:8192]:
        return data
    body = data[3:] if data.startswith(b"\xef\xbb\xbf") else data
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return data
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip(" \t") for ln in text.split("\n")]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    joined = "\n".join(lines)
    canon = _try_canonical_json(joined)
    if canon is not None:
        return canon
    canon_l = _try_canonical_jsonl(joined)
    if canon_l is not None:
        return canon_l
    return (joined + ("\n" if joined else "")).encode("utf-8")


def file_content_fingerprints(path: Path) -> frozenset[str]:
    """Raw SHA-256 plus normalized content hash. Empty if the file is unreadable."""
    try:
        data = path.read_bytes()
        raw = _sha256_file(path)
    except OSError:
        return frozenset()
    return frozenset({raw, _sha256_bytes(normalize_fixture_bytes(data))})


def fixture_content_hashes(fixtures_root: Path | None = None) -> frozenset[str]:
    """SHA-256 set of bundled fixture fingerprints. Cached for the process.

    Catalog includes raw bytes and a whitespace/JSON-normalized hash so a
    SAMPLE copy that only gained a trailing newline cannot claim CLIENT.
    """
    global _FIXTURE_HASH_CACHE
    if fixtures_root is None and _FIXTURE_HASH_CACHE is not None:
        return _FIXTURE_HASH_CACHE
    try:
        from shared.io_util import root_dir

        root = fixtures_root or (root_dir() / "fixtures")
    except Exception:
        root = fixtures_root
    found: set[str] = set()
    if root is not None and root.is_dir():
        try:
            for path in root.rglob("*"):
                if not _hashable_file(path):
                    continue
                found.update(file_content_fingerprints(path))
        except OSError:
            pass
    result = frozenset(found)
    if fixtures_root is None:
        _FIXTURE_HASH_CACHE = result
    return result


def in_dir_fixture_hits(
    in_path: Path | None,
    *,
    fixtures_root: Path | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (fixture-matching relative paths, other input relative paths).

    Unreadable inputs and an empty fixture catalog fail closed: every scanner
    drop is treated as a fixture hit so classify_estate cannot claim CLIENT.
    """
    if in_path is None or not in_path.is_dir():
        return (), ()
    catalog = fixture_content_hashes(fixtures_root)
    hits: list[str] = []
    others: list[str] = []
    try:
        paths = [p for p in in_path.rglob("*") if _hashable_file(p)]
    except OSError:
        return ("<unreadable>",), ()
    if not catalog and paths:
        rels = []
        for path in paths:
            try:
                rels.append(str(path.relative_to(in_path)).replace("\\", "/"))
            except OSError:
                rels.append(path.name)
        return tuple(rels), ()
    for path in paths:
        try:
            rel = str(path.relative_to(in_path)).replace("\\", "/")
        except OSError:
            hits.append(path.name)
            continue
        fps = file_content_fingerprints(path)
        if not fps or (fps & catalog):
            hits.append(rel)
        else:
            others.append(rel)
    return tuple(hits), tuple(others)


def _looks_non_auth(value: str) -> bool:
    blob = str(value or "").strip().lower()
    if blob in _AUTH_PLACEHOLDERS:
        return True
    return any(
        tok in blob
        for tok in ("demo", "sample", "lab fixture", "not a client", "not recorded")
    )


def _parse_authorization_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower().lstrip("- ")
        val = val.strip().strip("\"'")
        if key in {"authorized by", "authorizer", "by"} and val:
            out["authorizer"] = val
        elif key in {"date", "authorized on", "on"} and val:
            out["date"] = val
        elif key in {"reference", "ref", "scope"} and val:
            out["ref"] = val
    return out


def client_authorization_record(
    env: dict[str, str] | None = None,
    in_dir: Path | None = None,
) -> dict[str, str] | None:
    """A CLIENT label needs a real authorization record, not just a name.

    Accepted evidence: GRC_AUTHORIZER + GRC_AUTH_DATE, or in/AUTHORIZATION.txt
    (or AUTHORIZATION.md / AUTH.txt) with those fields. DEMO / sample wording
    and the pack DEMO consent file never count.
    """
    src = env if env is not None else {k: str(v) for k, v in os.environ.items()}
    authorizer = str(src.get("GRC_AUTHORIZER") or "").strip()
    auth_date = str(src.get("GRC_AUTH_DATE") or "").strip()
    scope_ref = str(src.get("GRC_SCOPE_REF") or "").strip()
    if in_dir is not None and in_dir.is_dir():
        for name in _AUTH_FILENAMES:
            path = in_dir / name
            if not path.is_file():
                continue
            parsed = _parse_authorization_file(path)
            authorizer = authorizer or parsed.get("authorizer", "")
            auth_date = auth_date or parsed.get("date", "")
            scope_ref = scope_ref or parsed.get("ref", "")
    if _looks_non_auth(authorizer) or _looks_non_auth(auth_date):
        return None
    return {
        "authorizer": authorizer,
        "date": auth_date,
        "ref": scope_ref,
    }


def _is_pack_demo_scope(path: Path) -> bool:
    """True for the committed DEMO dropbox/SCOPE.yaml (or a copy of it)."""
    try:
        from shared.io_util import root_dir

        demo = (root_dir() / _PACK_DEMO_SCOPE).resolve()
        if path.resolve() == demo:
            return True
    except Exception:
        pass
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    blob = text.lower()
    return "demo-written-consent" in blob or "demo — not a client estate" in blob


def _fallback_from_records(records: list[dict]) -> list[str]:
    names: list[str] = []
    for rec in records:
        labels = [str(x).strip().lower() for x in (rec.get("labels") or [])]
        if "demo" not in labels and "sample" not in labels:
            continue
        src = str(rec.get("source") or "fixtures/demo").strip() or "fixtures/demo"
        if src not in names:
            names.append(src)
    return names


@dataclass
class EstateStamp:
    kind: str
    label: str
    sentence: str
    run_id: str = NOT_RECORDED
    generated_at_local: str = NOT_RECORDED
    pack_commit: str = NOT_RECORDED
    fallback_files: tuple[str, ...] = ()
    client_name: str = NOT_RECORDED

    def banner_md(self) -> str:
        return (
            f"> **{self.label}**: {self.sentence}\n"
            f"> Run `{self.run_id}` · generated {self.generated_at_local} · pack `{self.pack_commit}`"
        )

    def banner_lines(self) -> list[str]:
        return self.banner_md().splitlines()

    def banner_oneline(self) -> str:
        return f"{self.label}: {self.sentence}"

    def token(self) -> str:
        return f"estate_{self.kind.lower()}"


def classify_estate(
    records: list[dict] | None = None,
    *,
    in_dir: Path | None = None,
    fallback_files: Iterable[str] | None = None,
    env: dict[str, str] | None = None,
    client_name: str | None = None,
    generated_at: str | None = None,
    run_id: str | None = None,
    commit: str | None = None,
) -> EstateStamp:
    """Pick exactly one allowed label. Fail closed. Banner is never suppressible."""
    records = list(records or [])
    env = env if env is not None else {k: str(v) for k, v in os.environ.items()}
    # Suppression knobs are ignored on purpose.
    for banned in (
        "GRC_HIDE_ESTATE",
        "GRC_SUPPRESS_ESTATE",
        "GRC_ESTATE_OFF",
        "HIDE_ESTATE_BANNER",
    ):
        env.pop(banned, None)

    raw_label = str(env.get("GRC_ESTATE_LABEL") or "").strip().upper()
    signals: list[str] = []

    fb = [str(x).strip() for x in (fallback_files or []) if str(x).strip()]
    rec_fb = _fallback_from_records(records)
    for name in rec_fb:
        if name not in fb:
            fb.append(name)
    drop_fb = [x for x in fb if "product-lab/drop" in x.replace("\\", "/")]

    def _finding_like(rec: dict) -> bool:
        kind = str(rec.get("kind") or "").strip().lower()
        return kind in {"", "finding", "vulnerability", "observation"}

    scored = [rec for rec in records if _finding_like(rec)] or list(records)
    n_records = len(scored)
    n_demo = sum(
        1
        for rec in scored
        if "demo" in [str(x).strip().lower() for x in (rec.get("labels") or [])]
        or "sample" in [str(x).strip().lower() for x in (rec.get("labels") or [])]
    )
    mixed_records = n_records > 0 and 0 < n_demo < n_records

    in_path = in_dir
    if in_path is None:
        raw_in = str(env.get("IN_DIR") or "").strip()
        in_path = Path(raw_in) if raw_in else None

    lab_marker = _marker_in(in_path, "LAB.txt")
    # DROPBOX_DEMO=1 is the prove dry-run flag. It is SAMPLE only when the
    # run is not already labeled LAB (LAB.txt / GRC_ESTATE_LABEL=LAB).
    dropbox_demo = str(env.get("DROPBOX_DEMO") or "") == "1"
    sample_marker = _marker_in(in_path, "SAMPLE.txt")
    if dropbox_demo and raw_label not in {"LAB", "DEMO"} and not lab_marker:
        sample_marker = True

    fixture_hits, fixture_others = in_dir_fixture_hits(in_path)
    for rel in fixture_hits:
        if rel not in fb:
            fb.append(rel)
    # Fixture bytes forbid CLIENT (see client_ok). SAMPLE/MIXED only when the
    # run is not an explicit LAB dest_in — fixtures/lab-* is copied into in/
    # on the operator LAB path and must stay LAB, never a client KEEP.
    if fixture_hits and fixture_others:
        signals.append("MIXED")
    elif fixture_hits and raw_label != "LAB" and not lab_marker:
        signals.append("SAMPLE")

    if drop_fb and (mixed_records or n_demo < n_records or lab_marker):
        signals.append("MIXED")
    elif drop_fb:
        signals.append("SAMPLE")
    elif mixed_records:
        signals.append("MIXED")

    if sample_marker:
        signals.append("SAMPLE")
    if lab_marker:
        if mixed_records or drop_fb or (n_demo and n_demo < n_records):
            signals.append("MIXED")
        else:
            signals.append("LAB")

    if raw_label in {"SAMPLE", "DEMO", "LAB"}:
        signals.append(raw_label)

    if n_demo == n_records and n_records > 0:
        signals.append("DEMO" if raw_label != "SAMPLE" and not sample_marker else "SAMPLE")
    elif n_demo and not mixed_records:
        signals.append("DEMO")

    name = (client_name or "").strip() or _client_name_from_scope()
    if name and _looks_non_client_name(name):
        name = ""

    auth = client_authorization_record(env, in_path)
    has_client_artifacts = bool(n_records) or bool(fixture_others)

    kind = most_restrictive(*signals) if signals else "SAMPLE"

    client_ok = (
        raw_label == "CLIENT"
        and bool(name)
        and auth is not None
        and has_client_artifacts
        and not fixture_hits
        and not drop_fb
        and n_demo == 0
        and not lab_marker
        and not sample_marker
        and "SAMPLE" not in signals
        and "DEMO" not in signals
        and "LAB" not in signals
        and "MIXED" not in signals
    )
    if client_ok:
        kind = "CLIENT"
    else:
        kind = most_restrictive(*signals) if signals else "SAMPLE"

    if kind == "CLIENT" and (
        n_demo or drop_fb or lab_marker or sample_marker or raw_label in {"SAMPLE", "DEMO", "LAB"}
    ):
        kind = most_restrictive("SAMPLE", *signals)

    fb_display = ", ".join(fb) if fb else NOT_RECORDED
    if kind == "CLIENT":
        label = f"CLIENT: {name}"
        sentence = SENTENCE_FOR_KIND["CLIENT"]
        client_out = name
    else:
        label = LABEL_FOR_KIND[kind]
        sentence = SENTENCE_FOR_KIND[kind].format(fallback_files=fb_display)
        client_out = name or NOT_RECORDED

    return EstateStamp(
        kind=kind,
        label=label,
        sentence=sentence,
        run_id=recorded(run_id or run_id_from_records(records)),
        generated_at_local=recorded(generated_at_local(generated_at)),
        pack_commit=recorded(commit or pack_commit()),
        fallback_files=tuple(fb),
        client_name=client_out,
    )


def write_csv_with_estate(
    path: Path,
    header: list[str],
    rows: list[list[Any]],
    stamp: EstateStamp,
    *,
    delimiter: str = ",",
) -> None:
    """Exact importer header first. No # preamble. estate column only if listed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = list(header)
    estate_idx = cols.index("estate") if "estate" in cols else None
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter=delimiter, lineterminator="\n")
        writer.writerow(cols)
        for row in rows:
            cells = list(row)
            if len(cells) < len(cols):
                cells.extend([""] * (len(cols) - len(cells)))
            elif len(cells) > len(cols):
                cells = cells[: len(cols)]
            if estate_idx is not None:
                cells[estate_idx] = stamp.label
            writer.writerow(cells)


def write_estate_sidecar(sink_dir: Path, stamp: EstateStamp, *, note: str = "") -> Path:
    """Human-readable estate banner next to a CSV sink. Not suppressible."""
    dest = Path(sink_dir)
    dest.mkdir(parents=True, exist_ok=True)
    extra = (
        note.strip()
        if note.strip()
        else (
            "Machine-imported CSVs in this directory start with the importer "
            "header (no # preamble). SAMPLE/DEMO/LAB cannot be suppressed and "
            "is never client KEEP."
        )
    )
    path = dest / "ESTATE.txt"
    path.write_text(stamp.banner_md() + "\n\n" + extra + "\n", encoding="utf-8")
    return path


def prepend_banner_md(body: str, stamp: EstateStamp) -> str:
    banner = stamp.banner_md()
    text = body.lstrip("\n")
    heads = text.splitlines()[:3]
    if text.startswith("> **") and any(line.startswith("> Run `") for line in heads):
        rest = "\n".join(text.splitlines()[2:]).lstrip("\n")
        return banner + "\n\n" + rest
    if text.startswith(banner):
        return text if text.endswith("\n") else text + "\n"
    return banner + "\n\n" + text


def assert_banner_present(text: str, stamp: EstateStamp | None = None) -> None:
    blob = text
    if stamp is not None:
        if stamp.label not in blob:
            raise AssertionError(f"estate banner label missing: {stamp.label}")
        if stamp.sentence.split(".")[0] not in blob and stamp.sentence not in blob:
            raise AssertionError("estate banner sentence missing")
        return
    labels = list(LABEL_FOR_KIND.values()) + ["CLIENT:"]
    if not any(label in blob for label in labels):
        raise AssertionError("no allowed estate banner label in file")


def _sev(rec: dict) -> str:
    raw = str(rec.get("severity") or "").strip().lower()
    if raw in SEV_RANK:
        return raw
    return "low"


def _area_for(rec: dict) -> str:
    blob = " ".join(
        str(x or "")
        for x in (
            rec.get("category"),
            rec.get("source"),
            rec.get("name"),
        )
    ).lower()
    for area, hints in AREA_HINTS:
        if any(h in blob for h in hints):
            return area
    cat = str(rec.get("category") or rec.get("source") or "").strip()
    return COLLECTOR_AREAS.get(cat, cat or "other")


def _count_severities(items: Iterable[dict], key: str = "severity") -> dict[str, int]:
    out = {s: 0 for s in SEV_TABLE}
    for item in items:
        sev = str(item.get(key) or "").strip().lower()
        if sev in out:
            out[sev] += 1
    return out


def _dedupe_merged(before: int | None, after: int) -> str:
    if before is None:
        return NOT_RECORDED
    merged = max(0, int(before) - int(after))
    return str(merged)


def _risk_key(rec: dict, mapped: dict | None) -> tuple[int, int, int, str]:
    sev = _sev(rec)
    # Risk, not scanner severity alone: mapped POA&M inclusion + control refs.
    mapped = mapped or {}
    poam = 1 if mapped.get("include_poam") else 0
    refs = 1 if mapped.get("framework_refs") else 0
    return (SEV_RANK.get(sev, 9), -poam, -refs, str(rec.get("ref_id") or ""))


def _exec_top_findings(
    findings: list[dict],
    mapped_by_ref: dict[str, dict],
    n: int,
) -> list[dict]:
    """Top-N by risk, one row per host/port EGP (pack_drop id ≠ weakness)."""
    from shared.poam_ledger import fp_v1

    ranked: list[dict] = []
    seen: set[str] = set()
    def _exec_sort(rec: dict) -> tuple:
        sev, poam, refs, ref = _risk_key(rec, mapped_by_ref.get(str(rec.get("ref_id"))))
        extra = rec.get("extra") if isinstance(rec.get("extra"), dict) else {}
        port_first = 0 if str(extra.get("check_id") or "").startswith("nmap-port-") else 1
        return (sev, poam, refs, port_first, ref)

    ordered = sorted(findings, key=_exec_sort)
    for rec in ordered:
        ident = fp_v1(rec)
        if ident in seen:
            continue
        seen.add(ident)
        ranked.append(rec)
        if len(ranked) >= n:
            break
    return ranked


def _frameworks_used(mapped_by_ref: dict[str, dict]) -> str:
    names: list[str] = []
    blob = " ".join(
        str((m or {}).get("framework_refs") or "") for m in mapped_by_ref.values()
    )
    if "cpg_" in blob:
        names.append("CISA CPG")
    if "csf_" in blob:
        names.append("NIST CSF")
    if "nist80053_" in blob or "800-53" in blob:
        names.append("NIST SP 800-53")
    if "cis_" in blob:
        names.append("CIS Controls")
    return ", ".join(names) if names else NOT_RECORDED


def _records_by_source(records: list[dict] | None) -> dict[str, list[dict]]:
    by_source: dict[str, list[dict]] = {}
    for rec in records or []:
        src = str(rec.get("source") or "").strip()
        if not src:
            continue
        by_source.setdefault(src, []).append(rec)
    return by_source


def coverage_scope_rows(
    sensor_rows: list[dict] | None,
    records: list[dict] | None = None,
) -> list[dict[str, str]]:
    """One row per coverage sensor. In-scope iff that row has records.

    sensor_rows is the single source of truth. When collectors did not
    write coverage (loader-only tests), synthesize equivalent rows from
    the same record sources so in/out still partition one list.
    Fixtures with records are in scope (labelled SAMPLE/DEMO).
    """
    recs_by = _records_by_source(records)
    raw_rows = [row for row in (sensor_rows or []) if isinstance(row, dict) and row.get("source")]
    if not raw_rows:
        raw_rows = [
            {
                "source": src,
                "status": "ok",
                "records": len(items),
                "demo": any(
                    str(x).strip().lower() in {"demo", "sample"}
                    for x in (items[0].get("labels") or [])
                ),
            }
            for src, items in sorted(recs_by.items())
        ]
    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    for raw in raw_rows:
        src = str(raw.get("source") or "").strip()
        if not src or src in seen:
            continue
        seen.add(src)
        recs = recs_by.get(src, [])
        try:
            n_rec = int(raw.get("records"))
        except (TypeError, ValueError):
            n_rec = len(recs)
        extra0 = recs[0].get("extra") if recs and isinstance(recs[0].get("extra"), dict) else {}
        labels = [str(x).strip().lower() for x in ((recs[0].get("labels") if recs else None) or [])]
        demo = bool(raw.get("demo")) or "demo" in labels or "sample" in labels
        if n_rec > 0 and demo:
            targets = "bundled sample / fixture"
        elif n_rec > 0:
            targets = recorded(
                extra0.get("target") or extra0.get("targets") or "file supplied by client"
            )
        else:
            targets = recorded(None)
        rows.append(
            {
                "source": src,
                "area": COLLECTOR_AREAS.get(src, src),
                "targets": targets,
                "tool": recorded(extra0.get("tool") or extra0.get("scanner") or src),
                "version": recorded(extra0.get("version") or extra0.get("tool_version")),
                "collected": _artifact_scan_stamp(recs[0]) if recs else NOT_RECORDED,
                "records": str(n_rec),
                "in_scope": "true" if n_rec > 0 else "false",
                "status": str(raw.get("status") or ("ok" if n_rec else "empty")),
            }
        )
    return rows


def partition_scope(
    rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Disjoint in-scope / out-of-scope from the same coverage rows."""
    inside = [row for row in rows if row.get("in_scope") == "true"]
    outside = [row for row in rows if row.get("in_scope") != "true"]
    return inside, outside


def _out_of_scope_phrase(rows: list[dict[str, str]], outside: list[dict[str, str]]) -> str:
    if not rows:
        return NOT_RECORDED
    if not outside:
        return "none"
    names: list[str] = []
    for row in outside:
        name = row.get("area") or row.get("source") or ""
        if name and name not in names:
            names.append(name)
    return ", ".join(names) if names else NOT_RECORDED


def _dated_counts(records: list[dict]) -> tuple[int, int]:
    dated = sum(1 for rec in records if _artifact_scan_stamp(rec) != NOT_RECORDED)
    return dated, len(records)


def _reconcile(
    findings_n: int,
    poam_n: int,
    risk_n: int,
    *,
    vuln_n: int = 0,
    excluded_poam: int = 0,
    merged: str = NOT_RECORDED,
) -> str | None:
    if findings_n == poam_n == risk_n:
        return None
    reasons: list[str] = []
    if vuln_n and findings_n + vuln_n == risk_n:
        reasons.append(
            f"{vuln_n} vulnerability-class rows are counted on the risk register "
            "but not in findings.csv"
        )
    if excluded_poam:
        reasons.append(f"{excluded_poam} findings were not included in the POA&M")
    if merged not in {NOT_RECORDED, "0"} and merged.isdigit() and int(merged) > 0:
        reasons.append(f"{merged} duplicates were merged")
    if findings_n != poam_n and not excluded_poam:
        pass
    if reasons:
        return (
            f"{findings_n} findings produced {poam_n} POA&M rows and {risk_n} "
            f"risk-register entries because {'; '.join(reasons)}."
        )
    return "counts not reconciled"


def _read_scope_window(path: Path) -> tuple[str, str]:
    start = end = ""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return start, end
    for line in text.splitlines():
        if line.strip().startswith("start:"):
            start = start or line.split(":", 1)[1].strip().strip("\"'")
        if line.strip().startswith("end:"):
            end = end or line.split(":", 1)[1].strip().strip("\"'")
    return start, end


def _engagement_window(
    records: list[dict],
    *,
    kind: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Assessment window. Never inherit the DEMO SCOPE dates on non-DEMO runs."""
    src = env if env is not None else None
    start = _env(src, "GRC_SCAN_START")
    end = _env(src, "GRC_SCAN_END")
    if start or end:
        return recorded(start), recorded(end)
    scope_path = _env(src, "GRC_SCOPE_PATH")
    candidates: list[Path] = []
    if scope_path:
        candidates.append(Path(scope_path))
    if (kind or "").upper() == "DEMO":
        try:
            from shared.io_util import root_dir

            candidates.append(root_dir() / _PACK_DEMO_SCOPE)
        except Exception:
            pass
    for path in candidates:
        if not path.is_file():
            continue
        if (kind or "").upper() != "DEMO" and _is_pack_demo_scope(path):
            continue
        s, e = _read_scope_window(path)
        start = start or s
        end = end or e
        if start or end:
            break
    times: list[str] = []
    for rec in records:
        stamp = _artifact_scan_stamp(rec)
        if stamp != NOT_RECORDED:
            times.append(stamp)
    if times:
        return recorded(min(times)), recorded(max(times))
    return recorded(start), recorded(end)


def coverage_gap_rows(sensor_rows: list[dict] | None) -> list[dict[str, str]]:
    """Failed or empty sensors: name, files, reason. ok/demo are not gaps."""
    from shared.io_util import SENSOR_GAP_STATUSES, UNRECOGNIZED_STATUS

    gaps: list[dict[str, str]] = []
    for row in sensor_rows or []:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").strip()
        if status in {"ok", "demo"}:
            continue
        issues = row.get("issues") if isinstance(row.get("issues"), list) else []
        files: list[str] = []
        reasons: list[str] = []
        for item in issues:
            if not isinstance(item, dict):
                continue
            item_status = str(item.get("status") or "").strip()
            if item_status not in SENSOR_GAP_STATUSES and item_status != UNRECOGNIZED_STATUS:
                continue
            name = str(item.get("file") or "").strip() or "(no file)"
            files.append(name)
            reasons.append(str(item.get("reason") or item_status or status))
        if not files:
            if status not in SENSOR_GAP_STATUSES:
                continue
            files = ["(no file)"]
            reasons = [status]
        gaps.append(
            {
                "source": str(row.get("source") or "sensor"),
                "status": status or "empty",
                "files": ", ".join(files),
                "reason": reasons[0] if len(set(reasons)) == 1 else "; ".join(reasons),
            }
        )
    return gaps


def format_coverage_gaps(sensor_rows: list[dict] | None) -> list[str]:
    """Short Coverage gaps block. Long lists collapse to a count + out/coverage."""
    gaps = coverage_gap_rows(sensor_rows)
    lines = [COVERAGE_GAPS_HEADING]
    if not gaps:
        lines.append(COVERAGE_GAPS_NONE)
        return lines
    if len(gaps) > MAX_COVERAGE_GAP_ROWS:
        lines.append(
            f"{len(gaps)} sensors were not assessed (failed or empty). See `out/coverage`."
        )
        return lines
    for gap in gaps:
        lines.append(
            f"- {gap['source']}: {gap['files']} ({gap['status']} — {gap['reason']})"
        )
    return lines


@dataclass
class PageContext:
    stamp: EstateStamp
    records: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    poam_rows: list[dict] = field(default_factory=list)
    mapped_by_ref: dict[str, dict] = field(default_factory=dict)
    findings_csv_n: int = 0
    vuln_n: int = 0
    risk_n: int = 0
    poam_n: int = 0
    merged: str = NOT_RECORDED
    excluded_poam: int = 0
    in_dir: Path | None = None
    generated_at: str = ""
    run_delta: dict[str, int] = field(default_factory=dict)
    sensor_rows: list[dict] = field(default_factory=list)


def build_executive_summary(ctx: PageContext) -> str:
    stamp = ctx.stamp
    org = (
        stamp.client_name
        if stamp.kind == "CLIENT" and stamp.client_name != NOT_RECORDED
        else recorded(stamp.client_name if stamp.client_name != NOT_RECORDED else None)
    )
    scan_start, scan_end = _engagement_window(ctx.records, kind=stamp.kind)
    dated_n, dated_total = _dated_counts(ctx.records)
    find_sev = _count_severities(ctx.findings)
    poam_sev = _count_severities(ctx.poam_rows)
    # Duplicates merged are recorded only when the loader supplied a count.
    merged_total = ctx.merged
    merged_by = {s: merged_total if s == "critical" else NOT_RECORDED for s in SEV_TABLE}
    # Per-severity merge is not tracked; print not recorded rather than invent 0.
    merged_by = {s: NOT_RECORDED for s in SEV_TABLE}

    lines = [
        stamp.banner_md(),
        "",
        f"**{stamp.label}**. {org}. Assessment window {scan_start} to {scan_end} ({dated_n} of {dated_total} rows dated).",
        "",
        "### What we found",
        REVIEWER_WHAT_WE_FOUND,
        "",
        "| Severity | Findings | In POA&M | Duplicates merged |",
        "|---|---|---|---|",
    ]
    tot_f = tot_p = 0
    for sev in SEV_TABLE:
        n_f = find_sev[sev]
        n_p = poam_sev[sev]
        tot_f += n_f
        tot_p += n_p
        lines.append(f"| {sev.title()} | {n_f} | {n_p} | {merged_by[sev]} |")
    lines.append(f"| **Total** | {tot_f} | {tot_p} | {merged_total} |")
    lines.append("")
    if ctx.run_delta:
        lines.append(
            "Changed since last run: "
            f"open={int(ctx.run_delta.get('open') or 0)} "
            f"new={int(ctx.run_delta.get('new') or 0)} "
            f"pending verification={int(ctx.run_delta.get('pending_verification') or 0)} "
            f"reopened={int(ctx.run_delta.get('reopened') or 0)} "
            f"closed={int(ctx.run_delta.get('closed') or 0)}."
        )
        lines.append("")
    recon = _reconcile(
        tot_f,
        ctx.poam_n or tot_p,
        ctx.risk_n or tot_f,
        vuln_n=ctx.vuln_n,
        excluded_poam=ctx.excluded_poam,
        merged=ctx.merged,
    )
    if recon:
        lines.append(recon)
        lines.append("")

    ranked = _exec_top_findings(
        ctx.findings, ctx.mapped_by_ref, MAX_EXEC_BODY_ROWS["top_n"]
    )
    lines.extend(
        [
            "### Fix these first (top 5 by risk, not by scanner severity alone)",
            "| # | Weakness | Affected | Why it matters | Recommended action | Finding ref |",
            "|---|---|---|---|---|---|",
        ]
    )
    for i, rec in enumerate(ranked, 1):
        mapped = ctx.mapped_by_ref.get(str(rec.get("ref_id"))) or {}
        weakness = recorded(rec.get("name") or rec.get("ref_id"))
        assets = rec.get("assets") or []
        affected = recorded("|".join(str(a) for a in assets) if assets else None)
        action = recorded(mapped.get("recommended_fix"))
        ref = recorded(rec.get("ref_id"))
        lines.append(
            f"| {i} | {weakness} | {affected} | {REVIEWER_WHY_IT_MATTERS} | {action} | `{ref}` |"
        )
    if not ranked:
        lines.append(
            f"| 1 | {NOT_RECORDED} | {NOT_RECORDED} | {REVIEWER_WHY_IT_MATTERS} | {NOT_RECORDED} | `{NOT_RECORDED}` |"
        )
    lines.append("")

    area_counts: dict[str, list[dict]] = {}
    for rec in ctx.findings:
        area_counts.setdefault(_area_for(rec), []).append(rec)
    top_areas = sorted(area_counts.items(), key=lambda kv: (-len(kv[1]), kv[0]))[
        : MAX_EXEC_BODY_ROWS["areas"]
    ]
    lines.append("### Where the risk concentrates")
    if not top_areas:
        lines.append(f"{NOT_RECORDED}: {NOT_RECORDED} findings, mapped to {NOT_RECORDED}.")
    else:
        for area, recs in top_areas:
            refs: list[str] = []
            for rec in recs:
                mapped = ctx.mapped_by_ref.get(str(rec.get("ref_id"))) or {}
                raw = str(mapped.get("framework_refs") or "").strip()
                for tok in raw.replace(";", ",").split(","):
                    tok = tok.strip()
                    if tok and tok not in refs:
                        refs.append(tok)
            ref_s = ", ".join(refs[:8]) if refs else NOT_RECORDED
            lines.append(f"{area}: {len(recs)} findings, mapped to {ref_s}.")
    lines.append("")

    coverage_rows = coverage_scope_rows(ctx.sensor_rows, ctx.records)
    _, outside = partition_scope(coverage_rows)
    uncovered_s = _out_of_scope_phrase(coverage_rows, outside)
    owner_who = (
        "the client"
        if stamp.kind == "CLIENT"
        else "the operator"
    )
    lines.extend(
        [
            "### What this does not tell you",
            f"- {uncovered_s}. These areas were out of scope or had no scanner output. See the scope statement.",
            "- This is a point-in-time review of scanner artifacts. It is not a penetration test and not continuous monitoring.",
            f"- Owners and due dates in the POA&M are blank until {owner_who} assigns them.",
            "",
            *format_coverage_gaps(ctx.sensor_rows),
            "",
            "### Next step",
            REVIEWER_NEXT_STEP,
            "",
            "Companion files: `poam.csv`, `risk_register` (`ciso/risk_scenarios.csv`), the scope and trust statement, and `MANIFEST` (hashes).",
            "",
        ]
    )
    return _fit_one_page(
        "\n".join(lines),
        keep_tails=(
            "### What this does not tell you",
            COVERAGE_GAPS_HEADING,
            "### Next step",
            "Companion files:",
        ),
    )


def build_scope_and_trust(ctx: PageContext) -> str:
    stamp = ctx.stamp
    lines = [
        stamp.banner_md(),
        "",
        f"**{stamp.label}**. Run `{stamp.run_id}`, pack `{stamp.pack_commit}`, generated {stamp.generated_at_local}.",
        "",
        "### Authorization",
    ]
    if stamp.kind in {"SAMPLE", "DEMO", "LAB", "MIXED"}:
        lines.append(f"- {SAMPLE_AUTH}")
    else:
        auth = client_authorization_record(None, ctx.in_dir)
        authorizer = recorded((auth or {}).get("authorizer") or _env(None, "GRC_AUTHORIZER"))
        auth_date = recorded((auth or {}).get("date") or _env(None, "GRC_AUTH_DATE"))
        scope_ref = recorded((auth or {}).get("ref") or _env(None, "GRC_SCOPE_REF"))
        lines.append(
            f"- Authorized by: {authorizer} on {auth_date}. Reference: {scope_ref}."
        )
    lines.extend(
        [
            "",
            "### What was in scope",
            "| Area | Targets / source | Scanner or export used | Version | Collected (date/time) | Records |",
            "|---|---|---|---|---|---|",
        ]
    )
    coverage_rows = coverage_scope_rows(ctx.sensor_rows, ctx.records)
    inside, outside = partition_scope(coverage_rows)
    if not inside:
        lines.append(
            f"| {NOT_RECORDED} | {NOT_RECORDED} | {NOT_RECORDED} | {NOT_RECORDED} | {NOT_RECORDED} | {NOT_RECORDED} |"
        )
    else:
        for row in inside:
            lines.append(
                f"| {row['area']} | {row['targets']} | {row['tool']} | {row['version']} | {row['collected']} | {row['records']} |"
            )
    lines.append("")
    lines.append(
        "Out of scope, or no data supplied: " + _out_of_scope_phrase(coverage_rows, outside) + "."
    )
    lines.append("")
    lines.extend(format_coverage_gaps(ctx.sensor_rows))
    lines.append("")
    who = recorded(_env(None, "GRC_COLLECTED_BY"))
    merged = recorded(ctx.merged if ctx.merged != "0" else ctx.merged)
    frameworks = _frameworks_used(ctx.mapped_by_ref)
    reviewer = recorded(_env(None, "GRC_REVIEWER"))
    if reviewer == NOT_RECORDED:
        reviewer = REVIEWER_NOT_REVIEWED
    if who == NOT_RECORDED:
        method_1 = (
            "1. Scanner output was supplied as files. The pack parses files only. "
            "It does not run exploits, log in to client systems, or call client APIs."
        )
    else:
        method_1 = (
            f"1. Scanner output was supplied as files, or collected by {who} "
            "under the authorization above. The pack parses files only. "
            "It does not run exploits, log in to client systems, or call client APIs."
        )
    lines.extend(
        [
            "### Method",
            method_1,
            f"2. Each result is normalized, and duplicates are merged ({merged} merged).",
            f"3. Each finding is mapped to controls ({frameworks}) using a per-finding rule table, not by severity.",
            "4. Severity is taken from the source tool and adjusted only where noted in the finding's `severity_rationale`.",
            f"5. A human reviewer ({reviewer}) checked the top findings and the recommended actions before release.",
            "",
            "### What the labels mean",
            "CLIENT is authorized scanner output. LAB is an Evergreen test environment. SAMPLE/DEMO is bundled example data. MIXED includes bundled sample files and is not client-ready.",
            "",
            "### Limits (read before relying on this)",
            "Covers only the listed scanners at collection time. A clean area is not proof of safety. Control mappings are advisory, not an audit. Secrets are redacted. Nothing was uploaded to a GRC platform.",
            "",
            "### Integrity and traceability",
            "- Every POA&M row carries a `ref_id` that links to its finding and to the raw artifact under `evidence/`.",
            f"- SHA-256 hashes for every exported file are in `MANIFEST`. Verify with `{recorded(_env(None, 'GRC_VERIFY_COMMAND') or 'sha256sum -c MANIFEST')}`.",
            f"- Contact for questions or corrections: {recorded(_env(None, 'GRC_CONTACT'))}.",
            "",
        ]
    )
    return _fit_one_page(
        "\n".join(lines),
        keep_tails=(
            COVERAGE_GAPS_HEADING,
            "### Limits (read before relying on this)",
            "### Integrity and traceability",
            "### What the labels mean",
        ),
    )


def _scope_table_indexes(lines: list[str]) -> set[int]:
    """Banner + in-scope table + out-of-scope line. Never drop these to fit a page."""
    protected: set[int] = set()
    in_table = False
    for i, line in enumerate(lines):
        if line.startswith("> **") or line.startswith("> Run `"):
            protected.add(i)
        if line.startswith("### What was in scope"):
            in_table = True
            protected.add(i)
            continue
        if in_table:
            protected.add(i)
            if line.startswith("Out of scope") or (
                line.startswith("### ") and not line.startswith("### What was in scope")
            ):
                in_table = False
        elif line.startswith("Out of scope"):
            protected.add(i)
    return protected


def _fit_one_page(text: str, *, keep_tails: tuple[str, ...]) -> str:
    lines = text.splitlines()
    if len(lines) <= MAX_PAGE_LINES:
        return text if text.endswith("\n") else text + "\n"
    protected = _scope_table_indexes(lines)
    keep_idx: set[int] = set(protected)
    for needle in keep_tails:
        for i, line in enumerate(lines):
            if line.startswith(needle):
                keep_idx.add(i)
                break
    # Shrink non-sensor sections first. Never cut in-scope sensor rows.
    body: list[str] = []
    table_rows_kept = 0
    in_scope_table = False
    for i, line in enumerate(lines):
        if line.startswith("### What was in scope"):
            in_scope_table = True
        elif in_scope_table and (
            line.startswith("Out of scope")
            or (line.startswith("### ") and not line.startswith("### What was in scope"))
        ):
            in_scope_table = False
        is_data_row = (
            line.startswith("| ")
            and not line.startswith("|---")
            and "Severity" not in line
            and "Weakness" not in line
            and "Area |" not in line
        )
        if is_data_row and not in_scope_table:
            if table_rows_kept >= 12 and i not in keep_idx:
                continue
            table_rows_kept += 1
        body.append(line)
        if len(body) >= MAX_PAGE_LINES:
            rest = lines[i + 1 :]
            # Pull any remaining protected scope rows that have not been copied.
            for j in range(i + 1, len(lines)):
                if j in protected and lines[j] not in body:
                    body.append(lines[j])
            for needle in keep_tails:
                if any(x.startswith(needle) for x in body):
                    continue
                for extra in rest:
                    if extra.startswith(needle):
                        body.append(extra)
                        break
            break
    # If still over, drop non-sensor detail lines (never banner, table, or OOS).
    while len(body) > MAX_PAGE_LINES:
        drop_at = None
        for idx, line in enumerate(body):
            if line.startswith("> **") or line.startswith("> Run `"):
                continue
            if line.startswith("### ") or line.startswith("Out of scope"):
                continue
            if line.startswith("|"):
                continue
            drop_at = idx
            if line.strip() == "":
                break
        if drop_at is None:
            break
        body.pop(drop_at)
    out = "\n".join(body)
    return out if out.endswith("\n") else out + "\n"


def write_client_pages(out: Path, ctx: PageContext) -> dict[str, str]:
    dest = Path(out)
    dest.mkdir(parents=True, exist_ok=True)
    exec_text = build_executive_summary(ctx)
    trust_text = build_scope_and_trust(ctx)
    for blob in (exec_text, trust_text):
        low = blob.lower()
        for tok in CLIENT_PAGE_FORBIDDEN:
            if tok.lower() in low:
                raise ValueError(f"client page leaked internal token: {tok}")
    exec_path = dest / "EXECUTIVE_SUMMARY.md"
    trust_path = dest / "SCOPE_AND_TRUST.md"
    exec_path.write_text(exec_text, encoding="utf-8")
    trust_path.write_text(trust_text, encoding="utf-8")
    return {"executive_summary": str(exec_path), "scope_and_trust": str(trust_path)}


def write_export_manifest(out: Path, stamp: EstateStamp | None = None) -> Path:
    """Write `out/MANIFEST` last in GNU sha256sum format. Never list itself."""
    dest = Path(out)
    dest.mkdir(parents=True, exist_ok=True)
    manifest_path = dest / "MANIFEST"
    if manifest_path.is_file():
        manifest_path.unlink()
    rels = list(EXPORT_CSV_REL) + list(EXPORT_MD_REL) + list(EXPORT_OTHER_REL)
    lines: list[str] = []
    for rel in rels:
        rel_posix = str(rel).replace("\\", "/")
        if rel_posix == "MANIFEST" or Path(rel_posix).name == "MANIFEST":
            continue
        path = dest / rel_posix
        if not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {rel_posix}")
    manifest_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return manifest_path


def parse_scope_table_areas(trust_text: str) -> list[str]:
    areas: list[str] = []
    in_table = False
    for line in trust_text.splitlines():
        if line.startswith("### What was in scope"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("Out of scope") or line.startswith("### "):
            break
        if not line.startswith("|") or line.startswith("|---") or "Area |" in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and cells[0] and cells[0] != NOT_RECORDED:
            areas.append(cells[0])
    return areas


def parse_out_of_scope_names(trust_text: str) -> list[str]:
    for line in trust_text.splitlines():
        if not line.startswith("Out of scope"):
            continue
        payload = line.split(":", 1)[-1].strip().rstrip(".")
        if payload in {NOT_RECORDED, "none", ""}:
            return []
        return [part.strip() for part in payload.split(",") if part.strip()]
    return []


def iter_client_facing_texts(out: Path) -> list[tuple[str, str]]:
    dest = Path(out)
    found: list[tuple[str, str]] = []
    for rel in CLIENT_FACING_RELS:
        path = dest / rel
        if path.is_file():
            found.append((rel, path.read_text(encoding="utf-8")))
    return found


def assert_no_instruction_text(out: Path) -> None:
    for rel, text in iter_client_facing_texts(out):
        low = text.lower()
        for phrase in INSTRUCTION_LEAKS:
            if phrase.lower() in low:
                raise AssertionError(f"{rel} leaked instruction text: {phrase}")


def assert_scope_from_coverage(out: Path, sensor_rows: list[dict] | None = None) -> None:
    dest = Path(out)
    trust_path = dest / "SCOPE_AND_TRUST.md"
    if not trust_path.is_file():
        raise AssertionError("SCOPE_AND_TRUST.md missing")
    trust = trust_path.read_text(encoding="utf-8")
    if len(trust.splitlines()) > MAX_PAGE_LINES:
        raise AssertionError(
            f"SCOPE_AND_TRUST.md exceeds one printed page: {len(trust.splitlines())} > {MAX_PAGE_LINES}"
        )
    inside_areas = parse_scope_table_areas(trust)
    outside_names = parse_out_of_scope_names(trust)
    overlap = set(inside_areas) & set(outside_names)
    if overlap:
        raise AssertionError(f"scope contradiction: {sorted(overlap)} listed in and out of scope")
    rows = list(sensor_rows or [])
    if not rows:
        cov = dest / "coverage" / "sensors"
        if cov.is_dir():
            from shared.io_util import load_sensor_coverage

            rows = load_sensor_coverage(dest)
    if not rows:
        return
    derived = coverage_scope_rows(rows)
    want_in = [COLLECTOR_AREAS.get(r["source"], r["source"]) for r in derived if r["in_scope"] == "true"]
    want_out = [COLLECTOR_AREAS.get(r["source"], r["source"]) for r in derived if r["in_scope"] != "true"]
    if set(inside_areas) != set(want_in):
        raise AssertionError(
            f"in-scope table {inside_areas} != coverage rows {want_in}"
        )
    if set(outside_names) != set(want_out):
        raise AssertionError(
            f"out-of-scope {outside_names} != coverage rows {want_out}"
        )
    for src in ("vuln-scan", "saas-idp"):
        match = next((r for r in derived if r["source"] == src), None)
        if match is None:
            continue
        area = match["area"]
        if match["in_scope"] == "true" and area not in inside_areas:
            raise AssertionError(f"{src} produced records but was cut from the scope table")
        if match["in_scope"] != "true" and area not in outside_names:
            raise AssertionError(f"{src} has no records but is missing from out of scope")


def assert_manifest_sha256sum(out: Path) -> None:
    dest = Path(out)
    manifest = dest / "MANIFEST"
    if not manifest.is_file():
        raise AssertionError("MANIFEST missing")
    text = manifest.read_text(encoding="utf-8")
    parsed: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = SHA256SUM_LINE.match(line)
        if not match:
            raise AssertionError(f"MANIFEST is not sha256sum format: {line!r}")
        digest, rel = match.group(1), match.group(2)
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise AssertionError(f"MANIFEST path must be relative: {rel!r}")
        if rel == "MANIFEST" or Path(rel).name == "MANIFEST":
            raise AssertionError("MANIFEST must not list itself")
        parsed.append((digest, rel))
    if not parsed:
        raise AssertionError("MANIFEST has no checksum lines")
    try:
        proc = subprocess.run(
            ["sha256sum", "-c", "MANIFEST"],
            cwd=str(dest),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssertionError(f"sha256sum -c MANIFEST could not run: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise AssertionError(f"sha256sum -c MANIFEST failed: {detail}")


def assert_client_export_honesty(out: Path, sensor_rows: list[dict] | None = None) -> None:
    """Four cold-review locks: partition, no instructions, all sensors, MANIFEST."""
    dest = Path(out)
    assert_scope_from_coverage(dest, sensor_rows)
    assert_no_instruction_text(dest)
    assert_manifest_sha256sum(dest)


def stamp_text_file(path: Path, stamp: EstateStamp, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(prepend_banner_md(body, stamp), encoding="utf-8")
