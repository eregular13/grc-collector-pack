"""Fail-closed keep-package check for cold SAMPLE→SoR.

Not an operator entrypoint. Scripts and MCP call this before
``python -m keep lab`` / ``from keep.lab`` so a partial copy or
corrupt cold-path-gate tree cannot surface as ModuleNotFoundError.
"""

from __future__ import annotations

import json
import os
import sys
import zipfile
from pathlib import Path

KEEP_PACKAGE_FILES = (
    "keep/__main__.py",
    "keep/lab.py",
    "keep/adapters.py",
)
# Four SAMPLE keep-samples family files. Incomplete tree must fail closed
# (#98/#99 style) instead of emitting a hollow risk register.
KEEP_SAMPLES_PREFIX = "fixtures/keep-samples"
KEEP_SAMPLE_LEAVES = (
    "identity/hardeningkitty.csv",
    "saas/maester.json",
    "vuln/testssl.json",
    "cloud/prowler.json",
)
KEEP_SAMPLE_FILES = tuple(f"{KEEP_SAMPLES_PREFIX}/{rel}" for rel in KEEP_SAMPLE_LEAVES)
KEEP_CLAIM_NAMES = ("CLAIM.json", "claim.json", "manifest.json", "keep-claim.json")
KEEP_ZIP_NAMES = ("keep-package.zip", "keep.zip")
KEEP_PACKAGE_SCHEMA = "keep.package.v1"

KEEP_FAIL_INCOMPLETE = "KEEP_FIXTURE_INCOMPLETE"
KEEP_FAIL_MISSING_LEAF = "KEEP_FIXTURE_MISSING_LEAF"
KEEP_FAIL_EMPTY = "KEEP_FIXTURE_EMPTY"
KEEP_FAIL_TRUNCATED_JSON = "KEEP_FIXTURE_TRUNCATED_JSON"
KEEP_FAIL_GARBAGE_BINARY = "KEEP_FIXTURE_GARBAGE_BINARY"
KEEP_FAIL_WRONG_SCHEMA = "KEEP_FIXTURE_WRONG_SCHEMA"
KEEP_FAIL_CLAIM_MISMATCH = "KEEP_FIXTURE_CLAIM_MISMATCH"
KEEP_FAIL_CORRUPT_ZIP = "KEEP_FIXTURE_CORRUPT_ZIP"

KEEP_PACKAGE_CLONE = "eregular13/grc-collector-pack"
KEEP_PACKAGE_HINT = (
    "Checkout must be a full git clone of eregular13/grc-collector-pack "
    "(not a partial copy / corrupt cold-path-gate tree)."
)


class KeepPackageIncomplete(Exception):
    """keep package files missing or PYTHONPATH does not include the clone root."""


class KeepFixtureError(Exception):
    """SAMPLE keep-samples fixture missing, empty, or malformed. Carries a stable code."""

    def __init__(self, message: str, code: str = KEEP_FAIL_INCOMPLETE, path: str = ""):
        self.code = code
        self.path = path
        super().__init__(message)


class KeepFixtureIncomplete(KeepFixtureError):
    """SAMPLE keep-samples fixture missing or empty."""


class KeepFixtureMalformed(KeepFixtureError):
    """SAMPLE keep-samples fixture present but unparseable / dishonest."""


def missing_keep_package_files(root: Path) -> list[str]:
    """Return required keep paths that are not files under root."""
    root = Path(root)
    missing: list[str] = []
    for rel in KEEP_PACKAGE_FILES:
        path = root / rel
        if not path.is_file():
            missing.append(str(path))
    return missing


def pythonpath_includes_root(root: Path, pythonpath: str | None = None) -> bool:
    """True when PYTHONPATH lists the clone root (scripts export this)."""
    raw = os.environ.get("PYTHONPATH", "") if pythonpath is None else pythonpath
    if not raw:
        return False
    resolved = Path(root).resolve()
    for part in raw.split(os.pathsep):
        if not part:
            continue
        if Path(part).resolve() == resolved:
            return True
    return False


def keep_package_incomplete_message(
    root: Path,
    missing: list[str] | None = None,
    *,
    pythonpath_ok: bool | None = None,
) -> str:
    """Short operator message. Names the missing path. Full-clone hint."""
    root = Path(root)
    missing = list(missing) if missing is not None else missing_keep_package_files(root)
    if missing:
        named = missing[0]
        extra = f" (and {len(missing) - 1} more)" if len(missing) > 1 else ""
        return (
            f"keep package incomplete: missing {named}{extra}. "
            f"{KEEP_PACKAGE_HINT}"
        )
    if pythonpath_ok is False:
        return (
            f"keep package PYTHONPATH does not include {root} "
            f"(keep is not importable). {KEEP_PACKAGE_HINT}"
        )
    return f"keep package incomplete under {root}. {KEEP_PACKAGE_HINT}"


def check_keep_package(
    root: Path,
    *,
    pythonpath: str | None = None,
    require_pythonpath: bool = False,
) -> dict[str, object]:
    """Inspect root. Does not import keep (keep may be the missing package)."""
    root = Path(root)
    missing = missing_keep_package_files(root)
    path_ok = pythonpath_includes_root(root, pythonpath)
    ok = not missing and (path_ok if require_pythonpath else True)
    message = ""
    if not ok:
        message = keep_package_incomplete_message(
            root,
            missing,
            pythonpath_ok=path_ok if require_pythonpath else None,
        )
    return {
        "ok": ok,
        "root": str(root),
        "missing": missing,
        "pythonpath_ok": path_ok,
        "message": message,
    }


def require_keep_package(
    root: Path,
    *,
    pythonpath: str | None = None,
    require_pythonpath: bool = False,
) -> Path:
    """Raise KeepPackageIncomplete when the checkout cannot run ``python -m keep``."""
    report = check_keep_package(
        root,
        pythonpath=pythonpath,
        require_pythonpath=require_pythonpath,
    )
    if not report["ok"]:
        raise KeepPackageIncomplete(str(report["message"]))
    return Path(root)


def keep_samples_root(root: Path, samples_dir: Path | None = None) -> Path:
    """Directory that holds the four SAMPLE family leaves (or a stress overlay)."""
    if samples_dir is not None:
        return Path(samples_dir)
    return Path(root) / KEEP_SAMPLES_PREFIX


def _sample_leaf_rel(rel: str) -> str:
    prefix = KEEP_SAMPLES_PREFIX + "/"
    text = str(rel).replace("\\", "/")
    if text.startswith(prefix):
        return text[len(prefix) :]
    return text


def sample_leaf_path(root: Path, rel: str, samples_dir: Path | None = None) -> Path:
    return keep_samples_root(root, samples_dir) / _sample_leaf_rel(rel)


def missing_keep_sample_files(
    root: Path, samples_dir: Path | None = None
) -> list[str]:
    """Return required keep-samples paths that are missing or empty."""
    missing: list[str] = []
    for rel in KEEP_SAMPLE_LEAVES:
        path = sample_leaf_path(root, rel, samples_dir)
        if not path.is_file() or path.stat().st_size == 0:
            missing.append(str(path))
    return missing


def keep_samples_incomplete_message(
    root: Path,
    missing: list[str] | None = None,
    *,
    samples_dir: Path | None = None,
    code: str = KEEP_FAIL_INCOMPLETE,
    empty: bool = False,
) -> str:
    """Short operator message. Names the missing fixture. Full-clone hint."""
    root = Path(root)
    missing = (
        list(missing)
        if missing is not None
        else missing_keep_sample_files(root, samples_dir)
    )
    verb = "empty" if empty else "missing"
    if missing:
        named = Path(missing[0]).as_posix()
        extra = f" (and {len(missing) - 1} more)" if len(missing) > 1 else ""
        return (
            f"{code}: keep fixture incomplete: {verb} {named}{extra}. "
            f"SAMPLE keep-samples must include all four families. {KEEP_PACKAGE_HINT}"
        )
    return f"{code}: keep fixture incomplete under {root}. {KEEP_PACKAGE_HINT}"


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    probe = data[:4096]
    if b"\x00" in probe:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    textish = sum(1 for byte in probe if byte >= 32 or byte in (9, 10, 13))
    return textish / len(probe) < 0.75


def _issue(code: str, detail: str, path: Path | str = "") -> dict[str, str]:
    named = Path(path).as_posix() if path else ""
    suffix = f" ({named})" if named else ""
    malformed = (
        "incomplete"
        if code in {KEEP_FAIL_MISSING_LEAF, KEEP_FAIL_EMPTY, KEEP_FAIL_INCOMPLETE}
        else "malformed"
    )
    return {
        "code": code,
        "path": named,
        "detail": detail,
        "message": f"{code}: keep fixture {malformed}: {detail}{suffix}",
    }


def _zip_issue(path: Path) -> dict[str, str] | None:
    if not path.is_file():
        return None
    if path.stat().st_size == 0:
        return _issue(KEEP_FAIL_CORRUPT_ZIP, "empty keep package zip", path)
    try:
        with zipfile.ZipFile(path) as archive:
            bad = archive.testzip()
            if bad is not None:
                return _issue(KEEP_FAIL_CORRUPT_ZIP, f"corrupt zip member {bad}", path)
    except zipfile.BadZipFile:
        return _issue(KEEP_FAIL_CORRUPT_ZIP, "truncated or corrupt zip", path)
    return None


def _json_leaf_issue(path: Path, data: bytes) -> dict[str, str] | None:
    if _looks_binary(data):
        return _issue(KEEP_FAIL_GARBAGE_BINARY, "garbage binary where JSON expected", path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _issue(KEEP_FAIL_GARBAGE_BINARY, "garbage binary where JSON expected", path)
    stripped = text.lstrip("\ufeff").strip()
    if not stripped:
        return _issue(KEEP_FAIL_EMPTY, "empty required file", path)
    try:
        json.loads(stripped)
    except json.JSONDecodeError:
        if stripped[:1] in "{[":
            return _issue(KEEP_FAIL_TRUNCATED_JSON, "truncated or corrupt JSON", path)
        return _issue(KEEP_FAIL_GARBAGE_BINARY, "garbage binary where JSON expected", path)
    return None


def _detect_family(path: Path) -> str | None:
    """Lazy import so keep_preflight can run before keep.adapters exists."""
    from keep.adapters import detect_family

    return detect_family(path)


def _claim_path(samples: Path) -> Path | None:
    for name in KEEP_CLAIM_NAMES:
        path = samples / name
        if path.is_file():
            return path
    return None


def _claim_issue(
    path: Path,
    *,
    detected: set[str],
    sample_marked: bool,
) -> dict[str, str] | None:
    data = path.read_bytes()
    json_issue = _json_leaf_issue(path, data)
    if json_issue:
        json_issue["detail"] = f"claim/manifest {json_issue['detail']}"
        json_issue["message"] = (
            f"{json_issue['code']}: keep fixture malformed: {json_issue['detail']} "
            f"({path.as_posix()})"
        )
        return json_issue
    payload = json.loads(data.decode("utf-8").lstrip("\ufeff").strip())
    if not isinstance(payload, dict):
        return _issue(KEEP_FAIL_WRONG_SCHEMA, "claim/manifest is not a JSON object", path)
    schema = str(payload.get("schema") or payload.get("version") or "")
    if schema != KEEP_PACKAGE_SCHEMA:
        return _issue(
            KEEP_FAIL_WRONG_SCHEMA,
            f"claim/manifest schema {schema!r} != {KEEP_PACKAGE_SCHEMA}",
            path,
        )
    families = payload.get("families")
    if not isinstance(families, list) or not families:
        return _issue(
            KEEP_FAIL_WRONG_SCHEMA,
            "claim/manifest families must be a non-empty list",
            path,
        )
    from keep.adapters import KEEP_FAMILIES, family_group

    claimed = {family_group(str(name)) for name in families}
    expected = set(KEEP_FAMILIES)
    if not expected <= claimed or claimed != detected:
        return _issue(
            KEEP_FAIL_CLAIM_MISMATCH,
            f"claim families {sorted(claimed)} != parseable {sorted(detected)}",
            path,
        )
    if payload.get("client_keep") is True and sample_marked:
        return _issue(
            KEEP_FAIL_CLAIM_MISMATCH,
            "claim client_keep true but files are SAMPLE",
            path,
        )
    if payload.get("sample") is False and sample_marked:
        return _issue(
            KEEP_FAIL_CLAIM_MISMATCH,
            "claim sample false but files carry SAMPLE markers",
            path,
        )
    listed = payload.get("files")
    if isinstance(listed, list):
        for rel in listed:
            leaf = path.parent / str(rel)
            if not leaf.is_file():
                return _issue(
                    KEEP_FAIL_CLAIM_MISMATCH,
                    f"claim lists missing {rel}",
                    path,
                )
    return None


def inspect_keep_fixture_tree(
    samples_dir: Path,
    *,
    root: Path | None = None,
) -> dict[str, object]:
    """Inspect a keep-samples (or stress) tree. Stable fail codes. No SoR write."""
    samples = Path(samples_dir)
    repo = Path(root) if root is not None else samples
    issues: list[dict[str, str]] = []
    missing: list[str] = []
    empty: list[str] = []

    if not samples.is_dir():
        missing.append(str(samples))
        issues.append(
            _issue(KEEP_FAIL_MISSING_LEAF, "keep-samples directory missing", samples)
        )
    else:
        for rel in KEEP_SAMPLE_LEAVES:
            path = samples / rel
            if not path.is_file():
                missing.append(str(path))
                issues.append(
                    _issue(
                        KEEP_FAIL_MISSING_LEAF,
                        f"required KEEP leaf missing while parent exists: {rel}",
                        path,
                    )
                )
            elif path.stat().st_size == 0:
                empty.append(str(path))
                issues.append(
                    _issue(KEEP_FAIL_EMPTY, f"empty required file: {rel}", path)
                )

    # Incomplete tree (#98/#99) wins before parse so stub siblings stay unparsed.
    if missing or empty:
        first = issues[0]
        return {
            "ok": False,
            "root": str(repo),
            "samples_dir": str(samples),
            "missing": missing,
            "empty": empty,
            "code": first["code"],
            "path": first["path"],
            "message": keep_samples_incomplete_message(
                repo,
                missing or empty,
                samples_dir=samples,
                code=first["code"],
                empty=bool(empty) and not missing,
            ),
            "issues": issues,
            "detected": [],
        }

    for name in KEEP_ZIP_NAMES:
        zip_issue = _zip_issue(samples / name)
        if zip_issue:
            issues.append(zip_issue)

    if samples.is_dir():
        for rel in KEEP_SAMPLE_LEAVES:
            path = samples / rel
            data = path.read_bytes()
            if path.suffix.lower() == ".json":
                leaf_issue = _json_leaf_issue(path, data)
                if leaf_issue:
                    issues.append(leaf_issue)
                    continue
            elif _looks_binary(data):
                issues.append(
                    _issue(
                        KEEP_FAIL_GARBAGE_BINARY,
                        "garbage binary where KEEP text expected",
                        path,
                    )
                )
                continue
            family = _detect_family(path)
            if not family:
                issues.append(
                    _issue(
                        KEEP_FAIL_WRONG_SCHEMA,
                        f"wrong schema/version for required leaf {rel}",
                        path,
                    )
                )

    detected: set[str] = set()
    sample_marked = False
    blocking = {
        KEEP_FAIL_MISSING_LEAF,
        KEEP_FAIL_EMPTY,
        KEEP_FAIL_TRUNCATED_JSON,
        KEEP_FAIL_GARBAGE_BINARY,
        KEEP_FAIL_WRONG_SCHEMA,
        KEEP_FAIL_CORRUPT_ZIP,
    }
    if samples.is_dir() and not any(item["code"] in blocking for item in issues):
        from keep.adapters import KEEP_FAMILIES, family_group, is_sample_text, scan_keep_dir

        rows = scan_keep_dir(samples)
        detected = {family_group(str(row.get("family") or "")) for row in rows}
        sample_marked = any(bool(row.get("sample")) for row in rows) or any(
            is_sample_text(path.read_text(encoding="utf-8", errors="replace"))
            for path in (samples / rel for rel in KEEP_SAMPLE_LEAVES)
            if path.is_file()
        )
        unparseable = [name for name in KEEP_FAMILIES if name not in detected]
        if unparseable:
            issues.append(
                _issue(
                    KEEP_FAIL_WRONG_SCHEMA,
                    f"families not parseable: {unparseable}",
                    samples,
                )
            )
        claim = _claim_path(samples)
        if claim is not None:
            claim_issue = _claim_issue(
                claim, detected=detected, sample_marked=sample_marked
            )
            if claim_issue:
                issues.append(claim_issue)

    first = issues[0] if issues else None
    ok = not issues
    if first and first["code"] in {
        KEEP_FAIL_MISSING_LEAF,
        KEEP_FAIL_EMPTY,
        KEEP_FAIL_INCOMPLETE,
    }:
        message = keep_samples_incomplete_message(
            repo,
            missing or empty,
            samples_dir=samples,
            code=first["code"],
            empty=first["code"] == KEEP_FAIL_EMPTY,
        )
    else:
        message = first["message"] if first else ""
    return {
        "ok": ok,
        "root": str(repo),
        "samples_dir": str(samples),
        "missing": missing,
        "empty": empty,
        "code": first["code"] if first else "",
        "path": first["path"] if first else "",
        "message": message,
        "issues": issues,
        "detected": sorted(detected),
    }


def check_keep_samples(
    root: Path, samples_dir: Path | None = None
) -> dict[str, object]:
    """Inspect SAMPLE keep-samples files (existence + malformed stress shapes)."""
    root = Path(root)
    return inspect_keep_fixture_tree(keep_samples_root(root, samples_dir), root=root)


def require_keep_samples(root: Path, samples_dir: Path | None = None) -> Path:
    """Raise KeepFixtureIncomplete/Malformed when SAMPLE keep-samples cannot build a register."""
    report = check_keep_samples(root, samples_dir=samples_dir)
    if not report["ok"]:
        code = str(report.get("code") or KEEP_FAIL_INCOMPLETE)
        message = str(report.get("message") or "")
        path = str(report.get("path") or "")
        if code in {KEEP_FAIL_MISSING_LEAF, KEEP_FAIL_EMPTY, KEEP_FAIL_INCOMPLETE}:
            raise KeepFixtureIncomplete(message, code=code, path=path)
        raise KeepFixtureMalformed(message, code=code, path=path)
    return Path(root)


def abort_keep_samples(root: Path, samples_dir: Path | None = None) -> Path:
    """Fail closed with a named missing or malformed fixture (not a hollow SoR)."""
    try:
        return require_keep_samples(root, samples_dir=samples_dir)
    except KeepFixtureError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None


def abort_keep_package(
    root: Path,
    *,
    pythonpath: str | None = None,
    require_pythonpath: bool = False,
) -> Path:
    """Fail closed with the #98 preflight message (not ModuleNotFoundError)."""
    try:
        return require_keep_package(
            root,
            pythonpath=pythonpath,
            require_pythonpath=require_pythonpath,
        )
    except KeepPackageIncomplete as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None
