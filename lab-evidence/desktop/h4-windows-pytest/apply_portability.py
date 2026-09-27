"""Apply H4 Windows portability edits. Run from pack root."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TESTS = ROOT / "tests"

PYTHON_ARGV_FILES = [
    "test_dropbox.py",
    "test_farm_ship_gate.py",
    "test_keepmin_scheduler.py",
    "test_mcp_stub.py",
    "test_orchestrator.py",
    "test_orch_brakes.py",
]

BASH_FUNCS = {
    "test_farm_fedramp_open_matches_poam",
    "test_farm_fedramp_open_stays_109",
    "test_verify_only_stdout_encodes_under_cp1252",
    "test_farm_drop_to_sor_verify_only_fail_closed",
    "test_farm_drop_to_sor_sh_isolated_prove",
    "test_wipe_clone_script_fail_closed_on_partial_checkout",
    "test_wipe_clone_then_farm_drop_emits_register_shape",
    "test_sample_to_sor_sh_fails_closed_on_partial_clone",
    "test_lab_drop_to_sor_sh_uses_existing_in",
    "test_lab_drop_verify_only_after_prove",
    "test_lab_drop_to_sor_on_lab_drop_fixture",
    "test_use_existing_in_fail_closed_on_empty_in",
    "test_lab_shape_fail_cli_and_wrapper_are_stable",
    "test_poam_breakdown_identity_sample",
    "test_poam_breakdown_identity_farm_drop",
    "test_internal_external_scripts_leave_demo_artifacts",
    "test_sample_to_sor_verify_only_fail_closed",
    "test_sample_to_sor_sh_isolated_keep_lab",
    "test_sample_to_sor_sh_isolated_keep_lab_exporters",
    "test_sample_to_sor_wipe_work_then_sample_to_sor_emits_ciso_csvs",
    "test_riskready_push_1_is_review_only",
}

DIGEST_FILES = [
    "test_dns_email.py",
    "test_dropbox.py",
    "test_farm_adapters.py",
    "test_keepmin_scheduler.py",
    "test_mcp_stub.py",
    "test_orch_brakes.py",
    "test_orchestrator.py",
    "test_scan_to_sor.py",
]

IMPORT_PYTHON = "from tests.cli_python import PYTHON"
IMPORT_SKIP = "from tests.cli_python import skip_unless_bash"
IMPORT_BOTH = "from tests.cli_python import PYTHON, skip_unless_bash"
DIGEST_IMPORT = "from dropbox.scope import attestation_digest"


def _add_import(text: str, line: str) -> str:
    if line in text:
        return text
    # After last import block line
    lines = text.splitlines(keepends=True)
    last_import = 0
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if stripped.startswith("from ") or stripped.startswith("import "):
            last_import = i
        elif stripped == "" and last_import:
            continue
        elif last_import and i > last_import + 1:
            break
    lines.insert(last_import + 1, line + "\n")
    return "".join(lines)


def _ensure_scope_digest_import(text: str) -> str:
    if "attestation_digest" in text and "from dropbox.scope import" in text:
        # add to existing import if missing
        def _add(match: re.Match[str]) -> str:
            names = match.group(1)
            if "attestation_digest" in names:
                return match.group(0)
            return f"from dropbox.scope import {names}, attestation_digest"

        new, n = re.subn(
            r"from dropbox\.scope import ([^\n]+)",
            _add,
            text,
            count=1,
        )
        if n:
            return new
    if "from dropbox.scope import" not in text:
        return _add_import(text, "from dropbox.scope import attestation_digest")
    return text


def patch_python_argv(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    orig = text
    text = text.replace('["python3",', "[PYTHON,")
    text = text.replace('\n            "python3",\n', "\n            PYTHON,\n")
    if text != orig:
        need_skip = any(f"def {name}" in text for name in BASH_FUNCS) and path.name in {
            "test_farm_ship_gate.py",
        }
        if need_skip:
            text = _add_import(text, IMPORT_BOTH)
        else:
            text = _add_import(text, IMPORT_PYTHON)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"python argv: {path.name}")


def patch_digest(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    needle = "hashlib.sha256(att.read_bytes()).hexdigest()"
    if needle not in text:
        return
    text = text.replace(needle, "attestation_digest(att.read_bytes())")
    text = _ensure_scope_digest_import(text)
    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"digest: {path.name}")


def patch_skip(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    orig = text
    added = False
    for name in sorted(BASH_FUNCS):
        # insert decorator immediately before def
        pattern = rf"(def {re.escape(name)}\()"
        if re.search(pattern, text) and f"@skip_unless_bash\ndef {name}(" not in text:
            text = re.sub(pattern, r"@skip_unless_bash\n\1", text, count=1)
            added = True
    if not added and text == orig:
        return
    if "skip_unless_bash" in text and "from tests.cli_python import" not in text:
        text = _add_import(text, IMPORT_SKIP)
    elif "skip_unless_bash" in text and "skip_unless_bash" not in [
        ln for ln in text.splitlines() if "from tests.cli_python" in ln
    ][0] if any("from tests.cli_python" in ln for ln in text.splitlines()) else True:
        # merge import
        text = text.replace(
            "from tests.cli_python import PYTHON\n",
            "from tests.cli_python import PYTHON, skip_unless_bash\n",
        )
        if "from tests.cli_python import skip_unless_bash" not in text and "skip_unless_bash" in text:
            if "from tests.cli_python import PYTHON, skip_unless_bash" not in text:
                text = _add_import(text, IMPORT_SKIP)
    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"skip: {path.name}")


def main() -> None:
    for name in PYTHON_ARGV_FILES:
        patch_python_argv(TESTS / name)
    for name in DIGEST_FILES:
        patch_digest(TESTS / name)
    # skipif on every test file that defines a bash func
    for path in sorted(TESTS.glob("test_*.py")):
        blob = path.read_text(encoding="utf-8")
        if any(f"def {n}" in blob for n in BASH_FUNCS):
            patch_skip(path)

    # path_sep assertions
    farm_lab = TESTS / "test_farm_lab.py"
    t = farm_lab.read_text(encoding="utf-8")
    t = t.replace(
        'assert "farm/work" in stamp["in_dir"]',
        'assert "farm/work" in Path(stamp["in_dir"]).as_posix()',
    )
    farm_lab.write_text(t, encoding="utf-8", newline="\n")
    print("path_sep: test_farm_lab.py")

    mcp = TESTS / "test_mcp_stub.py"
    t = mcp.read_text(encoding="utf-8")
    t = t.replace(
        'assert "tool-bin/lab/" in by_slot[name]["path"]',
        'assert "tool-bin/lab/" in Path(by_slot[name]["path"]).as_posix()',
    )
    mcp.write_text(t, encoding="utf-8", newline="\n")
    print("path_sep: test_mcp_stub.py")

    tool = TESTS / "test_farm_tool_bin.py"
    t = tool.read_text(encoding="utf-8")
    t = t.replace(
        'assert farm_which("nmap").endswith("/lab/nmap")',
        'assert Path(farm_which("nmap")).as_posix().endswith("/lab/nmap")',
    )
    tool.write_text(t, encoding="utf-8", newline="\n")
    print("path_sep: test_farm_tool_bin.py")


if __name__ == "__main__":
    main()
