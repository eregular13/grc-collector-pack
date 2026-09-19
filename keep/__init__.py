"""KEEP-chain file-drop → Layer C → Origin Eval handoff. Parse-only. No HTTP."""

from pathlib import Path

from dropbox.keep_preflight import abort_keep_package

# Fail closed before importing lab/adapters so a partial / corrupt
# cold-path-gate tree cannot surface as ModuleNotFoundError.
abort_keep_package(Path(__file__).resolve().parents[1])

from keep.adapters import KEEP_FAMILIES, detect_family, land_keep_files
from keep.handoff import MAX_FINDINGS, build_eval_handoff, write_eval_handoff

__all__ = [
    "KEEP_FAMILIES",
    "MAX_FINDINGS",
    "build_eval_handoff",
    "detect_family",
    "land_keep_files",
    "write_eval_handoff",
]
