"""Fail-before/pass-after: migration map parents match the rollup's parents.

build_migration_map had its own package_of. For a title like
"CVE-2024-0001 in example-lib" it took "CVE-2024-0001" as the package while the
rollup took "example-lib", so old_id -> new_id pointed at parents that are not
on poam.csv. Synthetic rows only.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fixstack.build_migration_map import build_migration_map  # noqa: E402
from fixstack.rollup import package_of, stable_id  # noqa: E402

IMG = "example/app:1.0 (debian 12)"
ROWS = [
    {"poam_id": "EGP-00000000A1", "weakness": "CVE-2024-0001 in example-lib", "asset": IMG,
     "detector_source": "vuln-scan (trivy)", "recommended_action": ""},
    {"poam_id": "EGP-00000000A2", "weakness": "'@scope/pkg: example issue", "asset": IMG,
     "detector_source": "vuln-scan (trivy)", "recommended_action": ""},
    {"poam_id": "EGP-00000000A3", "weakness": "libexample1: example issue", "asset": IMG,
     "detector_source": "vuln-scan (trivy)", "recommended_action": ""},
]


def test_map_new_id_is_rollup_parent() -> None:
    rows = build_migration_map(ROWS, [])
    for old, m in zip(ROWS, rows):
        want = stable_id(IMG, package_of(old))
        assert m["new_id"] == want, (old["weakness"], m, want)
        assert m["disposition"] == "rolled_into_pkg_parent"
