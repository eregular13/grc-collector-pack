"""Fail-before/pass-after: fixstack rollup groups Trivy rows by package for every title form.

When a vendor title does not name the package, the Trivy collector can title a
finding "<CVE/GHSA id> in <PkgName>" or "<vendor title> (<PkgName>)".
scripts/fixstack/rollup.py package_of() only understood "pkg: title", so it
fell back to the first token (the advisory id) and produced one "package
rollup" group per advisory instead of one per (image, package). A scoped npm
package title that starts with "@" is CSV-formula-guarded ("'@scope/pkg: ..."),
which also split one package into two groups.
Synthetic data only: ids, packages and images below are made up.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLLUP = ROOT / "scripts" / "fixstack" / "rollup.py"


def _mod():
    spec = importlib.util.spec_from_file_location("fixstack_rollup_under_test", ROLLUP)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_package_of_vid_in_pkg_titles() -> None:
    m = _mod()
    assert m.package_of({"weakness": "CVE-2024-0101 in zlib1g"}) == "zlib1g"
    assert m.package_of({"weakness": "GHSA-aaaa-bbbb-cccc in dompurify"}) == "dompurify"
    assert m.package_of({"weakness": "CVE-2024-0102 in @remix-run/router"}) == "@remix-run/router"
    # existing "pkg: title" form unchanged
    assert m.package_of({"weakness": "gnutls: example denial of service"}) == "gnutls"


def test_rollup_collapses_same_image_package_cves(tmp_path: Path) -> None:
    hdr = ["weakness", "asset", "severity", "recommended_fix", "status", "poam_id",
           "finding_ref_id", "detector_source", "original_detection_date", "cve"]
    img = "example/app:1.0 (debian 12)"
    rows = [
        ["CVE-2024-0001 in libssl3", img, "high", "Upgrade libssl3 to 3.0.9", "open", "EGP-A1", "VULN-1", "vuln-scan (trivy)", "2026-10-03", "CVE-2024-0001"],
        ["CVE-2024-0002 in libssl3", img, "medium", "Upgrade libssl3 to 3.0.9", "open", "EGP-A2", "VULN-2", "vuln-scan (trivy)", "2026-10-03", "CVE-2024-0002"],
        ["CVE-2024-0003 in libssl3", img, "low", "Upgrade libssl3 to 3.0.9", "open", "EGP-A3", "VULN-3", "vuln-scan (trivy)", "2026-10-03", "CVE-2024-0003"],
        ["CVE-2024-0004 in zlib1g", img, "low", "Upgrade zlib1g to 1.3", "open", "EGP-A4", "VULN-4", "vuln-scan (trivy)", "2026-10-03", "CVE-2024-0004"],
    ]
    src = tmp_path / "poam.csv"
    with src.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(hdr)
        w.writerows(rows)
    out = tmp_path / "final"
    r = subprocess.run([sys.executable, str(ROLLUP), str(src), str(out)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    stats = json.loads((out / "rollup_stats.json").read_text(encoding="utf-8"))
    assert stats["trivy_rows_before"] == 4
    assert stats["trivy_groups"] == 2, stats["trivy_groups"]  # libssl3 + zlib1g, not 4
    assert stats["cve_conservation"]["ok"] is True


def test_package_of_title_pkg_suffix_form() -> None:
    """Non-CVE form "<title> (<PkgName>)" (e.g. distro TEMP- advisory ids)."""
    m = _mod()
    assert m.package_of({"weakness": "[Kernel: example local denial of service] (linux-libc-dev)"}) == "linux-libc-dev"
    assert m.package_of({"weakness": "[Example advisory title without the package] (bash)"}) == "bash"
    assert m.package_of({"weakness": "xz-utils - example update (liblzma5)"}) == "liblzma5"
    # pkg already in the title: suffix was not added by the collector; keep "pkg: title"
    assert m.package_of({"weakness": "openssl: thing in openssl (openssl)"}) == "openssl"
    # a trailing advisory id is not a package
    assert m.package_of({"weakness": "curl: HSTS bypass (CVE-2024-9999)"}) == "curl"


def test_scoped_npm_package_one_group_and_csv_guarded(tmp_path: Path) -> None:
    """'@scope/pkg: title' (formula-guarded) and 'CVE-… in @scope/pkg' are one package;
    the rolled weakness cell must stay CSV-formula-guarded."""
    m = _mod()
    assert m.package_of({"weakness": "'@remix-run/router: react-router: XSS"}) == "@remix-run/router"
    hdr = ["weakness", "asset", "severity", "recommended_fix", "status", "poam_id",
           "finding_ref_id", "detector_source", "original_detection_date", "cve"]
    rows = [
        ["'@remix-run/router: react-router: XSS", "Node.js", "high", "x", "open", "EGP-B1", "VULN-1", "vuln-scan (trivy)", "2026-10-03", "CVE-2026-0001"],
        ["CVE-2026-0002 in @remix-run/router", "Node.js", "medium", "x", "open", "EGP-B2", "VULN-2", "vuln-scan (trivy)", "2026-10-03", "CVE-2026-0002"],
    ]
    src = tmp_path / "poam.csv"
    with src.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(hdr)
        w.writerows(rows)
    out = tmp_path / "final"
    r = subprocess.run([sys.executable, str(ROLLUP), str(src), str(out)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    stats = json.loads((out / "rollup_stats.json").read_text(encoding="utf-8"))
    assert stats["trivy_groups"] == 1, stats["trivy_groups"]
    with (out / "poam_rolled.csv").open(encoding="utf-8", newline="") as fh:
        weak = [row["weakness"] for row in csv.DictReader(fh)]
    assert weak == ["'@remix-run/router: package rollup (2 CVEs/findings)"], weak
