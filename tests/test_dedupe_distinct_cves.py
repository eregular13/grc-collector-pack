"""Fail-before/pass-after: dedupe never merges distinct CVE ids on one asset.

Finding-type dedupe groups an issue class per asset (e.g. every row typed
web_xss). Two different CVEs whose titles both mention XSS are still two
weaknesses. The same CVE reported by two scanners must still merge.
Synthetic data only.
"""
from __future__ import annotations

from shared.finding_types import dedupe_key, dedupe_weaknesses, finding_type
from shared.schema import make_record, make_ref


def _cve(source: str, cve: str, title: str, asset: str = "example/app:1.0") -> dict:
    return make_record(
        kind="finding", source=source, ref_id=make_ref(source, f"{cve}-{asset}"),
        name=title, description=title, severity="medium", category="vulnerability",
        assets=[asset], labels=[source], collected_at="2026-10-01T00:00:00Z",
        extra={"cve": cve, "pkg": "example-lib"},
    )


def test_two_xss_cves_same_asset_stay_two() -> None:
    a = _cve("vuln-scan", "CVE-2024-0001", "example-lib: XSS via crafted input")
    b = _cve("vuln-scan", "CVE-2024-0002", "other-lib: Cross-site scripting (XSS) in renderer")
    assert finding_type(a) == finding_type(b)  # same issue class
    assert dedupe_key(a) != dedupe_key(b)
    out = [r for r in dedupe_weaknesses([a, b]) if r.get("kind") == "finding"]
    assert sorted(r["extra"]["cve"] for r in out) == ["CVE-2024-0001", "CVE-2024-0002"]


def test_same_cve_two_scanners_still_merges() -> None:
    a = _cve("vuln-scan", "CVE-2024-0001", "example-lib: XSS via crafted input")
    b = _cve("code-secrets", "CVE-2024-0001", "example-lib XSS (CVE-2024-0001)")
    out = [r for r in dedupe_weaknesses([a, b]) if r.get("kind") == "finding"]
    assert len(out) == 1
