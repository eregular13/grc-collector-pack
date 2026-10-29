"""A grype ``dir:/`` (whole host filesystem) scan has target ``/``. Naming the
asset ``/`` would merge two hosts scanned that way into one asset. Expected: one asset per host, named after the host
(``source.name`` when set, else the report file stem). Synthetic data only.
"""
from __future__ import annotations

import json
from pathlib import Path


def _dir_root_report(vid: str, name: str | None = None) -> dict:
    src: dict = {"type": "directory", "target": "/"}
    if name is not None:
        src["name"] = name
    return {
        "matches": [{
            "vulnerability": {"id": vid, "severity": "High", "fix": {"versions": [], "state": "not-fixed"}},
            "relatedVulnerabilities": [],
            "artifact": {"name": "examplepkg", "version": "1.0", "type": "deb", "locations": []},
        }],
        "source": src,
        "descriptor": {"name": "grype", "timestamp": "2099-01-02T03:04:05Z"},
    }


def _assets(recs: list[dict]) -> list[str]:
    return sorted(r["name"] for r in recs if r["kind"] == "asset")


def _finding_assets(recs: list[dict]) -> set[str]:
    return {a for r in recs if r["kind"] == "finding" for a in r["assets"]}


def test_two_hosts_dir_root_scans_stay_two_assets(tmp_path: Path) -> None:
    from collectors.vuln_scan import parse_file

    a = tmp_path / "host-a.example.test.json"
    b = tmp_path / "host-b.example.test.json"
    a.write_text(json.dumps(_dir_root_report("CVE-2099-59301")))
    b.write_text(json.dumps(_dir_root_report("CVE-2099-59302")))
    ra, rb = parse_file(a), parse_file(b)
    assert _assets(ra) == ["host-a.example.test"]
    assert _assets(rb) == ["host-b.example.test"]
    assert _finding_assets(ra) == {"host-a.example.test"}
    assert _finding_assets(rb) == {"host-b.example.test"}
    assert "/" not in set(_assets(ra) + _assets(rb))


def test_dir_root_scan_prefers_source_name(tmp_path: Path) -> None:
    from collectors.vuln_scan import parse_file

    f = tmp_path / "scan.json"
    f.write_text(json.dumps(_dir_root_report("CVE-2099-59303", name="host-c.example.test")))
    assert _assets(parse_file(f)) == ["host-c.example.test"]
