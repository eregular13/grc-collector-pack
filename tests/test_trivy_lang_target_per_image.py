"""Fail-before/pass-after: Trivy language/binary Targets are scoped per image.

Two container images that both carry a Result with the generic Target "Node.js"
must give two assets (one per image), not one shared "Node.js" asset. OS-package
Targets that already name the image, and non-image scans, keep their names.
Synthetic data only.
"""
from __future__ import annotations

import json
from pathlib import Path

from collectors import vuln_scan


def _image_scan(image: str, vid: str) -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": image,
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": f"{image} (debian 12)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-0011", "PkgName": "libexample1", "Severity": "LOW", "Title": "libexample1: example issue"}
                ],
            },
            {
                "Target": "Node.js",
                "Class": "lang-pkgs",
                "Type": "node-pkg",
                "Vulnerabilities": [
                    {"VulnerabilityID": vid, "PkgName": "example-lib", "Severity": "HIGH", "Title": "example-lib: example issue"}
                ],
            },
        ],
    }


def _assets_and_findings(tmp_path: Path, payloads: list[dict]) -> tuple[list[dict], list[dict]]:
    recs: list[dict] = []
    for i, p in enumerate(payloads):
        f = tmp_path / f"trivy-{i}.json"
        f.write_text(json.dumps(p), encoding="utf-8")
        recs.extend(vuln_scan.parse_file(f))
    assets = [r for r in recs if r.get("kind") == "asset"]
    finds = [r for r in recs if r.get("kind") == "finding"]
    return assets, finds


def test_same_lang_target_in_two_images_gives_two_assets(tmp_path: Path) -> None:
    assets, finds = _assets_and_findings(
        tmp_path,
        [_image_scan("example/app:1.0", "CVE-2024-0001"), _image_scan("example/web:2.0", "CVE-2024-0002")],
    )
    lang = sorted({a["name"] for a in assets if "Node.js" in a["name"]})
    assert lang == ["example/app:1.0 :: Node.js", "example/web:2.0 :: Node.js"], lang
    by_vid = {f["extra"].get("cve"): f["assets"] for f in finds}
    assert by_vid["CVE-2024-0001"] == ["example/app:1.0 :: Node.js"]
    assert by_vid["CVE-2024-0002"] == ["example/web:2.0 :: Node.js"]


def test_os_target_and_non_image_scans_unchanged(tmp_path: Path) -> None:
    assets, _ = _assets_and_findings(tmp_path, [_image_scan("example/app:1.0", "CVE-2024-0001")])
    names = {a["name"] for a in assets}
    assert "example/app:1.0 (debian 12)" in names
    fs = {"ArtifactName": "repo", "ArtifactType": "filesystem", "Results": [
        {"Target": "package-lock.json", "Class": "lang-pkgs",
         "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0003", "PkgName": "x", "Severity": "LOW"}]}]}
    assets2, _ = _assets_and_findings(tmp_path, [fs])
    assert {a["name"] for a in assets2} == {"package-lock.json"}
