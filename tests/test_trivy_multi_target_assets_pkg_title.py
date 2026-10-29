"""Fail-before/pass-after: multi-Target Trivy image scans.

One container scan with an OS Target and a Go binary Target sharing one
digest/ImageID. Before: both Targets merged into one asset (the other Target's
vulnerabilities pointed at an asset never written to assets.csv), and Go stdlib
CVEs titled "net/url: ..." / "crypto/tls: ..." rolled up per sub-package instead
of per PkgName ("stdlib"). Synthetic data only (example/app:1.0, CVE-2099-*).
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_nmap_pass2_same_port import _xml

ROOT = Path(__file__).resolve().parents[1]
IMG = "example/app:1.0"


def _scan() -> dict:
    def v(vid, pkg, sev, title):
        return {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": "1.0", "Severity": sev, "Title": title}

    return {
        "SchemaVersion": 2,
        "CreatedAt": "2026-09-21T14:13:20Z",
        "ArtifactID": "sha256:" + "a" * 64,
        "ArtifactName": IMG,
        "ArtifactType": "container_image",
        "Metadata": {
            "ImageID": "sha256:" + "b" * 64,
            "RepoTags": [IMG],
            "RepoDigests": ["example/app@sha256:" + "c" * 64],
        },
        "Results": [
            {"Target": f"{IMG} (debian 12)", "Class": "os-pkgs", "Type": "debian",
             "Vulnerabilities": [v("CVE-2099-0101", "libexample1", "HIGH", "libexample1: example issue")]},
            {"Target": "usr/local/bin/tool", "Class": "lang-pkgs", "Type": "gobinary",
             "Vulnerabilities": [
                 v("CVE-2099-0201", "stdlib", "HIGH", "net/url: example parsing issue"),
                 v("CVE-2099-0202", "stdlib", "MEDIUM", "crypto/tls: example handshake issue"),
             ]},
        ],
    }


def _rows(path: Path, delimiter: str | None = None) -> list[dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    head = text.splitlines()[0] if text else ""
    d = delimiter or (";" if head.count(";") > head.count(",") else ",")
    return list(csv.DictReader(text.splitlines(), delimiter=d))


@pytest.fixture(scope="module")
def out(tmp_path_factory) -> Path:
    work = tmp_path_factory.mktemp("mt") / "w"
    vuln = work / "in" / "vuln"
    vuln.mkdir(parents=True)
    (work / "in" / "LAB.txt").write_text(
        "LAB/DEMO -- not a client estate. Synthetic scan. Targets: 203.0.113.30\n", encoding="utf-8"
    )
    nmap = work / "in" / "nmap"
    nmap.mkdir()
    (nmap / "nmap-example.xml").write_text(_xml(1790000000, False), encoding="utf-8")
    (vuln / "trivy-example-app.json").write_text(json.dumps(_scan()), encoding="utf-8")
    env = dict(os.environ, PYTHON=sys.executable, SOURCE_DATE_EPOCH="1790007200", PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts" / "lab_drop_to_sor.sh"), "--work", str(work)],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]
    return work / "out"


def test_every_vulnerability_asset_is_exported(out: Path) -> None:
    names = {r["name"] for r in _rows(out / "ciso-assistant" / "assets.csv")}
    assert f"{IMG} (debian 12)" in names
    assert f"{IMG} :: usr/local/bin/tool" in names
    dangling = [
        a
        for r in _rows(out / "ciso-assistant" / "vulnerabilities.csv")
        for a in (r.get("assets") or "").split("|")
        if a and a not in names
    ]
    assert dangling == []


def test_go_stdlib_cves_roll_up_by_pkgname(out: Path) -> None:
    rows = [r for r in _rows(out / "poam" / "poam.csv") if r["asset"].endswith("usr/local/bin/tool")]
    weak = sorted(r["weakness"] for r in rows)
    assert len(rows) == 1, weak
    assert weak[0].startswith("stdlib: package rollup (2"), weak
