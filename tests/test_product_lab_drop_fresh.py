"""Packaged product-lab/drop must match a fresh host-lab generator run.

Argus cold-review: a Sep-4 drop (61 POA&M, no estate banner/column) is what
repo browsers and console fallback see. This test fails when the committed
drop drifts from collectors + grc_loader + refresh on HEAD.

DEMO/SAMPLE fixtures. Never client KEEP. No POST /api/risks.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from shared.ciso_shape import CISO_HEADERS, POAM_HEADER, csv_rows

ROOT = Path(__file__).resolve().parents[1]
DROP = ROOT / "product-lab" / "drop"
COLLECTORS = (
    "cloud_prowler",
    "inventory_nmap",
    "vuln_scan",
    "host_wazuh",
    "identity_ad",
    "easm",
    "k8s_kubescape",
    "code_secrets",
    "saas_idp",
    "dns_email",
    "honeypot",
    "grc_loader",
)
CISO_FILES = (
    "applied_controls.csv",
    "assets.csv",
    "evidences.csv",
    "findings.csv",
    "risk_scenarios.csv",
    "vulnerabilities.csv",
)
# Host-lab empty-in snapshot after EGA- collapse + honeypot + #166.
# Sep-4 drop was 62/62/15/61; pre-EGA lock was 84/103/22/33/125.
# filesrv.corp.local is NMAP-asset-10-0-0-50 (alias collapsed).
PACKAGED_COUNTS = {
    "assets.csv": 79,
    "findings.csv": 107,
    "vulnerabilities.csv": 22,
    "evidences.csv": 34,
    "applied_controls.csv": 129,
    "risk_scenarios.csv": 129,
}
# IDs that exist in both packaged drop and a fresh generator run.
KEY_ASSET_IDS = {
    "NMAP-asset-10-0-0-50",
    "NMAP-asset-dc-corp-local",
    "K8S-asset-prod-cluster",
    "CLD-asset-iam-admin-breakglass",
    "WAZ-asset-web-01",
    "HPOT-asset-ssh-canary-01",
}


def _hermetic_env(out: Path, inn: Path) -> dict[str, str]:
    """Empty-in demo lab. Do not inherit a leaked LAB/FIXTURES_DIR from pytest."""
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "TMPDIR", "TMP", "TEMP")
    env = {key: os.environ[key] for key in keep if os.environ.get(key)}
    env["PYTHONPATH"] = str(ROOT)
    env["OUT_DIR"] = str(out)
    env["IN_DIR"] = str(inn)
    env["FIXTURES_DIR"] = str(ROOT / "fixtures" / "demo")
    env["DRY_RUN"] = "1"
    env["GRC_LIVE_SCAN"] = "0"
    env["CISO_PUSH"] = "0"
    env["RISKREADY_PUSH"] = "0"
    env["DROPBOX_LIVE"] = "0"
    return env


def _run_fresh_lab(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    inn = tmp_path / "in"
    inn.mkdir()
    out.mkdir()
    env = _hermetic_env(out, inn)
    for name in COLLECTORS:
        subprocess.run(
            [sys.executable, str(ROOT / "collectors" / f"{name}.py")],
            cwd=str(ROOT),
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
    return out


def _ids(path: Path, header: str, key: str) -> set[str]:
    delim = ";" if path.name == "risk_scenarios.csv" else ","
    rows = csv_rows(path, delimiter=delim)
    assert rows or path.stat().st_size > 0
    first = path.read_text(encoding="utf-8").splitlines()[0].strip()
    assert first == header, (path.name, first, header)
    return {str(row.get(key) or "") for row in rows if str(row.get(key) or "")}


def test_product_lab_drop_matches_fresh_generator(tmp_path: Path) -> None:
    fresh = _run_fresh_lab(tmp_path)
    drop_ciso = DROP / "ciso"
    fresh_ciso = fresh / "ciso-assistant"

    for name in CISO_FILES:
        header = CISO_HEADERS[name]
        key = "name" if name == "evidences.csv" else "ref_id"
        packaged = _ids(drop_ciso / name, header, key)
        generated = _ids(fresh_ciso / name, header, key)
        if name in PACKAGED_COUNTS:
            assert len(packaged) == PACKAGED_COUNTS[name], (name, len(packaged))
        assert generated, name
        if name == "assets.csv":
            assert KEY_ASSET_IDS <= packaged, packaged
            assert KEY_ASSET_IDS <= generated, generated

    findings = csv_rows(drop_ciso / "findings.csv")
    assert findings
    assert all("estate_demo" in (row.get("filtering_labels") or "") for row in findings)
    assert all("CLIENT" not in (row.get("filtering_labels") or "").upper() for row in findings)

    poam_drop = DROP / "poam" / "poam.csv"
    poam_fresh = fresh / "poam" / "poam.csv"
    assert poam_drop.read_text(encoding="utf-8").splitlines()[0].strip() == POAM_HEADER
    assert poam_fresh.read_text(encoding="utf-8").splitlines()[0].strip() == POAM_HEADER
    drop_poam = csv_rows(poam_drop)
    fresh_poam = csv_rows(poam_fresh)
    drop_excluded = csv_rows(DROP / "poam" / "excluded.csv")
    assert len(drop_poam) == 124
    assert len(fresh_poam) >= 100
    assert len(drop_excluded) == 5
    assert {str(r.get("excluded_reason") or "") for r in drop_excluded} >= {
        "honeypot",
        "telemetry",
        "superseded_by_specific",
    }
    assert "estate" in POAM_HEADER
    estates = {str(r.get("estate") or "") for r in drop_poam}
    assert estates
    assert all("CLIENT" not in e.upper() or "NOT A CLIENT" in e.upper() for e in estates)
    assert any("DEMO" in e.upper() or "SAMPLE" in e.upper() for e in estates)
    assert all((r.get("owner") or "") == "" and (r.get("due") or "") == "" for r in drop_poam)

    for rel in (
        "ciso/ESTATE.txt",
        "poam/ESTATE.txt",
        "EXECUTIVE_SUMMARY.md",
        "SCOPE_AND_TRUST.md",
    ):
        text = (DROP / rel).read_text(encoding="utf-8")
        assert "DEMO: NOT A CLIENT" in text or "SAMPLE DATA: NOT A CLIENT" in text, rel
        assert "not a client" in text.lower()
        # Honesty copy may say "never client KEEP"; a CLIENT KEEP banner would not.
        first = text.splitlines()[0]
        assert first.startswith(">") or first.startswith("DEMO") or first.startswith("SAMPLE")
        assert "CLIENT KEEP:" not in text.upper()

    assert not (DROP / "riskready").exists()
    # findings + vulns == poam + excluded (honeypot/telemetry/superseded stay off the plan)
    assert len(findings) + len(csv_rows(drop_ciso / "vulnerabilities.csv")) == len(
        drop_poam
    ) + len(drop_excluded)
