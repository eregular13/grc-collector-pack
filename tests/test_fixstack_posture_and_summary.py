"""Fail-before/pass-after on fixstack_apply (synthetic, no lab data).

D: testssl cert/cipher checks roll into one TLS-posture parent per host:port.
   The parent must be an open POA&M row (critical self-signed chain included),
   not only a sidecar, while its members are closed rolled_into it.
F: summary.json "poam" must equal the post-fixstack poam.csv row count.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = [
    "weakness", "asset", "severity", "framework_refs", "recommended_fix", "owner", "due",
    "status", "estate", "poam_id", "finding_ref_id", "controls", "weakness_description",
    "detector_source", "weakness_source_id", "original_detection_date",
    "scheduled_completion_date", "status_date", "milestones", "original_risk_rating",
    "point_of_contact", "cve",
]
HOST = "203.0.113.10"


def _row(**kw: str) -> dict[str, str]:
    base = {k: "" for k in FIELDS}
    base.update(status="open", estate="DEMO", original_detection_date="2026-10-01",
                status_date="2026-10-01")
    base.update(kw)
    return base


def _work(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    (work / "out" / "poam").mkdir(parents=True)
    rows = [
        _row(weakness="Cert chain of trust", asset=f"{HOST}:443", severity="critical",
             poam_id="EGP-0000000001", finding_ref_id=f"VULN-cert-chain-of-trust-{HOST.replace('.', '-')}",
             detector_source="vuln-scan (testssl)", weakness_source_id="testssl:cert_chain_of_trust",
             weakness_description="failed (self signed)."),
        _row(weakness="Cipher-tls1 2 x2f", asset=f"{HOST}:443", severity="low",
             poam_id="EGP-0000000002", finding_ref_id=f"VULN-cipher-x2f-{HOST.replace('.', '-')}",
             detector_source="vuln-scan (testssl)", weakness_source_id="testssl:cipher-tls1_2_x2f"),
        _row(weakness="CVE-2024-0001 in example-lib", asset="example/app:1.0 (debian 12)",
             severity="high", poam_id="EGP-0000000003", finding_ref_id="VULN-cve-2024-0001-a",
             detector_source="vuln-scan (trivy)", weakness_source_id="cve:CVE-2024-0001",
             recommended_fix="Upgrade example-lib to 1.2 to remediate", cve="CVE-2024-0001"),
        _row(weakness="CVE-2024-0002 in example-lib", asset="example/app:1.0 (debian 12)",
             severity="medium", poam_id="EGP-0000000004", finding_ref_id="VULN-cve-2024-0002-a",
             detector_source="vuln-scan (trivy)", weakness_source_id="cve:CVE-2024-0002",
             recommended_fix="Upgrade example-lib to 1.2 to remediate", cve="CVE-2024-0002"),
    ]
    with (work / "out" / "poam" / "poam.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    (work / "in").mkdir()
    (work / "in" / "testssl.json").write_text(
        json.dumps([{"id": "cert_chain_of_trust", "ip": HOST, "port": "443",
                     "severity": "CRITICAL", "finding": "failed (self signed)."}]),
        encoding="utf-8",
    )
    ca = work / "out" / "ciso-assistant"
    ca.mkdir()
    with (ca / "vulnerabilities.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ref_id", "name", "description", "status", "severity", "assets", "applied_controls"])
        for r in rows:
            w.writerow([r["finding_ref_id"], r["weakness"], r["weakness_description"], "Exploitable",
                        r["severity"].title(), r["asset"], ""])
    (work / "out" / "summary.json").write_text(
        json.dumps({"poam": len(rows), "poam_included": len(rows), "assets": 2}, indent=2) + "\n",
        encoding="utf-8",
    )
    return work


def _apply(work: Path) -> list[dict[str, str]]:
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "fixstack_apply.py"), str(work)],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, r.stderr[-2000:]
    with (work / "out" / "poam" / "poam.csv").open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_tls_posture_parent_on_poam(tmp_path: Path) -> None:
    rows = _apply(_work(tmp_path))
    posture = [r for r in rows if r["weakness_source_id"] == "tls-posture"]
    assert len(posture) == 1, [r["weakness"] for r in rows]
    p = posture[0]
    assert p["severity"] == "critical" and p["status"] == "open"
    assert p["asset"] == f"{HOST}:443"
    side = list(csv.DictReader((tmp_path / "work" / "out" / "poam" / "tls_posture_findings.csv").open(encoding="utf-8")))
    assert p["poam_id"] == side[0]["poam_id_proposal"]
    assert not any(r["weakness"].startswith(("Cert ", "Cipher")) for r in rows)


def test_summary_poam_matches_poam_csv(tmp_path: Path) -> None:
    work = _work(tmp_path)
    rows = _apply(work)
    summary = json.loads((work / "out" / "summary.json").read_text(encoding="utf-8"))
    assert summary["poam"] == len(rows), (summary, len(rows))
    assert summary["poam_included"] == len(rows)
    assert summary["poam_pre_fixstack"] == 4
    assert summary["assets"] == 2


def test_posture_row_date_falls_back_to_status_date(tmp_path: Path) -> None:
    work = _work(tmp_path)
    p = work / "out" / "poam" / "poam.csv"
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    for r in rows:
        if "testssl" in r["detector_source"]:
            r["original_detection_date"] = "not recorded"
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    out = _apply(work)
    posture = [r for r in out if r["weakness_source_id"] == "tls-posture"]
    assert posture[0]["original_detection_date"] == "2026-10-01"
