"""POA&M control tags == FedRAMP-export control tags (same mapping source).

Framework Tags and Controls on poam_fedramp.csv are the poam.csv cells
(plan overlay), never a second map. SAMPLE/DEMO/LAB only.
"""

from __future__ import annotations

import csv
from pathlib import Path

from shared.control_map import map_finding
from shared.poam_fedramp import FEDRAMP_CSV_HEADERS, item_to_row
from shared.schema import make_record


def _finding(**kwargs):
    return make_record(
        kind="finding",
        source=kwargs.pop("source", "vuln-scan"),
        ref_id=kwargs.pop("ref", "VULN-1"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", "desc"),
        severity=kwargs.pop("severity", "high"),
        category=kwargs.pop("category", "vulnerability"),
        assets=kwargs.pop("assets", ["host-a"]),
        extra=kwargs.pop("extra", {}),
        **kwargs,
    )


def test_fedramp_framework_tags_come_from_poam_plan_not_ledger() -> None:
    mapped = map_finding(
        _finding(
            ref="VULN-redis",
            name="Redis without auth",
            description="Unauthenticated Redis on a LAB host.",
            extra={"template_id": "exposed-redis", "rule": "exposed-redis"},
            assets=["https://redis-a.lab.internal"],
        )
    )
    plan_tags = mapped["framework_refs"]
    plan_controls = ", ".join(mapped.get("nist_800_53") or [])
    assert "csf_PR_AA_03" in plan_tags
    item = {
        "poam_id": "EGP-REDIS",
        "name": "Redis without auth",
        "description": "Unauthenticated Redis",
        "source_family": "vuln-scan",
        "weakness_key": "nuclei:exposed-redis",
        "asset_key": "redis-a.lab.internal",
        "display_asset": "redis-a.lab.internal",
        "original_risk_rating": "High",
        "status": "open",
        "status_date": "2026-09-26",
        "original_detection_date": "2026-09-01",
        "vendor_dependency": "No",
        "framework_refs": "csf_PR_AA_05,cpg_3_I",
        "controls": "SI-2, RA-5",
        "remediation_plan": "stale ledger plan",
        "cves": [],
        "kev_comments": [],
        "vd_comments": [],
        "vd_flags": [],
    }
    plan = {
        "controls": plan_controls,
        "recommended_fix": mapped["recommended_fix"],
        "original_risk_rating": "High",
        "framework_refs": plan_tags,
    }
    row = item_to_row(item, plan)
    cells = dict(zip(FEDRAMP_CSV_HEADERS, row))
    assert cells["Framework Tags"] == plan_tags
    assert cells["Framework Tags"] != item["framework_refs"]
    assert cells["Controls"] == plan_controls
    assert cells["Controls"] != item["controls"]


def test_loader_every_poam_row_fedramp_tags_equal(tmp_path: Path, monkeypatch) -> None:
    from collectors.grc_loader import load
    from shared.io_util import out_dir, write_canonical

    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    (tmp_path / "in").mkdir()
    recs = [
        _finding(
            ref="NMAP-smb",
            name="SMB 445 exposed",
            description="filesrv has open TCP/445 (microsoft-ds).",
            extra={"port": "445", "service": "microsoft-ds"},
            assets=["filesrv.corp.local"],
        ),
        _finding(
            ref="VULN-redis",
            name="Redis without auth",
            description="Unauthenticated Redis on a LAB host.",
            extra={"template_id": "exposed-redis", "rule": "exposed-redis"},
            assets=["https://redis-a.lab.internal"],
        ),
        _finding(
            ref="NIKTO-xss",
            name="Stop reflected web-app cross-site scripting",
            description="Parameter q reflects a script tag.",
            extra={"check_id": "web_xss", "id": "000099"},
            labels=["nikto"],
        ),
        _finding(
            ref="NIKTO-lfi",
            name="Stop web-app local file inclusion",
            description="NextGEN Gallery LFI on wordpress path.",
            extra={"check_id": "web_lfi", "id": "006737"},
            labels=["nikto"],
        ),
    ]
    write_canonical("inventory-nmap", recs)
    load()
    poam_path = out_dir() / "poam" / "poam.csv"
    fed_path = out_dir() / "poam" / "poam_fedramp.csv"
    with poam_path.open(encoding="utf-8", newline="") as fh:
        poam = list(csv.DictReader(fh))
    with fed_path.open(encoding="utf-8", newline="") as fh:
        fed = list(csv.DictReader(fh))
    poam_by = {r.get("poam_id") or "": r for r in poam if r.get("poam_id")}
    fed_by = {r.get("POAM ID") or "": r for r in fed if r.get("POAM ID")}
    assert set(poam_by) == set(fed_by)
    assert poam_by
    for pid, prow in poam_by.items():
        frow = fed_by[pid]
        assert (frow.get("Framework Tags") or "") == (prow.get("framework_refs") or ""), (
            pid,
            prow.get("weakness"),
        )
        assert (frow.get("Controls") or "") == (prow.get("controls") or ""), pid
    redis = next(r for r in poam if "Redis" in (r.get("weakness") or ""))
    assert "csf_PR_AA_03" in (redis.get("framework_refs") or "")
    assert "csf_PR_AA_05" not in (redis.get("framework_refs") or "").split(",")
