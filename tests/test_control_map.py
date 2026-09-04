"""Finding → CPG/CSF map and POA&M rows. No invented CVEs or due dates."""

from __future__ import annotations

from pathlib import Path

from shared.control_map import extra_labels, map_finding
from shared.schema import make_record


def test_smb_445_maps_to_hardening_not_cve() -> None:
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-filesrv-445",
        name="SMB 445 exposed",
        description="filesrv.corp.local has open TCP/445 (microsoft-ds).",
        severity="high",
        category="exposure",
        assets=["filesrv.corp.local"],
        labels=["nmap", "port-445"],
        extra={"port": "445", "service": "microsoft-ds"},
    )
    mapped = map_finding(rec)
    assert mapped["include_poam"] is True
    assert "cpg_2_W" in mapped["cpg"]
    assert "csf_PR" in mapped["csf"]
    assert "CVE-" not in mapped["recommended_fix"]
    assert "445" in mapped["recommended_fix"]
    assert "SMBv1" in mapped["recommended_fix"]
    assert "not a dialect" in mapped["recommended_fix"].lower() or "not a dialect or CVE" in mapped["recommended_fix"]
    assert ":" not in mapped["framework_refs"]


def test_rdp_medium_is_key_poam() -> None:
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-dc-3389",
        name="RDP exposed",
        description="dc.corp.local has open TCP/3389 (ms-wbt-server).",
        severity="medium",
        category="exposure",
        assets=["dc.corp.local"],
        extra={"port": "3389", "service": "ms-wbt-server"},
    )
    assert map_finding(rec)["include_poam"] is True


def test_low_ssh_not_forced_onto_poam() -> None:
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-box-22",
        name="SSH exposed",
        description="box has open TCP/22 (ssh).",
        severity="low",
        category="exposure",
        assets=["box"],
        extra={"port": "22", "service": "ssh"},
    )
    assert map_finding(rec)["include_poam"] is False


def test_extra_labels_wizard_safe_no_colon() -> None:
    stamps = extra_labels()
    assert "cpg_2_W" in stamps
    assert "csf_PR" in stamps
    assert all(":" not in s for s in stamps)
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-x-445",
        name="SMB 445 exposed",
        severity="high",
        category="exposure",
        extra={"port": "445", "service": "microsoft-ds"},
    )
    mapped = extra_labels(rec)
    assert "cpg_2_W" in mapped and "csf_PR" in mapped
    assert all(":" not in s for s in mapped)


def test_loader_writes_poam_with_blank_owner_due(tmp_path: Path, monkeypatch) -> None:
    import csv

    from collectors.grc_loader import load
    from shared.io_util import out_dir, write_canonical

    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-filesrv-445",
        name="SMB 445 exposed",
        description="filesrv.corp.local has open TCP/445 (microsoft-ds).",
        severity="high",
        category="exposure",
        assets=["filesrv.corp.local"],
        labels=["nmap", "port-445"],
        extra={"port": "445", "service": "microsoft-ds"},
    )
    write_canonical("inventory-nmap", [rec])
    summary = load()
    assert summary.get("poam", 0) >= 1
    poam = out_dir() / "poam" / "poam.csv"
    with poam.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    assert any("SMB" in (r.get("weakness") or "") for r in rows)
    for row in rows:
        assert row.get("owner") == ""
        assert row.get("due") == ""
        assert row.get("status") == "open"
        assert ":" not in (row.get("framework_refs") or "")
    md = (out_dir() / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "Pentera" in md and "Evergreen maps" in md
    assert "blank" in md.lower()
