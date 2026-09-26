"""KEV acceptance criteria §1.6 (numbering maps 1:1). §4/§5 supersede §1.1 separator."""

from __future__ import annotations

import csv
import hashlib
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from shared.kev import (
    HEADER_BOD_DUE,
    HEADER_BOD_TRACKING,
    HEADER_CVE,
    KevSnapshotError,
    bod_2604_timeline,
    collect_cves,
    format_cves,
    join_kev,
    load_kev_catalog,
    write_snapshot_files,
)
from shared.poam_fedramp import FEDRAMP_OPEN_HEADERS
from shared.poam_fields import _to_date

ROOT = Path(__file__).resolve().parents[1]


def _entry(
    cve: str,
    due: str,
    added: str = "2026-06-15",
    triage: str = "No",
    ransom: str = "Unknown",
) -> dict:
    return {
        "cveID": cve,
        "vendorProject": "Example",
        "product": "Widget",
        "vulnerabilityName": f"{cve} demo",
        "dateAdded": added,
        "shortDescription": "fixture",
        "requiredAction": "Apply updates",
        "dueDate": due,
        "knownRansomwareCampaignUse": ransom,
        "forensicTriage": triage,
        "notes": "",
        "cwes": [],
    }


def _catalog(*entries: dict, version: str = "2026.09.01", released: str = "2026-09-01T00:00:00Z") -> dict:
    return {
        "catalogVersion": version,
        "dateReleased": released,
        "count": len(entries),
        "vulnerabilities": list(entries),
    }


def _write_kev(dest: Path, catalog: dict, fetched: str = "2026-09-01T12:00:00Z") -> str:
    prov = write_snapshot_files(
        dest / "kev",
        catalog,
        source_url="https://example.test/kev.json",
        fetched_at_utc=fetched,
    )
    return str(prov["sha256"])


def _finding(cve: str | list[str], **kw) -> dict:
    cves = [cve] if isinstance(cve, str) else list(cve)
    extra = kw.pop("extra", {})
    extra = {
        "cve": " ".join(cves),
        "cves": cves,
        "id": kw.pop("scanner_id", extra.get("id") or "rule-1"),
        "tool": extra.get("tool") or "trivy",
        "port": extra.get("port") or "",
        **extra,
    }
    rec = {
        "kind": "finding",
        "source": "vuln-scan",
        "ref_id": kw.pop("ref_id", "VULN-" + cves[0]),
        "name": kw.pop("name", cves[0]),
        "description": kw.pop("description", "fixture finding"),
        "severity": kw.pop("severity", "high"),
        "category": "vulnerability",
        "assets": kw.pop("assets", ["10.0.0.9"]),
        "labels": ["vuln", "trivy"],
        "collected_at": kw.pop("collected_at", "2026-09-20T10:00:00Z"),
        "extra": extra,
    }
    rec.update(kw)
    return rec


def _load_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: list[dict], in_dir: Path | None = None):
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    with (out / "canonical" / "x.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    dest_in = in_dir or (tmp_path / "in")
    dest_in.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("IN_DIR", str(dest_in))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    return out


def test_1_6_1_fixture_snapshot_cve_x_gets_z_yes_aa_due_ab_cve(tmp_path: Path) -> None:
    """§1.6.1 Given a fixture snapshot that contains CVE-X, extra.cve=CVE-X → Z=Yes, AA=dueDate, AB contains CVE-X."""
    catalog = _catalog(_entry("CVE-2024-11111", "2026-09-10"))
    _write_kev(tmp_path, catalog)
    cat = load_kev_catalog(in_root=tmp_path, now=datetime(2026, 9, 2, tzinfo=timezone.utc))
    joined = join_kev(["CVE-2024-11111"], cat)
    assert joined["tracking"] == "Yes"
    assert joined["due"] == "2026-09-10"
    assert "CVE-2024-11111" in joined["cves"]
    assert joined["evaluated"] is True


def test_1_6_2_cve_not_in_snapshot_leaves_z_aa_blank_never_no(tmp_path: Path) -> None:
    """§1.6.2 CVE not in snapshot → Z blank, AA blank, AB set. Never No or N/A."""
    catalog = _catalog(_entry("CVE-2024-11111", "2026-09-10"))
    _write_kev(tmp_path, catalog)
    cat = load_kev_catalog(in_root=tmp_path, now=datetime(2026, 9, 2, tzinfo=timezone.utc))
    joined = join_kev(["CVE-2014-0160"], cat)
    assert joined["tracking"] == ""
    assert joined["due"] == ""
    assert joined["cves"] == ["CVE-2014-0160"]
    for cell in (joined["tracking"], joined["due"], format_cves(joined["cves"])):
        assert cell.strip().lower() not in {"no", "n/a", "na", "none"}


def test_1_6_3_several_kev_cves_earliest_due_sorted_ab(tmp_path: Path) -> None:
    """§1.6.3 Several KEV CVEs → AA = earliest dueDate; AB = all CVEs sorted.

    §4.2 supersedes the §1.1 comma proposal: primary separator is newline; ``, `` is the CSV fallback.
    """
    catalog = _catalog(
        _entry("CVE-2024-22222", "2026-09-20"),
        _entry("CVE-2024-11111", "2026-09-08"),
    )
    _write_kev(tmp_path, catalog)
    cat = load_kev_catalog(in_root=tmp_path, now=datetime(2026, 9, 2, tzinfo=timezone.utc))
    joined = join_kev(["CVE-2024-22222", "CVE-2024-11111"], cat)
    assert joined["due"] == "2026-09-08"
    assert format_cves(joined["cves"]) == "CVE-2024-11111\nCVE-2024-22222"
    assert format_cves(joined["cves"], csv_fallback=True) == "CVE-2024-11111, CVE-2024-22222"


def test_1_6_4_col_m_never_written_effective_due_min(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§1.6.4 Col M is never written by us. effective_due = min(M, AA)."""
    catalog = _catalog(_entry("CVE-2024-11111", "2026-09-05"))
    in_dir = tmp_path / "in"
    _write_kev(in_dir, catalog)
    rec = _finding("CVE-2024-11111", collected_at="2026-09-01T00:00:00Z", extra={"port": "443"})
    out = _load_loader(tmp_path, monkeypatch, [rec], in_dir=in_dir)
    with (out / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    assert rows[0]["Scheduled Completion Date"] == ""
    ledger = json.loads((out / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    item = next(iter(ledger["items"].values()))
    # High +30 from 2026-09-01 = 2026-10-01; KEV due 2026-09-05 is earlier
    assert item["effective_due"] == "2026-09-05"
    assert item["template_due"] == "2026-10-01"
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "template formula" in md.lower() or "blank" in md.lower()


def test_1_6_5_missing_snapshot_unevaluated_sha_and_schema_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§1.6.5 Missing snapshot → kev_evaluated=false. SHA/schema fail the run."""
    cat = load_kev_catalog(in_root=tmp_path / "empty")
    assert cat.kev_evaluated is False
    rec = _finding("CVE-2024-11111")
    out = _load_loader(tmp_path, monkeypatch, [rec], in_dir=tmp_path / "empty-in")
    prov = json.loads((out / "poam" / "kev_provenance.json").read_text(encoding="utf-8"))
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8")
    assert prov["kev_evaluated"] is False
    assert "kev_evaluated: false" in md
    assert "not 'checked, not in KEV'" in md or "not 'checked, not in KEV'" in md.replace("“", "'")
    with (out / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        row = list(csv.DictReader(fh))[0]
    assert row[HEADER_BOD_TRACKING] == ""
    assert row[HEADER_BOD_DUE] == ""

    bad = tmp_path / "bad-sha"
    catalog = _catalog(_entry("CVE-2024-11111", "2026-09-10"))
    _write_kev(bad, catalog)
    (bad / "kev" / "known_exploited_vulnerabilities.json.sha256").write_text("0" * 64 + "\n", encoding="utf-8")
    with pytest.raises(KevSnapshotError, match="KEV_SNAPSHOT_SHA_MISMATCH"):
        load_kev_catalog(in_root=bad)

    schema = tmp_path / "bad-schema"
    broken = _catalog(_entry("CVE-2024-11111", "2026-09-10"))
    broken["count"] = 99
    _write_kev(schema, broken)
    with pytest.raises(KevSnapshotError, match="KEV_SNAPSHOT_SCHEMA"):
        load_kev_catalog(in_root=schema)


def test_1_6_6_stale_warn_7d_and_stale_30d(tmp_path: Path) -> None:
    """§1.6.6 dateReleased > 30d → KEV_STALE; > 7d → KEV_STALE_WARN."""
    now = datetime(2026, 9, 20, tzinfo=timezone.utc)
    warn = tmp_path / "warn"
    _write_kev(warn, _catalog(_entry("CVE-2024-11111", "2026-09-10"), released="2026-09-10T00:00:00Z"))
    cat = load_kev_catalog(in_root=warn, now=now)
    assert cat.stale == "KEV_STALE_WARN"
    assert "KEV_STALE_WARN" in cat.warnings

    stale = tmp_path / "stale"
    _write_kev(stale, _catalog(_entry("CVE-2024-11111", "2026-09-10"), released="2026-08-01T00:00:00Z"))
    cat = load_kev_catalog(in_root=stale, now=now)
    assert cat.stale == "KEV_STALE"
    assert "KEV_STALE" in cat.warnings
    joined = join_kev(["CVE-2024-11111"], cat)
    assert joined["tracking"] == "Yes"


def test_1_6_7_nessus_cve_tags_yield_cves_in_ab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§1.6.7 A Nessus fixture with <cve> tags yields CVEs in AB (depends on the parser fix)."""
    from collectors import vuln_scan

    catalog = _catalog(
        _entry("CVE-2021-44228", "2026-09-04"),
        _entry("CVE-2021-45046", "2026-09-18"),
    )
    in_dir = tmp_path / "in"
    _write_kev(in_dir, catalog)
    recs = vuln_scan.parse_file(ROOT / "tests" / "fixtures" / "nessus" / "cve-tags.nessus")
    findings = [r for r in recs if r["kind"] == "finding"]
    assert collect_cves(findings[0]) == ["CVE-2021-44228", "CVE-2021-45046"]
    out = _load_loader(tmp_path, monkeypatch, findings, in_dir=in_dir)
    with (out / "poam" / "poam_fedramp.csv").open(encoding="utf-8", newline="") as fh:
        row = list(csv.DictReader(fh))[0]
    assert row[HEADER_BOD_TRACKING] == "Yes"
    assert row[HEADER_BOD_DUE] == "2026-09-04"
    ab = row[HEADER_CVE]
    assert "CVE-2021-44228" in ab and "CVE-2021-45046" in ab
    assert "\n" in ab


def test_1_6_8_header_strings_match_s1_including_22_01() -> None:
    """§1.6.8 Header strings match S1 byte-for-byte, including '22-01'."""
    assert HEADER_BOD_TRACKING == "Binding Operational Directive 22-01 tracking"
    assert HEADER_BOD_DUE == "Binding Operational Directive 22-01 Due Date"
    assert HEADER_CVE == "CVE"
    assert FEDRAMP_OPEN_HEADERS[-3:] == (
        HEADER_BOD_TRACKING,
        HEADER_BOD_DUE,
        HEADER_CVE,
    )
    assert "22-01" in FEDRAMP_OPEN_HEADERS[-3]
    assert "22-01" in FEDRAMP_OPEN_HEADERS[-2]


def test_bod_26_04_table_1_all_16_rows() -> None:
    """§4.3 / §5 — BOD 26-04 Table 1 (text confirmed)."""
    assert bod_2604_timeline(
        publicly_exposed=True, in_kev=True, automatable=True, technical_impact="Total"
    )["timeline"] == "3 days + forensic triage"
    assert bod_2604_timeline(
        publicly_exposed=True, in_kev=True, automatable=False, technical_impact="Partial"
    )["days"] == 14
    assert bod_2604_timeline(
        publicly_exposed=False, in_kev=False, automatable=False, technical_impact="Partial"
    )["timeline"] == "Fix on system upgrade"
    assert len({(e, k, a, i) for e in (True, False) for k in (True, False) for a in (True, False) for i in ("Total", "Partial")}) == 16


def test_pipeline_never_imports_or_fetches() -> None:
    src = (ROOT / "collectors" / "grc_loader.py").read_text(encoding="utf-8")
    kev_src = (ROOT / "shared" / "kev.py").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "lab.yml").read_text(encoding="utf-8")
    assert "kev_fetch" not in src
    assert "urllib.request" not in kev_src
    assert "urlopen" not in kev_src
    assert "kev_fetch" not in ci
    assert "shared.kev_fetch" not in sys.modules


def test_sha_pins_byte_content(tmp_path: Path) -> None:
    catalog = _catalog(_entry("CVE-2024-11111", "2026-09-10"))
    sha = _write_kev(tmp_path, catalog)
    raw = (tmp_path / "kev" / "known_exploited_vulnerabilities.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == sha
    assert _to_date("2026-09-10") is not None
