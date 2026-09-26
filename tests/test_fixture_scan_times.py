"""Lab/demo fixture scan times feed original_detection_date.

Detection date is the artifact's own scan timestamp (PR #131). Missing stays
the literal 'not recorded' — never the pack run date. SAMPLE keep-samples stay
honest when they carry no tool timestamp.
"""

from __future__ import annotations

import csv
import importlib
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from collectors import (
    cloud_prowler,
    code_secrets,
    dns_email,
    easm,
    honeypot,
    host_wazuh,
    identity_ad,
    inventory_nmap,
    k8s_kubescape,
    saas_idp,
    vuln_scan,
)
from collectors import grc_loader
from keep.lab import keep_lab
from scripts.prove_ciso import prove_ciso
from shared.hardening_dedup import dedupe_hardening
from shared.io_util import run_collector
from shared.scan_time import NOT_RECORDED, PENDING_DUE, format_detection_date
from tests.test_lab_prove_lock import stage_lab_drop_dest_in

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"
LAB_DROP = ROOT / "fixtures" / "lab-drop"
TODAY = datetime.now(timezone.utc).date().isoformat()

# Calendar days stamped on lab/demo fixtures this brick. Not the pack run date.
FIXTURE_DATES = frozenset(
    {
        "2026-09-08",  # httpx
        "2026-09-10",  # nmap / gnmap / masscan / nessus
        "2026-09-11",  # nuclei
        "2026-09-12",  # trivy / testssl
        "2026-09-13",  # SARIF invocations
        "2026-09-14",  # prowler / ASFF
        "2026-09-15",  # greenbone
        "2026-09-16",  # ScubaGear TimestampZulu
        "2026-09-17",  # lynis report_datetime_start
        "2026-09-18",  # falco time
        "2026-09-19",  # PingCastle GenerationDate
        "2026-09-21",  # lab-drop nmap pack_drop generated_at
        "2026-09-25",  # OpenSCAP TestResult start-time
    }
)

# Tools whose real output has no scan-time field. Rows stay 'not recorded'.
NO_TIMESTAMP_TOOLS = (
    "fping / arp-scan / netdiscover / zmap / unicornscan / nbtscan / smbmap "
    "(stdout; no scan clock)",
    "whatweb / sslscan / naabu / nikto text / enum4linux (no scan-time field)",
    "hardeningkitty CSV (filename clock is pack convention, not a CSV column)",
    "kube-bench / kubescape JSON (no scan timestamp in the exported schema)",
    "checkov / gitleaks / trufflehog / semgrep JSON (non-SARIF)",
    "scoutsuite / steampipe / custodian / maester / okta / graph / entra / jamf / intune",
    "amass / subfinder / ffuf / bloodhound JSON (no scan-level time)",
    "osquery inventory demo (no unixTime/calendarTime on these rows)",
    "honeypot events (ts is event time; rows stay excluded telemetry)",
)

COLLECTORS = (
    ("cloud-prowler", (".json", ".js", ".csv"), cloud_prowler.parse_file, None),
    (
        "inventory-nmap",
        (".xml", ".gnmap", ".txt", ".json", ".jsonl", ".csv", ".md"),
        inventory_nmap.parse_file,
        None,
    ),
    (
        "vuln-scan",
        (".json", ".jsonl", ".sarif", ".txt", ".xml", ".nessus", ".csv"),
        vuln_scan.parse_file,
        None,
    ),
    (
        "host-wazuh",
        (".json", ".jsonl", ".xml", ".txt", ".log", ".dat", ".csv"),
        host_wazuh.parse_file,
        dedupe_hardening,
    ),
    ("identity-ad", (".json", ".xml", ".csv", ".txt"), identity_ad.parse_file, dedupe_hardening),
    ("easm", (".txt", ".json", ".jsonl", ".xml"), easm.parse_file, None),
    ("k8s-kubescape", (".json", ".jsonl"), k8s_kubescape.parse_file, None),
    ("code-secrets", (".json", ".jsonl", ".sarif"), code_secrets.parse_file, None),
    ("saas-idp", (".json", ".jsonl", ".csv"), saas_idp.parse_file, None),
    ("dns-email", (".json", ".jsonl", ".txt", ".pem", ".crt", ".cer"), dns_email.parse_file, None),
    ("honeypot", (".jsonl", ".json"), honeypot.parse_file, None),
)


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r.get("kind") == "finding"]


def _scan_dates(recs: list[dict]) -> set[str]:
    out: set[str] = set()
    for rec in _findings(recs):
        stamp = format_detection_date((rec.get("extra") or {}).get("scan_time") or (rec.get("extra") or {}).get("timestamp") or (rec.get("extra") or {}).get("first_seen"))
        if stamp != NOT_RECORDED:
            out.add(stamp)
    return out


def _poam_date_counts(path: Path) -> tuple[int, int, list[str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    real: list[str] = []
    missing = 0
    for row in rows:
        det = (row.get("original_detection_date") or "").strip()
        if det == NOT_RECORDED:
            missing += 1
            assert (row.get("scheduled_completion_date") or "").strip() == PENDING_DUE
        else:
            assert len(det) == 10 and det[4] == "-" and det[7] == "-", det
            assert det != TODAY
            assert det != date.today().isoformat()
            real.append(det)
    return len(real), missing, real


def test_no_timestamp_tools_are_named() -> None:
    assert len(NO_TIMESTAMP_TOOLS) >= 8


def test_nmap_xml_start_feeds_scan_time() -> None:
    recs = inventory_nmap.parse_file(DEMO / "nmap" / "scan.xml")
    stamps = _scan_dates(recs)
    assert stamps == {"2026-09-10"}


def test_gnmap_header_feeds_scan_time() -> None:
    recs = inventory_nmap.parse_file(DEMO / "nmap" / "scan.gnmap")
    assert _scan_dates(recs) == {"2026-09-10"}


def test_masscan_xml_start_feeds_scan_time() -> None:
    recs = inventory_nmap.parse_file(DEMO / "nmap" / "masscan.xml")
    assert _scan_dates(recs) == {"2026-09-10"}


def test_nuclei_timestamp_feeds_scan_time() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "nuclei.jsonl")
    assert _scan_dates(recs) == {"2026-09-11"}
    lab = vuln_scan.parse_file(LAB_DROP / "vuln" / "nuclei-multi-host.jsonl")
    assert _scan_dates(lab) == {"2026-09-11"}


def test_trivy_created_at_feeds_scan_time() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "trivy.json")
    assert _scan_dates(recs) == {"2026-09-12"}
    fs = code_secrets.parse_file(DEMO / "code" / "trivy-fs.json")
    # code-secrets may classify trivy-fs as vuln-shaped or ignore; vuln-scan owns CreatedAt.
    vuln_fs = vuln_scan.parse_file(DEMO / "code" / "trivy-fs.json")
    assert _scan_dates(vuln_fs) == {"2026-09-12"} or _scan_dates(fs) == {"2026-09-12"}


def test_sarif_invocations_feed_scan_time() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "demo.sarif")
    assert _scan_dates(recs) == {"2026-09-13"}
    code = code_secrets.parse_file(DEMO / "code" / "semgrep.sarif.json")
    assert _scan_dates(code) == {"2026-09-13"}


def test_nessus_host_start_feeds_scan_time() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "demo.nessus")
    assert _scan_dates(recs) == {"2026-09-10"}


def test_greenbone_json_timestamp_feeds_scan_time() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "greenbone.json")
    assert _scan_dates(recs) == {"2026-09-15"}


def test_testssl_at_feeds_scan_time() -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "testssl.json")
    assert "2026-09-12" in _scan_dates(recs)


def test_prowler_and_asff_timestamps() -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "prowler.json")
    assert _scan_dates(recs) == {"2026-09-14"}
    asff = cloud_prowler.parse_file(DEMO / "cloud" / "prowler-asff.json")
    assert _scan_dates(asff) == {"2026-09-14"}


def test_scuba_timestamp_zulu() -> None:
    recs = saas_idp.parse_file(DEMO / "saas" / "scuba.json")
    assert _scan_dates(recs) == {"2026-09-16"}
    wrap = saas_idp.parse_file(DEMO / "saas" / "scuba-wrap.json")
    assert _scan_dates(wrap) == {"2026-09-16"}


def test_pingcastle_generation_date() -> None:
    recs = identity_ad.parse_file(DEMO / "identity" / "pingcastle.xml")
    assert _scan_dates(recs) == {"2026-09-19"}


def test_falco_time() -> None:
    recs = k8s_kubescape.parse_file(DEMO / "k8s" / "falco.jsonl")
    assert _scan_dates(recs) == {"2026-09-18"}


def test_lynis_report_datetime_start() -> None:
    recs = host_wazuh.parse_file(DEMO / "wazuh" / "lynis-report.txt")
    assert _scan_dates(recs) == {"2026-09-17"}
    lab = host_wazuh.parse_file(LAB_DROP / "wazuh" / "lynis-lab-jump.dat")
    assert _scan_dates(lab) == {"2026-09-17"}


def test_openscap_start_time() -> None:
    recs = host_wazuh.parse_file(LAB_DROP / "wazuh" / "openscap-lab-jump.xml")
    assert _scan_dates(recs) == {"2026-09-25"}


def test_httpx_timestamp() -> None:
    recs = easm.parse_file(DEMO / "easm" / "httpx.jsonl")
    assert "2026-09-08" in _scan_dates(recs)


def test_lab_drop_nmap_meta_generated_at() -> None:
    recs = inventory_nmap.parse_file(LAB_DROP / "nmap" / "pack_drop" / "findings.jsonl")
    assert "2026-09-21" in _scan_dates(recs)


def _run_demo_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest_in = tmp_path / "in"
    dest_out = tmp_path / "out"
    dest_in.mkdir()
    dest_out.mkdir()
    monkeypatch.setenv("IN_DIR", str(dest_in))
    monkeypatch.setenv("OUT_DIR", str(dest_out))
    monkeypatch.setenv("FIXTURES_DIR", str(DEMO))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "DEMO")
    monkeypatch.setenv("DRY_RUN", "1")
    monkeypatch.setenv("GRC_LIVE_SCAN", "0")
    monkeypatch.setenv("CISO_PUSH", "0")
    monkeypatch.setenv("RISKREADY_PUSH", "0")
    for source, suffixes, parse, finalize in COLLECTORS:
        run_collector(source, suffixes, parse, finalize=finalize)
    importlib.reload(grc_loader)
    grc_loader.load()
    return dest_out / "poam" / "poam.csv"


def test_demo_pack_run_detection_dates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    poam = _run_demo_pack(tmp_path, monkeypatch)
    real, missing, dates = _poam_date_counts(poam)
    # Before (older 109-row plan): 4 real / 105 not recorded.
    # After this brick on the current 121-row demo plan:
    assert real + missing == 121
    assert real == 52
    assert missing == 69
    unknown = set(dates) - FIXTURE_DATES
    assert not unknown, f"POA&M dates not from fixtures: {sorted(unknown)}"
    assert TODAY not in dates


def test_lab_drop_run_detection_dates(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    stage_lab_drop_dest_in(dest / "in")
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    poam = Path(stamp["out_dir"]) / "poam" / "poam.csv"
    real, missing, dates = _poam_date_counts(poam)
    assert real + missing == 49
    assert real == 23
    assert missing == 26
    unknown = set(dates) - FIXTURE_DATES
    assert not unknown, f"lab-drop dates not from fixtures: {sorted(unknown)}"
    assert TODAY not in dates
    assert stamp["paying_day"] == "FAIL"


def test_farm_drop_detection_date_counts(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    stamp = prove_ciso(root=ROOT, dest=dest)
    poam = Path(stamp["out_dir"]) / "poam" / "poam.csv"
    real, missing, dates = _poam_date_counts(poam)
    # Farm fixtures were not rewritten. Current full-plan farm_drop is 73 rows.
    # Dates come from pack_drop meta.json generated_at (2026-09-08).
    assert real + missing == 73
    assert real == 69
    assert missing == 4
    assert TODAY not in dates
    assert stamp["paying_day"] == "FAIL"
    assert stamp["sample"] is True


def test_sample_keep_stays_not_recorded(tmp_path: Path) -> None:
    empty = tmp_path / "empty-in"
    empty.mkdir()
    work = tmp_path / "work"
    stamp = keep_lab(ROOT, pack_in=empty, work=work)
    assert stamp["sample"] is True
    assert stamp["client_keep"] is False
    poam = work / "out" / "poam" / "poam.csv"
    assert poam.is_file()
    real, missing, dates = _poam_date_counts(poam)
    assert real + missing == 8
    assert real == 0
    assert missing == 8
    assert dates == []
    assert TODAY not in dates
