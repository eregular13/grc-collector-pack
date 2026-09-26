"""Per-parser scan-time extraction: real field → date; missing → not recorded.

Covers the 11 production parsers this PR changes, plus the seven tools
that do emit a timestamp (kubescape, ScoutSuite, Maester, naabu, Custodian,
nikto, ffuf). Never uses the pack run date.
"""

from __future__ import annotations

import json
from pathlib import Path

from collectors import (
    cloud_prowler,
    code_secrets,
    easm,
    host_wazuh,
    identity_ad,
    inventory_nmap,
    k8s_kubescape,
    saas_idp,
    vuln_scan,
)
from shared.masscan import parse_masscan
from shared.nessus import iter_nessus_items
from shared.openscap import iter_openscap_failures
from shared.scan_time import NOT_RECORDED, format_detection_date

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"
SAMPLES = ROOT / "fixtures" / "samples"
LAB_DROP = ROOT / "fixtures" / "lab-drop"


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r.get("kind") == "finding"]


def _dates(recs: list[dict]) -> set[str]:
    out: set[str] = set()
    for rec in _findings(recs):
        extra = rec.get("extra") or {}
        stamp = format_detection_date(
            extra.get("scan_time") or extra.get("timestamp") or extra.get("first_seen")
        )
        if stamp != NOT_RECORDED:
            out.add(stamp)
    return out


def _all_not_recorded(recs: list[dict]) -> None:
    finds = _findings(recs)
    assert finds, "expected findings so the missing-field fallback is observable"
    for rec in finds:
        extra = rec.get("extra") or {}
        assert (
            format_detection_date(
                extra.get("scan_time") or extra.get("timestamp") or extra.get("first_seen")
            )
            == NOT_RECORDED
        )


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- 11 production parsers ---


def test_cloud_prowler_asff_created_at_and_missing(tmp_path: Path) -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "prowler-asff.json")
    assert _dates(recs) == {"2026-09-14"}
    payload = json.loads((DEMO / "cloud" / "prowler-asff.json").read_text(encoding="utf-8"))
    for item in payload["Findings"]:
        item.pop("CreatedAt", None)
        item.pop("UpdatedAt", None)
    dest = tmp_path / "prowler-asff.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(cloud_prowler.parse_file(dest))


def test_code_secrets_sarif_start_time_utc_and_missing(tmp_path: Path) -> None:
    recs = code_secrets.parse_file(DEMO / "code" / "semgrep.sarif.json")
    assert _dates(recs) == {"2026-09-13"}
    payload = json.loads((DEMO / "code" / "semgrep.sarif.json").read_text(encoding="utf-8"))
    for run in payload.get("runs") or []:
        run["invocations"] = []
    dest = tmp_path / "semgrep.sarif.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(code_secrets.parse_file(dest))


def test_easm_httpx_timestamp_and_missing(tmp_path: Path) -> None:
    recs = easm.parse_file(DEMO / "easm" / "httpx.jsonl")
    assert "2026-09-08" in _dates(recs)
    dest = tmp_path / "httpx.jsonl"
    lines = []
    for line in (DEMO / "easm" / "httpx.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        row.pop("timestamp", None)
        row.pop("time", None)
        lines.append(json.dumps(row))
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _all_not_recorded(easm.parse_file(dest))


def test_host_wazuh_lynis_report_datetime_and_missing(tmp_path: Path) -> None:
    recs = host_wazuh.parse_file(DEMO / "wazuh" / "lynis-report.txt")
    assert _dates(recs) == {"2026-09-17"}
    dest = tmp_path / "lynis-report.txt"
    dest.write_text(
        (DEMO / "wazuh" / "lynis-report.txt")
        .read_text(encoding="utf-8")
        .replace("report_datetime_start=2026-09-17 09:00:00\n", ""),
        encoding="utf-8",
    )
    _all_not_recorded(host_wazuh.parse_file(dest))


def test_identity_ad_pingcastle_generation_date_and_missing(tmp_path: Path) -> None:
    recs = identity_ad.parse_file(DEMO / "identity" / "pingcastle.xml")
    assert _dates(recs) == {"2026-09-19"}
    dest = tmp_path / "pingcastle.xml"
    dest.write_text(
        (DEMO / "identity" / "pingcastle.xml")
        .read_text(encoding="utf-8")
        .replace("<GenerationDate>2026-09-19T14:00:00+00:00</GenerationDate>\n", ""),
        encoding="utf-8",
    )
    _all_not_recorded(identity_ad.parse_file(dest))


def test_inventory_nmap_gnmap_initiated_and_missing(tmp_path: Path) -> None:
    recs = inventory_nmap.parse_file(DEMO / "nmap" / "scan.gnmap")
    assert _dates(recs) == {"2026-09-10"}
    dest = tmp_path / "scan.gnmap"
    dest.write_text(
        "\n".join(
            line
            for line in (DEMO / "nmap" / "scan.gnmap").read_text(encoding="utf-8").splitlines()
            if "scan initiated" not in line.lower()
        )
        + "\n",
        encoding="utf-8",
    )
    _all_not_recorded(inventory_nmap.parse_file(dest))


def test_k8s_falco_time_and_missing(tmp_path: Path) -> None:
    recs = k8s_kubescape.parse_file(DEMO / "k8s" / "falco.jsonl")
    assert _dates(recs) == {"2026-09-18"}
    dest = tmp_path / "falco.jsonl"
    lines = []
    for line in (DEMO / "k8s" / "falco.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        row.pop("time", None)
        lines.append(json.dumps(row))
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _all_not_recorded(k8s_kubescape.parse_file(dest))


def test_vuln_scan_testssl_at_and_missing(tmp_path: Path) -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "testssl.json")
    assert "2026-09-12" in _dates(recs)
    payload = json.loads((DEMO / "vuln" / "testssl.json").read_text(encoding="utf-8"))
    payload.pop("at", None)
    dest = tmp_path / "testssl.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(vuln_scan.parse_file(dest))


def test_vuln_scan_greenbone_timestamp_and_missing(tmp_path: Path) -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "greenbone.json")
    assert _dates(recs) == {"2026-09-15"}
    payload = json.loads((DEMO / "vuln" / "greenbone.json").read_text(encoding="utf-8"))
    payload.pop("timestamp", None)
    payload.pop("scan_start", None)
    dest = tmp_path / "greenbone.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(vuln_scan.parse_file(dest))


def test_nessus_host_start_timestamp_and_missing() -> None:
    with_ts = """<NessusClientData_v2><Report name="t"><ReportHost name="10.0.0.9">
    <HostProperties>
      <tag name="HOST_START_TIMESTAMP">1789043400</tag>
    </HostProperties>
    <ReportItem port="443" svc_name="www" protocol="tcp" severity="3" pluginID="42411" pluginName="SMB">
    <risk_factor>High</risk_factor></ReportItem>
    </ReportHost></Report></NessusClientData_v2>"""
    rows = iter_nessus_items(with_ts)
    assert len(rows) == 1
    assert format_detection_date(rows[0].get("scan_time")) == "2026-09-10"
    missing = """<NessusClientData_v2><Report name="t"><ReportHost name="10.0.0.9">
    <HostProperties></HostProperties>
    <ReportItem port="443" svc_name="www" protocol="tcp" severity="3" pluginID="42411" pluginName="SMB">
    <risk_factor>High</risk_factor></ReportItem>
    </ReportHost></Report></NessusClientData_v2>"""
    rows2 = iter_nessus_items(missing)
    assert len(rows2) == 1
    assert format_detection_date(rows2[0].get("scan_time")) == NOT_RECORDED


def test_openscap_start_time_and_missing(tmp_path: Path) -> None:
    recs = host_wazuh.parse_file(LAB_DROP / "wazuh" / "openscap-lab-jump.xml")
    assert _dates(recs) == {"2026-09-25"}
    dest = tmp_path / "openscap.xml"
    dest.write_text(
        (LAB_DROP / "wazuh" / "openscap-lab-jump.xml")
        .read_text(encoding="utf-8")
        .replace(' start-time="2026-09-25T00:00:00+00:00"', ""),
        encoding="utf-8",
    )
    _all_not_recorded(host_wazuh.parse_file(dest))
    rows = iter_openscap_failures(dest.read_text(encoding="utf-8"))
    assert rows
    assert all(format_detection_date((r.get("extra") or {}).get("scan_time")) == NOT_RECORDED for r in rows)


def test_masscan_start_and_missing(tmp_path: Path) -> None:
    recs = inventory_nmap.parse_file(DEMO / "nmap" / "masscan.xml")
    assert _dates(recs) == {"2026-09-10"}
    dest = tmp_path / "masscan.xml"
    dest.write_text(
        (DEMO / "nmap" / "masscan.xml")
        .read_text(encoding="utf-8")
        .replace(' start="1789041660" startstr="Thu Sep 10 12:01:00 2026"', "")
        .replace(' endtime="1789041661"', "")
        .replace(' time="1789041661" timestr="Thu Sep 10 12:01:01 2026"', ""),
        encoding="utf-8",
    )
    parsed = parse_masscan(dest, dest.read_text(encoding="utf-8"))
    assert parsed
    assert all(format_detection_date(h.get("scan_time")) == NOT_RECORDED for h in parsed)
    _all_not_recorded(inventory_nmap.parse_file(dest))


# --- seven tools that do emit a timestamp ---


def test_nikto_start_time_and_missing(tmp_path: Path) -> None:
    recs = vuln_scan.parse_file(DEMO / "vuln" / "nikto.txt")
    assert _dates(recs) == {"2026-09-04"}
    dest = tmp_path / "nikto.txt"
    dest.write_text(
        (DEMO / "vuln" / "nikto.txt")
        .read_text(encoding="utf-8")
        .replace("+ Start Time:         2026-09-04 17:00:00 (GMT0)\n", ""),
        encoding="utf-8",
    )
    _all_not_recorded(vuln_scan.parse_file(dest))


def test_naabu_timestamp_and_missing(tmp_path: Path) -> None:
    recs = inventory_nmap.parse_file(DEMO / "nmap" / "naabu.jsonl")
    assert _dates(recs) == {"2026-09-09"}
    dest = tmp_path / "naabu.jsonl"
    row = json.loads((DEMO / "nmap" / "naabu.jsonl").read_text(encoding="utf-8"))
    row.pop("timestamp", None)
    dest.write_text(json.dumps(row) + "\n", encoding="utf-8")
    _all_not_recorded(inventory_nmap.parse_file(dest))


def test_ffuf_time_and_missing(tmp_path: Path) -> None:
    recs = easm.parse_file(DEMO / "easm" / "ffuf.json")
    assert _dates(recs) == {"2026-09-07"}
    payload = json.loads((DEMO / "easm" / "ffuf.json").read_text(encoding="utf-8"))
    payload.pop("time", None)
    dest = tmp_path / "ffuf.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(easm.parse_file(dest))


def test_kubescape_generation_time_and_missing(tmp_path: Path) -> None:
    recs = k8s_kubescape.parse_file(DEMO / "k8s" / "kubescape.json")
    assert _dates(recs) == {"2026-09-20"}
    payload = json.loads((DEMO / "k8s" / "kubescape.json").read_text(encoding="utf-8"))
    payload.pop("generationTime", None)
    dest = tmp_path / "kubescape.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(k8s_kubescape.parse_file(dest))


def test_scoutsuite_last_run_time_and_missing(tmp_path: Path) -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "scoutsuite.json")
    assert _dates(recs) == {"2026-09-22"}
    payload = json.loads((DEMO / "cloud" / "scoutsuite.json").read_text(encoding="utf-8"))
    payload.pop("last_run", None)
    dest = tmp_path / "scoutsuite.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(cloud_prowler.parse_file(dest))


def test_maester_executed_at_and_missing(tmp_path: Path) -> None:
    recs = saas_idp.parse_file(DEMO / "saas" / "maester.json")
    assert _dates(recs) == {"2026-09-23"}
    payload = json.loads((DEMO / "saas" / "maester.json").read_text(encoding="utf-8"))
    payload.pop("ExecutedAt", None)
    dest = tmp_path / "maester.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(saas_idp.parse_file(dest))


def test_custodian_execution_start_and_missing(tmp_path: Path) -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "custodian.json")
    assert _dates(recs) == {"2026-09-24"}
    payload = json.loads((DEMO / "cloud" / "custodian.json").read_text(encoding="utf-8"))
    payload.pop("execution", None)
    dest = tmp_path / "custodian.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    _all_not_recorded(cloud_prowler.parse_file(dest))
    sample = cloud_prowler.parse_file(SAMPLES / "cloud" / "s3-encryption-missing" / "resources.json")
    assert _dates(sample) == {"2026-09-24"}
