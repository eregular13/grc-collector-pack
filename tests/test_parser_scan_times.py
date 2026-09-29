"""Per-parser scan-time extraction: real field → date; missing → not recorded.

Covers the 11 production parsers this PR changes, plus the seven tools
that do emit a timestamp (kubescape, ScoutSuite, Maester, naabu, Custodian,
nikto, ffuf). Never uses the pack run date.
"""

from __future__ import annotations

import itertools
import json
import os
import threading
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

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
from collectors import grc_loader
from shared.masscan import parse_masscan
from shared.nessus import iter_nessus_items
from shared.openscap import iter_openscap_failures
from shared.fast_portscan import parse_fast_portscan
from shared.nikto import _nikto_start_time, parse_nikto
from shared.scan_time import (
    NOT_RECORDED,
    _RUN_CLOCK,
    bind_run_clock,
    earlier_scan_raw,
    epoch_cutoff_date,
    extra_scan_raw,
    format_detection_date,
    parse_scan_datetime,
    zone_for,
)

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


def test_custodian_real_metadata_epoch_float() -> None:
    """c7n writes execution.start as time.time() float — not an ISO string."""
    ebs = cloud_prowler.parse_file(
        SAMPLES / "cloud" / "check-ebs-snapshot-public" / "resources.json"
    )
    assert _dates(ebs) == {"2026-05-02"}
    for rec in _findings(ebs):
        assert format_detection_date(extra_scan_raw(rec)) == "2026-05-02"
    pods = cloud_prowler.parse_file(
        SAMPLES / "cloud" / "security-context-pods" / "resources.json"
    )
    assert _dates(pods) == {"2023-07-05"}
    for rec in _findings(pods):
        assert format_detection_date(extra_scan_raw(rec)) == "2023-07-05"


def test_custodian_iso_string_still_accepted(tmp_path: Path) -> None:
    dest = tmp_path / "custodian.json"
    dest.write_text(
        json.dumps(
            {
                "execution": {"start": "2026-09-24T15:00:00.000000+00:00"},
                "policies": [
                    {
                        "name": "s3-encryption-missing",
                        "resource": "aws.s3",
                        "severity": "high",
                        "description": "S3 bucket without default encryption",
                        "resources": [
                            {
                                "Name": "demo-unencrypted-tmp",
                                "Arn": "arn:aws:s3:::demo-unencrypted-tmp",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert _dates(cloud_prowler.parse_file(dest)) == {"2026-09-24"}


def test_epoch_float_string_and_implausible_epochs() -> None:
    assert format_detection_date(1777719763.7834156) == "2026-05-02"
    assert format_detection_date("1777719763.7834156") == "2026-05-02"
    assert format_detection_date(1688566785.685432) == "2023-07-05"
    assert format_detection_date(12345) == NOT_RECORDED
    assert format_detection_date("12345") == NOT_RECORDED
    assert format_detection_date(0) == NOT_RECORDED
    assert format_detection_date(4_000_000_000) == NOT_RECORDED


def test_naabu_uses_earliest_timestamp_regardless_of_order(tmp_path: Path) -> None:
    """One host, three records: earliest observation wins, not first/last in file."""
    earliest = "2026-09-02T00:00:00Z"
    later = "2026-09-15T00:00:00Z"
    latest = "2026-09-20T00:00:00Z"
    rows = [
        {
            "ip": "10.0.0.50",
            "host": "filesrv.corp.local",
            "port": 23,
            "protocol": "tcp",
            "timestamp": later,
        },
        {
            "ip": "10.0.0.50",
            "host": "filesrv.corp.local",
            "port": 3389,
            "protocol": "tcp",
            "timestamp": earliest,
        },
        {
            "ip": "10.0.0.50",
            "host": "filesrv.corp.local",
            "port": 445,
            "protocol": "tcp",
            "timestamp": latest,
        },
    ]
    # Every file order — first-seen, last-seen, and the four mixed orders.
    for i, ordered in enumerate(itertools.permutations(rows)):
        dest = tmp_path / f"naabu-order-{i}.jsonl"
        dest.write_text("\n".join(json.dumps(r) for r in ordered) + "\n", encoding="utf-8")
        first_in_file = ordered[0]["timestamp"]
        last_in_file = ordered[-1]["timestamp"]
        hosts = parse_fast_portscan(dest)
        assert hosts and len(hosts) == 1
        assert hosts[0]["scan_time"] == earliest
        assert hosts[0]["scan_time"] != first_in_file or first_in_file == earliest
        assert hosts[0]["scan_time"] != last_in_file or last_in_file == earliest
        recs = inventory_nmap.parse_file(dest)
        port_finds = [
            r
            for r in _findings(recs)
            if str((r.get("extra") or {}).get("port") or "") in {"23", "3389", "445"}
        ]
        assert {str((r.get("extra") or {}).get("port")) for r in port_finds} == {
            "23",
            "3389",
            "445",
        }
        for rec in port_finds:
            assert format_detection_date((rec.get("extra") or {}).get("scan_time")) == "2026-09-02"
        assert _dates(recs) == {"2026-09-02"}


def test_naabu_mixed_naive_and_aware_timestamps_do_not_crash(tmp_path: Path) -> None:
    """Master crashed TypeError on naive vs aware. Naive is UTC; earliest wins."""
    naive_later = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 23,
        "protocol": "tcp",
        "timestamp": "2026-09-15T00:00:00",
    }
    aware_earlier = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 3389,
        "protocol": "tcp",
        "timestamp": "2026-09-02T00:00:00Z",
    }
    for i, rows in enumerate(((naive_later, aware_earlier), (aware_earlier, naive_later))):
        dest = tmp_path / f"naabu-mixed-{i}.jsonl"
        dest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        hosts = parse_fast_portscan(dest)
        assert hosts and len(hosts) == 1
        assert hosts[0]["scan_time"] == "2026-09-02T00:00:00Z"
        recs = inventory_nmap.parse_file(dest)
        assert _dates(recs) == {"2026-09-02"}


def test_naabu_same_utc_instant_breaks_tie_on_local_date(tmp_path: Path) -> None:
    """00:30+05:30 and 19:00Z the previous day are one instant; keep 09-01."""
    offset = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 22,
        "protocol": "tcp",
        "timestamp": "2026-09-02T00:30:00+05:30",
    }
    zulu = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 80,
        "protocol": "tcp",
        "timestamp": "2026-09-01T19:00:00Z",
    }
    for i, rows in enumerate(((offset, zulu), (zulu, offset))):
        dest = tmp_path / f"naabu-tie-{i}.jsonl"
        dest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        hosts = parse_fast_portscan(dest)
        assert hosts and len(hosts) == 1
        assert hosts[0]["scan_time"] == "2026-09-01T19:00:00Z"


def test_naabu_full_tie_raw_stamp_is_order_independent(tmp_path: Path) -> None:
    """Same instant + same local date: lexicographically smaller raw stamp wins."""
    zulu = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 22,
        "protocol": "tcp",
        "timestamp": "2026-09-01T12:00:00Z",
    }
    offset = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 80,
        "protocol": "tcp",
        "timestamp": "2026-09-01T12:00:00+00:00",
    }
    expected = min(zulu["timestamp"], offset["timestamp"])
    assert expected == "2026-09-01T12:00:00+00:00"
    for i, rows in enumerate(((zulu, offset), (offset, zulu))):
        dest = tmp_path / f"naabu-raw-tie-{i}.jsonl"
        dest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        hosts = parse_fast_portscan(dest)
        assert hosts and len(hosts) == 1
        assert hosts[0]["scan_time"] == expected


def test_naabu_epoch_vs_negative_offset_keeps_earlier_local_date(tmp_path: Path) -> None:
    """Same instant: epoch 09-02 03:00Z vs 20:00-07:00. Local date 09-01 wins.

    Lex of the raw strings would pick the epoch (``1788318000`` < ISO),
    so this case is not masked by the raw-string tie. Removing the
    local-date rule would store 09-02.
    """
    epoch = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 22,
        "protocol": "tcp",
        "timestamp": 1_788_318_000,  # 2026-09-02T03:00:00Z
    }
    evening = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 80,
        "protocol": "tcp",
        "timestamp": "2026-09-01T20:00:00-07:00",
    }
    assert str(epoch["timestamp"]) < evening["timestamp"]
    for i, rows in enumerate(((epoch, evening), (evening, epoch))):
        dest = tmp_path / f"naabu-epoch-local-{i}.jsonl"
        dest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        hosts = parse_fast_portscan(dest)
        assert hosts and len(hosts) == 1
        assert hosts[0]["scan_time"] == evening["timestamp"]
        assert format_detection_date(hosts[0]["scan_time"]) == "2026-09-01"
        recs = inventory_nmap.parse_file(dest)
        assert _dates(recs) == {"2026-09-01"}


def test_naabu_later_lex_smaller_stamp_does_not_win(tmp_path: Path) -> None:
    """Later 12:30-07:00 sorts before 19:00Z; earlier stamp wins both orders."""
    later = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 22,
        "protocol": "tcp",
        "timestamp": "2026-09-01T12:30:00-07:00",  # 19:30Z
    }
    earlier = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 80,
        "protocol": "tcp",
        "timestamp": "2026-09-01T19:00:00Z",
    }
    assert later["timestamp"] < earlier["timestamp"]
    for i, rows in enumerate(((later, earlier), (earlier, later))):
        dest = tmp_path / f"naabu-lex-later-{i}.jsonl"
        dest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        hosts = parse_fast_portscan(dest)
        assert hosts and len(hosts) == 1
        assert hosts[0]["scan_time"] == earlier["timestamp"]


def test_naabu_full_tie_prefers_zoned_stamp_over_naive(tmp_path: Path) -> None:
    """Same instant: keep Z / offset, not the zoneless string (artifact-local)."""
    naive = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 22,
        "protocol": "tcp",
        "timestamp": "2026-09-01T19:00:00",
    }
    zulu = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 80,
        "protocol": "tcp",
        "timestamp": "2026-09-01T19:00:00Z",
    }
    assert naive["timestamp"] < zulu["timestamp"]
    assert earlier_scan_raw(naive["timestamp"], zulu["timestamp"]) == zulu["timestamp"]
    assert earlier_scan_raw(zulu["timestamp"], naive["timestamp"]) == zulu["timestamp"]
    for i, rows in enumerate(((naive, zulu), (zulu, naive))):
        dest = tmp_path / f"naabu-zoned-tie-{i}.jsonl"
        dest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        hosts = parse_fast_portscan(dest)
        assert hosts and len(hosts) == 1
        assert hosts[0]["scan_time"] == zulu["timestamp"]
        assert zone_for(hosts[0]["scan_time"]) == "UTC"


def test_unparseable_incoming_does_not_replace_parseable(tmp_path: Path) -> None:
    """#205: garbage / empty never overwrites a dated stamp (either order)."""
    good = "2026-09-02T00:00:00Z"
    assert earlier_scan_raw(good, "not-a-clock") == good
    assert earlier_scan_raw(good, "xyz") == good
    assert earlier_scan_raw("garbage", good) == good
    parseable = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 22,
        "protocol": "tcp",
        "timestamp": good,
    }
    junk = {
        "ip": "10.0.0.50",
        "host": "filesrv.corp.local",
        "port": 80,
        "protocol": "tcp",
        "timestamp": "not-a-clock",
    }
    for i, rows in enumerate(((parseable, junk), (junk, parseable))):
        dest = tmp_path / f"naabu-garbage-{i}.jsonl"
        dest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        hosts = parse_fast_portscan(dest)
        assert hosts and len(hosts) == 1
        assert hosts[0]["scan_time"] == good
        recs = inventory_nmap.parse_file(dest)
        assert _dates(recs) == {"2026-09-02"}


def test_seven_tools_malformed_values_are_not_recorded(tmp_path: Path) -> None:
    cases = [
        (
            k8s_kubescape.parse_file,
            DEMO / "k8s" / "kubescape.json",
            tmp_path / "ks.json",
            lambda p: {**p, "generationTime": "not-a-time"},
        ),
        (
            cloud_prowler.parse_file,
            DEMO / "cloud" / "scoutsuite.json",
            tmp_path / "scout.json",
            lambda p: {**p, "last_run": {"time": "garbage"}},
        ),
        (
            saas_idp.parse_file,
            DEMO / "saas" / "maester.json",
            tmp_path / "mae.json",
            lambda p: {**p, "ExecutedAt": ""},
        ),
        (
            easm.parse_file,
            DEMO / "easm" / "ffuf.json",
            tmp_path / "ff.json",
            lambda p: {**p, "time": "??"},
        ),
        (
            cloud_prowler.parse_file,
            DEMO / "cloud" / "custodian.json",
            tmp_path / "c7n.json",
            lambda p: {**p, "execution": {"start": "nope"}},
        ),
    ]
    for parse, src, dest, mutate in cases:
        payload = json.loads(src.read_text(encoding="utf-8"))
        dest.write_text(json.dumps(mutate(payload)), encoding="utf-8")
        _all_not_recorded(parse(dest))
    dest = tmp_path / "naabu-bad.jsonl"
    dest.write_text(
        json.dumps(
            {
                "ip": "10.0.0.50",
                "host": "filesrv.corp.local",
                "port": 23,
                "protocol": "tcp",
                "timestamp": "xyz",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _all_not_recorded(inventory_nmap.parse_file(dest))
    dest = tmp_path / "nikto-bad.txt"
    dest.write_text(
        (DEMO / "vuln" / "nikto.txt")
        .read_text(encoding="utf-8")
        .replace("2026-09-04 17:00:00 (GMT0)", "not-a-clock"),
        encoding="utf-8",
    )
    _all_not_recorded(vuln_scan.parse_file(dest))


def test_seven_tools_timezone_offsets() -> None:
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as td:
        path = Path(td)
        nikto = path / "nikto.txt"
        nikto.write_text(
            (DEMO / "vuln" / "nikto.txt")
            .read_text(encoding="utf-8")
            .replace("(GMT0)", "(GMT-7)"),
            encoding="utf-8",
        )
        recs = vuln_scan.parse_file(nikto)
        assert _dates(recs) == {"2026-09-04"}
        hit = _findings(recs)[0]
        assert zone_for(extra_scan_raw(hit)) == "UTC-07:00"

        ks = path / "kubescape.json"
        payload = json.loads((DEMO / "k8s" / "kubescape.json").read_text(encoding="utf-8"))
        payload["generationTime"] = "2026-09-20T16:00:00-07:00"
        ks.write_text(json.dumps(payload), encoding="utf-8")
        recs = k8s_kubescape.parse_file(ks)
        assert _dates(recs) == {"2026-09-20"}
        assert zone_for(extra_scan_raw(_findings(recs)[0])) == "UTC-07:00"

        ff = path / "ffuf.json"
        payload = json.loads((DEMO / "easm" / "ffuf.json").read_text(encoding="utf-8"))
        payload["time"] = "2026-09-07T16:00:00+02:00"
        ff.write_text(json.dumps(payload), encoding="utf-8")
        recs = easm.parse_file(ff)
        assert _dates(recs) == {"2026-09-07"}
        assert zone_for(extra_scan_raw(_findings(recs)[0])) == "UTC+02:00"


# --- future-epoch cutoff is the run clock, not parse-time wall-clock ---

_RUN = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


def _epoch_at(day: date, hour: int = 0) -> int:
    return int(datetime(day.year, day.month, day.day, hour, tzinfo=timezone.utc).timestamp())


def test_future_epoch_cutoff_uses_injected_run_clock_not_wall_clock() -> None:
    """Same epoch is dated or rejected solely from the injected run start."""
    mid_2026 = 1_777_719_763  # 2026-05-02 — "now" on this VM is later in 2026
    early_run = datetime(2020, 1, 1, tzinfo=timezone.utc)
    late_run = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
    assert format_detection_date(mid_2026, now=late_run) == "2026-05-02"
    assert format_detection_date(mid_2026, now=early_run) == NOT_RECORDED
    with bind_run_clock(early_run):
        assert format_detection_date(mid_2026) == NOT_RECORDED
        assert parse_scan_datetime(mid_2026) is None
    with bind_run_clock(late_run):
        assert format_detection_date(mid_2026) == "2026-05-02"
        parsed = parse_scan_datetime(mid_2026)
        assert parsed is not None
        assert parsed[0].date() == date(2026, 5, 2)


def test_future_epoch_cutoff_boundary_cases() -> None:
    """Inclusive run_date+1 day; exclusive run_date+2 days; 2000-01-01 floor."""
    run = _RUN
    run_day = run.date()
    plus_one = run_day + timedelta(days=1)
    plus_two = run_day + timedelta(days=2)
    assert epoch_cutoff_date(run) == plus_one
    # On the last accepted calendar day (any hour).
    assert format_detection_date(_epoch_at(plus_one, 0), now=run) == plus_one.isoformat()
    assert format_detection_date(_epoch_at(plus_one, 23), now=run) == plus_one.isoformat()
    # First rejected calendar day.
    assert format_detection_date(_epoch_at(plus_two, 0), now=run) == NOT_RECORDED
    # Run day itself and the second before midnight of plus_one.
    assert format_detection_date(_epoch_at(run_day, 12), now=run) == run_day.isoformat()
    just_inside = int(datetime(plus_one.year, plus_one.month, plus_one.day, 23, 59, 59, tzinfo=timezone.utc).timestamp())
    just_outside = just_inside + 1  # 2026-10-01T00:00:00Z
    assert format_detection_date(just_inside, now=run) == plus_one.isoformat()
    assert format_detection_date(just_outside, now=run) == NOT_RECORDED
    # Floor: 2000-01-01 00:00:00Z in, one second earlier out.
    assert format_detection_date(946_684_800, now=run) == "2000-01-01"
    assert format_detection_date(946_684_799, now=run) == NOT_RECORDED
    assert format_detection_date(12345, now=run) == NOT_RECORDED
    assert format_detection_date(0, now=run) == NOT_RECORDED
    # Float string still honors the injected clock.
    assert format_detection_date(str(float(_epoch_at(plus_two))), now=run) == NOT_RECORDED
    assert format_detection_date(f"{_epoch_at(plus_one)}.5", now=run) == plus_one.isoformat()


def test_future_epoch_cutoff_bind_survives_nested_parse() -> None:
    """Pipeline-style bind: cutoff is the bound run, even if wall-clock moved."""
    run = datetime(2018, 6, 15, tzinfo=timezone.utc)
    year_2019 = 1_546_300_800  # 2019-01-01
    with bind_run_clock(run):
        assert format_detection_date(year_2019) == NOT_RECORDED
        # Explicit now= overrides the bind (call-site injection wins).
        later = datetime(2020, 1, 2, tzinfo=timezone.utc)
        assert format_detection_date(year_2019, now=later) == "2019-01-01"


# --- nikto half-hour / 45-minute offsets ---

_NIKTO_OFFSET_CASES = (
    ("(GMT+5:30)", "UTC+05:30", "+05:30"),
    ("(GMT+05:30)", "UTC+05:30", "+05:30"),
    ("(GMT+0530)", "UTC+05:30", "+05:30"),
    ("(GMT0530)", "UTC+05:30", "+05:30"),
    ("(GMT-3:30)", "UTC-03:30", "-03:30"),
    ("(GMT-03:30)", "UTC-03:30", "-03:30"),
    ("(GMT+5:45)", "UTC+05:45", "+05:45"),
    ("(GMT+0545)", "UTC+05:45", "+05:45"),
)


def test_nikto_start_time_half_hour_and_45_minute_offsets(tmp_path: Path) -> None:
    """+05:30 / -03:30 / +05:45 stay on 2026-09-04 with the recorded offset."""
    demo = (DEMO / "vuln" / "nikto.txt").read_text(encoding="utf-8")
    for gmt, zone, iso_off in _NIKTO_OFFSET_CASES:
        assert _nikto_start_time(f"2026-09-04 17:00:00 {gmt}") == f"2026-09-04 17:00:00{iso_off}"
        dest = tmp_path / f"nikto-{zone.replace(':', '')}.txt"
        dest.write_text(demo.replace("(GMT0)", gmt), encoding="utf-8")
        recs = vuln_scan.parse_file(dest)
        assert _dates(recs) == {"2026-09-04"}, gmt
        hit = _findings(recs)[0]
        raw = extra_scan_raw(hit)
        assert zone_for(raw) == zone, (gmt, raw)
        parsed = parse_scan_datetime(raw)
        assert parsed is not None
        assert parsed[0].date() == date(2026, 9, 4)
        sign = 1 if iso_off[0] == "+" else -1
        assert parsed[0].utcoffset() == timedelta(
            hours=sign * int(iso_off[1:3]), minutes=sign * int(iso_off[4:6])
        )
        rows = parse_nikto(dest)
        assert rows
        assert all(r.get("scan_time", "").endswith(iso_off) for r in rows if r.get("scan_time"))


def test_nikto_integer_hour_offsets_still_parse() -> None:
    assert _nikto_start_time("2026-09-04 17:00:00 (GMT0)") == "2026-09-04 17:00:00+00:00"
    assert _nikto_start_time("2026-09-04 17:00:00 (GMT-7)") == "2026-09-04 17:00:00-07:00"
    assert _nikto_start_time("2026-09-04 17:00:00 (GMT+14)") == "2026-09-04 17:00:00+14:00"
    assert zone_for(_nikto_start_time("2026-09-04 17:00:00 (GMT-7)")) == "UTC-07:00"


_NIKTO_REAL_DECIMAL = (
    ("(GMT5.5)", "UTC+05:30", "+05:30"),
    ("(GMT-2.5)", "UTC-02:30", "-02:30"),
    ("(GMT5.75)", "UTC+05:45", "+05:45"),
    ("(GMT13.75)", "UTC+13:45", "+13:45"),
    ("(GMT+5.5)", "UTC+05:30", "+05:30"),
)


def test_nikto_real_decimal_hour_offsets(tmp_path: Path) -> None:
    """Nikto gmt_offset() prints decimal hours, often unsigned: (GMT5.5)."""
    demo = (DEMO / "vuln" / "nikto.txt").read_text(encoding="utf-8")
    for gmt, zone, iso_off in _NIKTO_REAL_DECIMAL:
        assert _nikto_start_time(f"2026-09-04 17:00:00 {gmt}") == f"2026-09-04 17:00:00{iso_off}"
        dest = tmp_path / f"nikto-dec-{zone.replace(':', '').replace('+', 'p').replace('-', 'm')}.txt"
        dest.write_text(demo.replace("(GMT0)", gmt), encoding="utf-8")
        recs = vuln_scan.parse_file(dest)
        assert _dates(recs) == {"2026-09-04"}, gmt
        raw = extra_scan_raw(_findings(recs)[0])
        assert zone_for(raw) == zone, (gmt, raw)
        parsed = parse_scan_datetime(raw)
        assert parsed is not None
        assert parsed[0].date() == date(2026, 9, 4)
        sign = 1 if iso_off[0] == "+" else -1
        assert parsed[0].utcoffset() == timedelta(
            hours=sign * int(iso_off[1:3]), minutes=sign * int(iso_off[4:6])
        )


def test_nikto_offset_range_guards() -> None:
    """hours > 14, minutes at +14, below −12, and invalid fractions stay raw."""
    body = "2026-09-04 17:00:00"
    rejected = (
        f"{body} (GMT15)",
        f"{body} (GMT+15)",
        f"{body} (GMT+99)",
        f"{body} (GMT5.3)",
        f"{body} (GMT5.1)",
        f"{body} (GMT-2.3)",
        f"{body} (GMT+5:60)",
        f"{body} (GMT+5:99)",
        f"{body} (GMT5.25)",
        f"{body} (GMT0559)",
        f"{body} (GMT1259)",
        f"{body} (GMT0515)",
        f"{body} (GMT+5:15)",
        f"{body} (GMT14.5)",
        f"{body} (GMT14.25)",
        f"{body} (GMT+1430)",
        f"{body} (GMT+14:30)",
        f"{body} (GMT-14)",
        f"{body} (GMT-12.5)",
        f"{body} (GMT5.749)",
        f"{body} (GMT5.751)",
        f"{body} (GMT5.٥)",
        f"{body} (GMT５.5)",
    )
    for raw in rejected:
        assert _nikto_start_time(raw) == raw, raw
        assert zone_for(_nikto_start_time(raw)) == "artifact-local"
    assert _nikto_start_time(f"{body} (GMT14)") == f"{body}+14:00"
    assert _nikto_start_time(f"{body} (GMT-12)") == f"{body}-12:00"
    assert _nikto_start_time(f"{body} (GMT5.5)") == f"{body}+05:30"
    assert _nikto_start_time(f"{body} (GMT-2.5)") == f"{body}-02:30"
    assert _nikto_start_time(f"{body} (GMT0530)") == f"{body}+05:30"
    assert _nikto_start_time(f"{body} (GMT+0530)") == f"{body}+05:30"
    assert zone_for(_nikto_start_time(f"{body} (GMT0530)")) == "UTC+05:30"


# --- run-clock lifetime (kills never-reset / set(None) / no-finally / no-bind) ---

_JUN_2020 = 1_591_056_000  # 2020-06-02T00:00:00Z


def test_bind_run_clock_resets_on_exception() -> None:
    """finally always unbinds — even when the body raises."""
    clock = datetime(2018, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(RuntimeError):
        with bind_run_clock(clock):
            assert _RUN_CLOCK.get() is not None
            raise RuntimeError("parse failed")
    assert _RUN_CLOCK.get() is None


def test_nested_bind_restores_outer_clock() -> None:
    """Inner 2020 unbinds back to outer 2018; 2020-06-02 is future again."""
    outer = datetime(2018, 1, 1, tzinfo=timezone.utc)
    inner = datetime(2020, 12, 1, tzinfo=timezone.utc)
    with bind_run_clock(outer):
        assert format_detection_date(_JUN_2020) == NOT_RECORDED
        with bind_run_clock(inner):
            assert format_detection_date(_JUN_2020) == "2020-06-02"
        assert format_detection_date(_JUN_2020) == NOT_RECORDED
        assert _RUN_CLOCK.get() == datetime(2018, 1, 1, tzinfo=timezone.utc)
    assert _RUN_CLOCK.get() is None


def test_load_binds_and_unbinds_run_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """load() binds a clock for _load and leaves the var None afterwards."""
    seen: list[datetime | None] = []

    def fake_load() -> dict:
        seen.append(_RUN_CLOCK.get())
        return {"ok": True}

    monkeypatch.setattr(grc_loader, "_load", fake_load)
    assert grc_loader.load() == {"ok": True}
    assert len(seen) == 1
    assert seen[0] is not None
    assert seen[0].tzinfo is not None
    assert _RUN_CLOCK.get() is None

    def boom() -> dict:
        seen.append(_RUN_CLOCK.get())
        raise RuntimeError("load failed")

    monkeypatch.setattr(grc_loader, "_load", boom)
    with pytest.raises(RuntimeError, match="load failed"):
        grc_loader.load()
    assert seen[-1] is not None
    assert _RUN_CLOCK.get() is None


def test_run_clock_thread_isolation() -> None:
    """Two threads, different clocks, same epoch → different cutoffs."""
    barrier = threading.Barrier(2)
    results: dict[str, str | datetime | None] = {}

    def worker(name: str, clock: datetime) -> None:
        with bind_run_clock(clock):
            barrier.wait()
            results[name] = format_detection_date(_JUN_2020)
            barrier.wait()
        results[f"{name}_after"] = _RUN_CLOCK.get()

    early = datetime(2018, 1, 1, tzinfo=timezone.utc)
    late = datetime(2020, 12, 1, tzinfo=timezone.utc)
    t1 = threading.Thread(target=worker, args=("early", early))
    t2 = threading.Thread(target=worker, args=("late", late))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert results["early"] == NOT_RECORDED
    assert results["late"] == "2020-06-02"
    assert results["early_after"] is None
    assert results["late_after"] is None
    assert _RUN_CLOCK.get() is None


def test_future_epoch_cutoff_naive_clock_is_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Naive now= is UTC. TZ=PT + naive 20:00 would be next-day UTC if local.

    ``time.tzset`` is POSIX-only. On Windows the TZ pin is skipped; the
    naive=UTC and aware-PT assertions still run.
    """
    has_tzset = hasattr(time, "tzset")
    prev_tz = os.environ.get("TZ")
    if has_tzset:
        monkeypatch.setenv("TZ", "America/Los_Angeles")
        time.tzset()
    try:
        naive = datetime(2020, 1, 1, 20, 0, 0)  # no tzinfo — 20:00 UTC, not PT
        mid_2026 = 1_777_719_763
        # Naive = UTC → 2020-01-01 20:00Z → cutoff 2020-01-02.
        # Naive as PT (PST, UTC-8) → 2020-01-02 04:00Z → cutoff 2020-01-03.
        assert epoch_cutoff_date(naive) == date(2020, 1, 2)
        assert format_detection_date(mid_2026, now=naive) == NOT_RECORDED
        jan2 = int(datetime(2020, 1, 2, 12, 0, tzinfo=timezone.utc).timestamp())
        jan3 = int(datetime(2020, 1, 3, 0, 0, tzinfo=timezone.utc).timestamp())
        assert format_detection_date(jan2, now=naive) == "2020-01-02"
        assert format_detection_date(jan3, now=naive) == NOT_RECORDED
        pt = timezone(timedelta(hours=-7))
        evening_pt = datetime(2026, 9, 28, 22, 50, tzinfo=pt)  # 05:50Z on 09-29
        assert epoch_cutoff_date(evening_pt) == date(2026, 9, 30)
        assert format_detection_date(mid_2026, now=evening_pt) == "2026-05-02"
    finally:
        if has_tzset:
            if prev_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = prev_tz
            time.tzset()


