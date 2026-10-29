"""prior-unit: demo testssl.json without port must map host/IP → 443 and pass PQ-2 gate."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_load_port_map_reads_plain_testssl_json_defaults_443(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from fixstack.testssl_fix import load_port_map

    raw = tmp_path / "raw_in"
    raw.mkdir()
    (raw / "testssl.json").write_text(
        json.dumps(
            {
                "at": "2026-09-12 14:30:00",
                "scanResult": [
                    {
                        "targetHost": "dev-api.example.com",
                        "ip": "203.0.113.20",
                        "vulnerabilities": [
                            {
                                "id": "heartbleed",
                                "severity": "HIGH",
                                "cve": "CVE-2014-0160",
                                "finding": "Heartbleed still offered on TLS",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    ports = load_port_map(raw, tmp_path / "raw")
    assert ports.get("dev-api.example.com") == "443"
    assert ports.get("203.0.113.20") == "443"



def test_testssl_fix_gate_passes_when_port_map_defaults(tmp_path: Path) -> None:
    """Minimal CSV in/out: bare host + raw testssl.json → every_asset_has_host_port."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from fixstack import testssl_fix as tf

    inn = tmp_path / "in"
    out = tmp_path / "out"
    inn.mkdir()
    (inn / "raw_in").mkdir()
    (inn / "raw").mkdir()
    (inn / "raw_in" / "testssl.json").write_text(
        json.dumps(
            {
                "scanResult": [
                    {
                        "targetHost": "dev-api.example.com",
                        "ip": "203.0.113.20",
                        "vulnerabilities": [
                            {
                                "id": "heartbleed",
                                "severity": "HIGH",
                                "finding": "Heartbleed",
                                "cve": "CVE-2014-0160",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    poam_fields = [
        "poam_id",
        "asset",
        "weakness",
        "weakness_description",
        "weakness_source_id",
        "detector_source",
        "finding_ref_id",
        "original_detection_date",
        "severity",
    ]
    vuln_fields = [
        "ref_id",
        "name",
        "description",
        "severity",
        "assets",
        "detector_source",
    ]
    with (inn / "poam.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=poam_fields)
        w.writeheader()
        w.writerow(
            {
                "poam_id": "EGP-TEST1",
                "asset": "dev-api.example.com",
                "weakness": "TLS stack is vulnerable to Heartbleed",
                "weakness_description": "Heartbleed",
                "weakness_source_id": "testssl:heartbleed",
                "detector_source": "testssl",
                "finding_ref_id": "REF-1",
                "original_detection_date": "2026-09-12",
                "severity": "high",
            }
        )
    with (inn / "vulnerabilities.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=vuln_fields)
        w.writeheader()
        w.writerow(
            {
                "ref_id": "REF-1",
                "name": "Heartbleed",
                "description": "Heartbleed",
                "severity": "high",
                "assets": "dev-api.example.com",
                "detector_source": "testssl",
            }
        )
    # invoke main via argv
    old = sys.argv
    try:
        sys.argv = ["testssl_fix.py", str(inn), str(out)]
        rc = tf.main()
    finally:
        sys.argv = old
    assert rc == 0, (out / "summary.txt").read_text() if (out / "summary.txt").is_file() else rc
    stats = json.loads((out / "stats.json").read_text(encoding="utf-8"))
    assert stats["checks"]["every_asset_has_host_port"] is True
    assert "dev-api.example.com:443" in stats["host_port_check"]["with_port"]
