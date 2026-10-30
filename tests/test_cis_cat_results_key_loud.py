"""Refuse corrupted CIS-CAT results keys that used to silent-zero."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from collectors.host_wazuh import parse_file as parse_wazuh


def _payload() -> dict:
    return {
        "benchmark": "CIS Example Linux Benchmark",
        "target": "app-01.example.test",
        "results": [
            {
                "id": "5.2.10",
                "title": "Ensure SSH PermitRootLogin is no",
                "result": "fail",
                "severity": "high",
            },
            {
                "id": "3.5.1",
                "title": "Ensure a host firewall is installed",
                "result": "pass",
            },
        ],
    }


def test_cis_cat_results_ok_example(tmp_path: Path) -> None:
    good = tmp_path / "cis-cat.example.test.json"
    good.write_text(json.dumps(_payload()), encoding="utf-8")
    rows = parse_wazuh(good)
    findings = [r for r in rows if r.get("kind") == "finding"]
    assert len(findings) == 1
    assert "5.2.10" in (findings[0].get("name") or findings[0].get("description") or "")


def test_cis_cat_results_key_flip_corruption_loud(tmp_path: Path) -> None:
    """Single-bit flip renaming results -> rusults must not silent-zero."""
    bad_payload = json.loads(json.dumps(_payload()))
    bad_payload["rusults"] = bad_payload.pop("results")
    bad = tmp_path / "cis-cat-rusults.example.test.json"
    bad.write_text(json.dumps(bad_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="results"):
        parse_wazuh(bad)


def test_cis_cat_results_key_insert_corruption_loud(tmp_path: Path) -> None:
    bad_payload = json.loads(json.dumps(_payload()))
    bad_payload["rresults"] = bad_payload.pop("results")
    bad = tmp_path / "cis-cat-rresults.example.test.json"
    bad.write_text(json.dumps(bad_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="results"):
        parse_wazuh(bad)
