"""Tests for richer control_map."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import control_map as cm
import emit_risk_register as err


def test_sensor_map_covers_core_env_eval_sensors():
    needed = [
        "sense-surface",
        "sense-http-headers",
        "sense-cleartext-http",
        "sense-ssh-banner",
        "sense-tls",
        "sense-tls-expiry",
        "sense-cookie-flags",
        "sense-cors",
        "sense-service-exposure",
        "sense-git-exposed",
        "sense-dir-listing",
        "sense-http-methods",
        "sense-tech-disclosure",
        "sense-default-page",
        "sense-http-https-redirect",
    ]
    for s in needed:
        h = cm.map_finding(sensor=s, title="x")
        assert h.rule_id != "unmapped", s
        assert "UNMAPPED" not in h.controls
        assert len(h.controls) >= 2
        assert h.action


def test_critical_services_map_high():
    h = cm.map_finding(title="Redis port 6379 reachable", sensor="sense-service-exposure")
    assert h.priority in ("critical", "high")
    assert any("SC-7" in c or "AC-05" in c or "PR.AC" in c for c in h.controls)


def test_smb_and_s3_heuristics():
    assert cm.map_finding(title="SMBv1 enabled").rule_id == "smb-v1"
    assert cm.map_finding(title="S3 bucket public access").rule_id == "s3-public"


def test_git_exposed_critical():
    h = cm.map_finding(sensor="sense-git-exposed", title="Exposed .git/HEAD")
    assert h.priority == "critical"
    assert any("AC-3" in c or "DS-01" in c or "PR.DS" in c for c in h.controls)


def test_catalog_exports_sensors():
    cat = cm.catalog()
    assert len(cat["sensors"]) >= 15
    assert cat["heuristic_count"] >= 8


def test_emit_register_uses_rich_map_and_fields():
    sensory = {
        "findings": [
            {
                "id": "g1",
                "title": "Exposed .git/HEAD over HTTP",
                "severity": "critical",
                "sensor": "sense-git-exposed",
                "target": "https://192.0.2.9/.git/HEAD",
                "description": "git metadata",
                "remediation": "block now",
                "controls": {"NIST_CSF": ["PR.DS-1"]},
            },
            {
                "id": "h1",
                "title": "Missing security headers",
                "severity": "high",
                "sensor": "sense-http-headers",
                "target": "http://192.0.2.9/",
                "description": "no CSP",
            },
        ]
    }
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "s.json"
        p.write_text(json.dumps(sensory))
        rows = err.findings_from_sensory(p)
        assert len(rows) == 2
        git = next(r for r in rows if r["sensor"] == "sense-git-exposed")
        assert git["control_rule"] == "git-exposed"
        assert git["remediation_priority"] == "critical"
        assert "UNMAPPED" not in git["control_refs"]
        assert len(git["control_refs"]) >= 3
        hdr = next(r for r in rows if r["sensor"] == "sense-http-headers")
        assert hdr["control_rule"] == "security-headers"
        out = Path(td) / "out"
        err.write_register(rows, out)
        csv_txt = (out / "risk_register.csv").read_text()
        assert "control_rule" in csv_txt
        assert "remediation_priority" in csv_txt
        assert "git-exposed" in csv_txt
        poam = (out / "poam.csv").read_text()
        assert "control_rule" in poam
