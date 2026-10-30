"""Refuse kubescape controls whose status key was corrupted."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from collectors.k8s_kubescape import parse_file


def _payload(*, status_key: str = "status") -> dict:
    return {
        "summaryDetails": {
            "controls": {
                "C-0041": {
                    "name": "Host network access",
                    status_key: "failed",
                    "severityScore": 7,
                    "description": "deny hostNetwork",
                }
            }
        },
        "resources": [],
    }


def test_kubescape_status_ok(tmp_path: Path) -> None:
    dest = tmp_path / "kubescape.example.test.json"
    dest.write_text(json.dumps(_payload()), encoding="utf-8")
    rows = parse_file(dest)
    findings = [r for r in rows if r.get("kind") == "finding"]
    assert any("C-0041" in (r.get("name") or "") or "C-0041" in str(r.get("extra") or {}) for r in findings)


def test_kubescape_status_key_corruption_loud(tmp_path: Path) -> None:
    dest = tmp_path / "kubescape-3tatus.example.test.json"
    dest.write_text(json.dumps(_payload(status_key="3tatus")), encoding="utf-8")
    with pytest.raises(ValueError, match="status"):
        parse_file(dest)
