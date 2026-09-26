"""Same rule on two assets stays two weaknesses; same asset still collapses.

Parsers used to stamp rule-only ref_ids (nuclei / Trivy / Greenbone / semgrep /
falco / kube-bench / ScubaGear / SARIF). Loader #129 keys
(kind, finding_identity, normalized asset). These tests feed multi-host
tool JSON through the parsers and then the loader key.
"""

from __future__ import annotations

import json
from pathlib import Path

from collectors import code_secrets, k8s_kubescape, saas_idp, vuln_scan
from collectors.grc_loader import _dedupe, load
from shared.finding_types import dedupe_weaknesses, finding_identity, primary_asset
from shared.io_util import write_canonical


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r.get("kind") == "finding"]


def _through_loader(recs: list[dict]) -> list[dict]:
    return _findings(dedupe_weaknesses(_dedupe(recs)))


def test_nuclei_same_template_two_hosts(tmp_path: Path) -> None:
    dest = tmp_path / "nuclei.jsonl"
    dest.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "template-id": "exposed-panel",
                        "info": {"name": "Exposed admin panel", "severity": "high"},
                        "host": "https://app-a.corp.local",
                    }
                ),
                json.dumps(
                    {
                        "template-id": "exposed-panel",
                        "info": {"name": "Exposed admin panel", "severity": "high"},
                        "host": "https://app-b.corp.local",
                    }
                ),
                json.dumps(
                    {
                        "template-id": "exposed-panel",
                        "info": {"name": "Exposed admin panel", "severity": "high"},
                        "host": "https://app-a.corp.local",
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    findings = _findings(recs)
    assert len(findings) == 3
    assert {tuple(r["assets"]) for r in findings} >= {
        ("https://app-a.corp.local",),
        ("https://app-b.corp.local",),
    }
    assert all(r["extra"].get("rule") == "exposed-panel" for r in findings)
    kept = _through_loader(recs)
    assert len(kept) == 2
    assert {primary_asset(r) for r in kept} == {
        "https://app-a.corp.local",
        "https://app-b.corp.local",
    }
    assert {finding_identity(r) for r in kept} == {"exposed-panel"}
    assert len({r["ref_id"] for r in kept}) == 2


def test_trivy_same_cve_two_images(tmp_path: Path) -> None:
    dest = tmp_path / "trivy.json"
    dest.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "alpine:3.19",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-44270",
                                "Title": "postcss",
                                "Severity": "MEDIUM",
                            }
                        ],
                    },
                    {
                        "Target": "debian:12",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-44270",
                                "Title": "postcss",
                                "Severity": "MEDIUM",
                            }
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    kept = _through_loader(recs)
    assert len(kept) == 2
    assert {primary_asset(r) for r in kept} == {"alpine:3.19", "debian:12"}
    assert all(r["extra"].get("cve") == "CVE-2023-44270" for r in kept)
    assert len({r["ref_id"] for r in kept}) == 2


def test_greenbone_same_oid_two_hosts(tmp_path: Path) -> None:
    dest = tmp_path / "greenbone.json"
    dest.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "name": "OpenSSL Heartbleed",
                        "host": "10.0.0.30",
                        "severity": "high",
                        "nvt": {"oid": "1.3.6.1.4.1.25623.1.0.103234"},
                    },
                    {
                        "name": "OpenSSL Heartbleed",
                        "host": "10.0.0.31",
                        "severity": "high",
                        "nvt": {"oid": "1.3.6.1.4.1.25623.1.0.103234"},
                    },
                    {
                        "name": "OpenSSL Heartbleed",
                        "host": "10.0.0.30",
                        "severity": "high",
                        "nvt": {"oid": "1.3.6.1.4.1.25623.1.0.103234"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    kept = _through_loader(recs)
    assert len(kept) == 2
    assert {primary_asset(r) for r in kept} == {"10.0.0.30", "10.0.0.31"}
    assert all(r["extra"].get("rule") == "1.3.6.1.4.1.25623.1.0.103234" for r in kept)


def test_semgrep_same_check_two_files(tmp_path: Path) -> None:
    dest = tmp_path / "semgrep.json"
    dest.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.hardcoded-password",
                        "path": "services/payments/config.py",
                        "extra": {"severity": "WARNING", "message": "hardcoded"},
                    },
                    {
                        "check_id": "python.lang.security.audit.hardcoded-password",
                        "path": "services/auth/config.py",
                        "extra": {"severity": "WARNING", "message": "hardcoded"},
                    },
                    {
                        "check_id": "python.lang.security.audit.hardcoded-password",
                        "path": "services/payments/config.py",
                        "extra": {"severity": "WARNING", "message": "hardcoded"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    recs = code_secrets.parse_file(dest)
    findings = _findings(recs)
    assert all(r["severity"] == "medium" for r in findings)
    kept = _through_loader(recs)
    assert len(kept) == 2
    assert {primary_asset(r) for r in kept} == {
        "services/payments/config.py",
        "services/auth/config.py",
    }


def test_semgrep_error_warning_info_and_low(tmp_path: Path) -> None:
    dest = tmp_path / "sg.json"
    dest.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "a",
                        "path": "a.py",
                        "extra": {"severity": "ERROR", "message": "e"},
                    },
                    {
                        "check_id": "b",
                        "path": "b.py",
                        "extra": {"severity": "WARNING", "message": "w"},
                    },
                    {
                        "check_id": "c",
                        "path": "c.py",
                        "extra": {"severity": "INFO", "message": "i"},
                    },
                    {
                        "check_id": "d",
                        "path": "d.py",
                        "extra": {"severity": "LOW", "message": "l"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    recs = _findings(code_secrets.parse_file(dest))
    by_id = {r["extra"]["check_id"]: r["severity"] for r in recs}
    assert by_id == {"a": "high", "b": "medium", "c": "low", "d": "low"}


def test_falco_same_rule_two_nodes(tmp_path: Path) -> None:
    dest = tmp_path / "falco.jsonl"
    dest.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "hostname": "node-a",
                        "rule": "Write below binary dir",
                        "priority": "Warning",
                        "output": "write on node-a",
                        "output_fields": {"k8s.pod.name": "payments"},
                    }
                ),
                json.dumps(
                    {
                        "hostname": "node-b",
                        "rule": "Write below binary dir",
                        "priority": "Warning",
                        "output": "write on node-b",
                        "output_fields": {"k8s.pod.name": "payments"},
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    recs = k8s_kubescape.parse_file(dest)
    kept = _through_loader(recs)
    assert len(kept) == 2
    assert {primary_asset(r) for r in kept} == {"node-a", "node-b"}
    assert all(r["extra"].get("rule") == "Write below binary dir" for r in kept)
    assert all(r["severity"] == "medium" for r in kept)


def test_kube_bench_same_control_two_nodes(tmp_path: Path) -> None:
    payload = {
        "Controls": [
            {
                "id": "1",
                "tests": [
                    {
                        "results": [
                            {
                                "test_number": "1.2.1",
                                "test_desc": "Anonymous authentication is not enabled",
                                "status": "FAIL",
                                "scored": True,
                                "node_name": "master-a",
                            },
                            {
                                "test_number": "1.2.1",
                                "test_desc": "Anonymous authentication is not enabled",
                                "status": "FAIL",
                                "scored": True,
                                "node_name": "master-b",
                            },
                            {
                                "test_number": "1.2.2",
                                "test_desc": "Token authentication is configured",
                                "status": "WARN",
                                "scored": False,
                                "node_name": "master-a",
                            },
                            {
                                "test_number": "1.2.3",
                                "test_desc": "Unscored fail",
                                "status": "FAIL",
                                "scored": False,
                                "node_name": "master-a",
                            },
                        ]
                    }
                ],
            }
        ]
    }
    dest = tmp_path / "kube-bench-nodes.json"
    dest.write_text(json.dumps(payload), encoding="utf-8")
    recs = k8s_kubescape.parse_file(dest)
    findings = _findings(recs)
    assert len(findings) == 4
    anon = [r for r in findings if r["extra"].get("id") == "1.2.1"]
    assert len(anon) == 2
    assert {primary_asset(r) for r in anon} == {"master-a", "master-b"}
    assert all(r["severity"] == "high" for r in anon)
    warn = next(r for r in findings if r["extra"].get("id") == "1.2.2")
    assert warn["severity"] == "low"
    unscored = next(r for r in findings if r["extra"].get("id") == "1.2.3")
    assert unscored["severity"] == "medium"
    kept = _through_loader(recs)
    assert len(kept) == 4


def test_kubescape_score_factor_not_blanket_medium(tmp_path: Path) -> None:
    dest = tmp_path / "kubescape.json"
    dest.write_text(
        json.dumps(
            {
                "clusterName": "prod",
                "summaryDetails": {
                    "controls": {
                        "C-0057": {
                            "name": "Privileged container",
                            "status": "failed",
                            "scoreFactor": 8,
                        },
                        "C-0090": {
                            "name": "Label missing",
                            "status": "failed",
                            "scoreFactor": 2,
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    findings = _findings(k8s_kubescape.parse_file(dest))
    by_id = {r["extra"]["id"]: r["severity"] for r in findings}
    assert by_id["C-0057"] == "high"
    assert by_id["C-0090"] == "low"


def test_checkov_null_severity_defaults_medium(tmp_path: Path) -> None:
    dest = tmp_path / "checkov.json"
    dest.write_text(
        json.dumps(
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_20",
                            "check_name": "S3 public ACL",
                            "file_path": "/infra/a.tf",
                            "resource": "aws_s3_bucket.a",
                            "severity": None,
                        },
                        {
                            "check_id": "CKV_AWS_20",
                            "check_name": "S3 public ACL",
                            "file_path": "/infra/b.tf",
                            "resource": "aws_s3_bucket.b",
                            "severity": None,
                        },
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    recs = code_secrets.parse_file(dest)
    findings = _findings(recs)
    assert len(findings) == 2
    assert all(r["severity"] == "medium" for r in findings)
    assert all(r["extra"].get("severity_source") == "default" for r in findings)
    kept = _through_loader(recs)
    assert len(kept) == 2


def test_scuba_same_requirement_two_tenants(tmp_path: Path) -> None:
    dest = tmp_path / "scuba.json"
    dest.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Tenant": "a.onmicrosoft.com",
                        "ProductName": "AAD",
                        "Requirement": "Legacy authentication protocols disabled",
                        "Result": "Fail",
                        "Severity": "high",
                    },
                    {
                        "Tenant": "b.onmicrosoft.com",
                        "ProductName": "AAD",
                        "Requirement": "Legacy authentication protocols disabled",
                        "Result": "Fail",
                        "Severity": "high",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    recs = saas_idp.parse_file(dest)
    kept = _through_loader(recs)
    assert len(kept) == 2
    assert {primary_asset(r) for r in kept} == {"a.onmicrosoft.com", "b.onmicrosoft.com"}
    assert all(r["extra"].get("check_id") == "Legacy authentication protocols disabled" for r in kept)


def test_loader_summary_counts_severity_unmapped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    from shared.schema import make_record

    write_canonical(
        "code-secrets",
        [
            make_record(
                kind="finding",
                source="code-secrets",
                ref_id="CODE-purple",
                name="odd band",
                severity="purple",
                category="sast",
                assets=["repo/a.py"],
                extra={"rule": "odd"},
            ),
            make_record(
                kind="finding",
                source="code-secrets",
                ref_id="CODE-high",
                name="known",
                severity="high",
                category="sast",
                assets=["repo/b.py"],
                extra={"rule": "known"},
            ),
        ],
    )
    summary = load()
    assert summary["severity_unmapped"] == 1
    assert summary["weaknesses"] == 2
