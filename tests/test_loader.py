from __future__ import annotations

import importlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = [
    "collectors.cloud_prowler",
    "collectors.inventory_nmap",
    "collectors.vuln_scan",
    "collectors.host_wazuh",
    "collectors.identity_ad",
    "collectors.easm",
    "collectors.k8s_kubescape",
    "collectors.code_secrets",
    "collectors.saas_idp",
    "collectors.grc_loader",
]


def test_ten_collectors_import() -> None:
    for name in MODULES:
        importlib.import_module(name)


def test_compose_has_ten_services() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    names = [
        "cloud-prowler",
        "inventory-nmap",
        "vuln-scan",
        "host-wazuh",
        "identity-ad",
        "easm",
        "k8s-kubescape",
        "code-secrets",
        "saas-idp",
        "grc-loader",
    ]
    for n in names:
        assert f"{n}:" in text
    assert "service_completed_successfully" in text
    assert text.count("condition:") >= 9


def test_csv_header_strings() -> None:
    from collectors.grc_loader import (
        ASSETS_HEADER,
        CONTROLS_HEADER,
        EVIDENCE_HEADER,
        FINDINGS_HEADER,
        SCENARIO_HEADER,
        VULN_HEADER,
    )

    assert ",".join(ASSETS_HEADER) == (
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets"
    )
    assert ",".join(CONTROLS_HEADER) == (
        "ref_id,name,description,domain,status,category,priority,csf_function"
    )
    assert ",".join(EVIDENCE_HEADER) == "name,description"
    assert ",".join(FINDINGS_HEADER) == "ref_id,name,description,severity,status,filtering_labels"
    assert ",".join(VULN_HEADER) == "ref_id,name,description,status,severity,assets,applied_controls"
    assert ";".join(SCENARIO_HEADER) == (
        "ref_id;assets;threats;name;description;existing_controls;current_impact;"
        "current_proba;current_risk;additional_controls;residual_impact;residual_proba;"
        "residual_risk;treatment"
    )
