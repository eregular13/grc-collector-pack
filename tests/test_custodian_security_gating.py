"""Metis §13.4.3–4 Custodian security gating (T18a/b/c).

SAMPLE fixtures under fixtures/samples/custodian/ — not dest_in, not client KEEP.
"""

from __future__ import annotations

from pathlib import Path

from collectors import cloud_prowler
from shared.control_map import POAM_EXCLUDE_REASONS, map_finding, poam_decision
from shared.finding_types import dedupe_weaknesses

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples"
DEMO = ROOT / "fixtures" / "demo"
C7N = SAMPLES / "custodian"

ARM_IDLE = (
    "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/"
    "rg-lab/providers/Microsoft.Compute/virtualMachines/vm-idle-01"
)


def _findings(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "finding"]


def _assets(recs: list[dict]) -> list[dict]:
    return [r for r in recs if r["kind"] == "asset"]


def test_samples_sources_credits_custodian_metis13() -> None:
    text = (SAMPLES / "SOURCES.md").read_text(encoding="utf-8")
    assert "security-context-pods" in text
    assert "enforce-storage-encryption" in text
    assert "azure-vm-cpu-underutilized" in text
    assert "Metis" in text
    assert "SAMPLE/DEMO" in text
    assert "client KEEP" in text
    assert "/api/risks" in text
    assert "RiskReady" in text


def test_t18a_security_context_pods_is_finding() -> None:
    meta = C7N / "security-context-pods" / "metadata.json"
    recs = cloud_prowler.parse_file(meta)
    findings = _findings(recs)
    assets = _assets(recs)
    assert len(findings) == 1
    hit = findings[0]
    assert hit["assets"] == ["default/web"]
    assert any(r["name"] == "default/web" for r in assets)
    assert hit["extra"].get("policy_name") == "security-context-pods"
    assert hit["extra"].get("service") == "k8s.pod"
    assert hit["extra"].get("policy_resource") == "k8s.pod"
    assert hit["severity"] == "medium"
    assert hit["extra"].get("exclude_reason") != "NOT_A_WEAKNESS"
    assert "Cloud Custodian" in hit["name"]
    assert poam_decision(hit)["include"] is True
    assert map_finding(hit)["include_poam"] is True
    assert not any(r["name"] == "security-context-pods" for r in assets)
    assert not any(r["name"] == "web" for r in assets)
    assert not any((r.get("extra") or {}).get("service") == "cloud" for r in recs)

    twin = cloud_prowler.parse_file(C7N / "security-context-pods" / "resources.json")
    assert {r["ref_id"] for r in _findings(twin)} == {hit["ref_id"]}
    merged = dedupe_weaknesses(recs + twin)
    assert len(_findings(merged)) == 1


def test_t18b_empty_storage_encryption_no_finding() -> None:
    recs = cloud_prowler.parse_file(C7N / "enforce-storage-encryption" / "metadata.json")
    assert _findings(recs) == []
    assert _assets(recs) == []
    twin = cloud_prowler.parse_file(
        C7N / "enforce-storage-encryption" / "resources.json"
    )
    assert twin == []


def test_t18c_azure_vm_cpu_underutilized_not_a_weakness() -> None:
    recs = cloud_prowler.parse_file(
        C7N / "azure-vm-cpu-underutilized" / "metadata.json"
    )
    findings = _findings(recs)
    assets = _assets(recs)
    assert len(findings) == 1
    hit = findings[0]
    assert hit["assets"] == [ARM_IDLE]
    assert any(r["name"] == ARM_IDLE for r in assets)
    assert not any(r["name"] == "vm-idle-01" for r in recs)
    assert hit["extra"].get("policy_name") == "azure-vm-cpu-underutilized"
    assert hit["extra"].get("service") == "azure.vm"
    assert hit["severity"] == "medium"
    assert hit["extra"].get("exclude_reason") == "NOT_A_WEAKNESS"
    decision = poam_decision(hit)
    assert decision["include"] is False
    assert decision["reason"] == "NOT_A_WEAKNESS"
    assert decision["reason"] in POAM_EXCLUDE_REASONS
    assert map_finding(hit)["include_poam"] is False
    assert hit["severity"] != "high"


def test_demo_custodian_encrypt_still_a_finding() -> None:
    recs = cloud_prowler.parse_file(DEMO / "cloud" / "custodian.json")
    findings = _findings(recs)
    assert any(r["name"] == "arn:aws:s3:::demo-unencrypted-tmp" for r in _assets(recs))
    assert findings
    hit = findings[0]
    assert "Cloud Custodian" in hit["name"]
    assert hit["extra"].get("policy_name") == "s3-encryption-missing"
    assert hit["extra"].get("service") == "aws.s3"
    assert hit["severity"] == "high"
    assert hit["extra"].get("exclude_reason") != "NOT_A_WEAKNESS"
    assert poam_decision(hit)["include"] is True


def test_custodian_no_severity_defaults_medium(tmp_path: Path) -> None:
    dest = tmp_path / "custodian.json"
    dest.write_text(
        """{
  "policies": [
    {
      "name": "s3-public-acl",
      "resource": "aws.s3",
      "description": "Buckets with a public ACL",
      "resources": [
        {"Arn": "arn:aws:s3:::lab-public", "Name": "lab-public"}
      ]
    }
  ]
}
""",
        encoding="utf-8",
    )
    recs = cloud_prowler.parse_file(dest)
    hit = _findings(recs)[0]
    assert hit["severity"] == "medium"
    assert hit["assets"] == ["arn:aws:s3:::lab-public"]
    assert hit["extra"].get("service") == "aws.s3"
