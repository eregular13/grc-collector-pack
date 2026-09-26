"""Risk register, POA&M, and summary counts derive from one deduped set."""

from __future__ import annotations

from pathlib import Path

import pytest

from collectors.cloud_prowler import parse_file as parse_cloud
from collectors.grc_loader import load
from collectors.identity_ad import parse_file as parse_identity
from collectors.inventory_nmap import parse_file as parse_nmap
from collectors.k8s_kubescape import parse_file as parse_k8s
from shared.ciso_shape import assert_count_consistency
from shared.control_map import map_finding
from shared.finding_types import dedupe_weaknesses
from shared.io_util import write_canonical

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"
KEEP = ROOT / "fixtures" / "keep-samples"
PACK_NMAP = ROOT / "fixtures" / "pack_drop" / "nmap"


def _write_findings(source: str, records: list[dict]) -> None:
    write_canonical(source, records)


def _load_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, records_by_source: dict[str, list[dict]]) -> dict:
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "empty-in"))
    (tmp_path / "empty-in").mkdir(exist_ok=True)
    for source, recs in records_by_source.items():
        _write_findings(source, recs)
    return load()


def test_lab_demo_fixture_counts_agree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cloud: list[dict] = []
    for path in sorted((DEMO / "cloud").glob("*")):
        cloud.extend(parse_cloud(path))
    identity: list[dict] = []
    for path in sorted((DEMO / "identity").glob("*")):
        try:
            identity.extend(parse_identity(path))
        except Exception:
            continue
    k8s: list[dict] = []
    for path in sorted((DEMO / "k8s").glob("*")):
        k8s.extend(parse_k8s(path))
    summary = _load_dir(
        monkeypatch,
        tmp_path,
        {"cloud-prowler": cloud, "identity-ad": identity, "k8s-kubescape": k8s},
    )
    shape = assert_count_consistency(tmp_path, summary)
    merged = int(shape.get("merged_aliases") or 0)
    kind_ex = int(summary.get("kind_excluded") or 0)
    assert summary["risk_scenarios"] == summary["weaknesses"] + kind_ex - merged
    assert summary["poam"] == summary["open_risks"] == shape["poam"]
    assert summary["findings"] + summary["vulnerabilities"] == summary["weaknesses"]
    assert "incidents" not in summary
    assert "risks_proposed" not in summary
    assert not (tmp_path / "riskready").exists()
    raw = [r for r in cloud + identity + k8s if r.get("kind") == "finding"]
    deduped = [r for r in dedupe_weaknesses(raw) if r.get("kind") == "finding"]
    assert summary["weaknesses"] == len(deduped)
    open_n = sum(1 for r in deduped if map_finding(r).get("include_poam"))
    assert summary["poam"] == open_n


def test_sample_keep_fixture_counts_agree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not KEEP.is_dir():
        pytest.skip("keep-samples fixtures absent")
    cloud: list[dict] = []
    cloud_dir = KEEP / "cloud"
    if cloud_dir.is_dir():
        for path in sorted(cloud_dir.glob("*")):
            cloud.extend(parse_cloud(path))
    if not cloud:
        pytest.skip("keep-samples has no cloud findings")
    summary = _load_dir(monkeypatch, tmp_path, {"cloud-prowler": cloud})
    shape = assert_count_consistency(tmp_path, summary)
    assert summary["poam"] == summary["open_risks"] == shape["poam"]
    merged = int(shape.get("merged_aliases") or 0)
    kind_ex = int(summary.get("kind_excluded") or 0)
    assert summary["risk_scenarios"] == summary["weaknesses"] + kind_ex - merged
    assert summary["findings"] + summary["vulnerabilities"] == summary["weaknesses"]
    assert "incidents" not in summary
    assert "risks_proposed" not in summary
    assert not (tmp_path / "riskready").exists()


def test_farm_drop_nmap_counts_agree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not PACK_NMAP.is_dir():
        pytest.skip("pack_drop nmap fixtures absent")
    recs: list[dict] = []
    for path in sorted(PACK_NMAP.rglob("*")):
        if not path.is_file():
            continue
        recs.extend(parse_nmap(path))
    findings = [r for r in recs if r.get("kind") == "finding"]
    if not findings:
        pytest.skip("pack_drop nmap emitted no findings")
    summary = _load_dir(monkeypatch, tmp_path, {"inventory-nmap": recs})
    shape = assert_count_consistency(tmp_path, summary)
    assert summary["poam"] == summary["open_risks"] == shape["poam"]
    merged = int(shape.get("merged_aliases") or 0)
    kind_ex = int(summary.get("kind_excluded") or 0)
    assert summary["risk_scenarios"] == summary["weaknesses"] + kind_ex - merged
    assert summary["findings"] + summary["vulnerabilities"] == summary["weaknesses"]
    assert "incidents" not in summary
    assert "risks_proposed" not in summary
    assert not (tmp_path / "riskready").exists()
