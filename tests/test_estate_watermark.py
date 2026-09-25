"""ESTATE_WATERMARK: exported POA&M + risk-register CSVs carry the run's estate label.

LAB / SAMPLE / DEMO output must be self-describing once it leaves the console
(export.zip, copy to a share, email). Never label a run client.
"""

from __future__ import annotations

import csv
import importlib
import json
from pathlib import Path

import pytest

from shared.ciso_shape import POAM_HEADER, assert_risk_register_and_poam


def _finding(ref: str, sev: str = "high", labels: list[str] | None = None) -> dict:
    return {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": ref,
        "name": f"FTP exposed {ref}",
        "description": f"{ref} has open TCP/21 (ftp).",
        "severity": sev,
        "category": "exposure",
        "assets": ["host-a"],
        "labels": labels or ["nmap"],
        "extra": {"port": "21", "service": "ftp", "ip": "10.0.0.5"},
    }


def _asset() -> dict:
    return {
        "kind": "asset",
        "source": "inventory-nmap",
        "ref_id": "asset-host-a",
        "name": "host-a",
        "description": "Host host-a",
        "severity": "info",
        "category": "host",
        "assets": ["host-a"],
        "labels": ["nmap"],
        "extra": {"asset_type": "PR", "ip": "10.0.0.5"},
    }


def _run_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: list[dict], **env: str) -> Path:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    with (out / "canonical" / "inventory-nmap.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    for key in ("GRC_ESTATE_LABEL", "DROPBOX_DEMO"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    return out


def _poam(out: Path) -> list[dict[str, str]]:
    with (out / "poam" / "poam.csv").open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_poam_header_has_estate_column() -> None:
    assert POAM_HEADER.split(",")[-1] == "estate"
    assert POAM_HEADER.startswith("weakness,asset,severity,framework_refs,recommended_fix,owner,due,status")


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"GRC_ESTATE_LABEL": "LAB"}, "LAB"),
        ({"GRC_ESTATE_LABEL": "SAMPLE"}, "SAMPLE"),
        ({"DROPBOX_DEMO": "1"}, "SAMPLE"),
    ],
)
def test_poam_csv_and_md_carry_estate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env: dict, expected: str
) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], **env)
    rows = _poam(out)
    assert rows, "high finding must reach POA&M"
    assert {row["estate"] for row in rows} == {expected}
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8")
    banner = md.splitlines()[0:4]
    assert any(f"ESTATE: {expected}" in line and "not a client estate" in line for line in banner), banner
    sr = (out / "simplerisk" / "poam.csv").read_text(encoding="utf-8").splitlines()[0]
    assert sr == POAM_HEADER
    assert_risk_register_and_poam(out)


def test_demo_labeled_records_default_to_demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1", labels=["nmap", "demo"])])
    assert {row["estate"] for row in _poam(out)} == {"DEMO"}


def test_lab_txt_in_dest_in_means_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lab_in = tmp_path / "in" / "nmap" / "pack_drop"
    lab_in.mkdir(parents=True)
    (lab_in / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")])
    assert {row["estate"] for row in _poam(out)} == {"LAB"}


def test_unlabeled_run_never_claims_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")])
    rows = _poam(out)
    assert {row["estate"] for row in rows} == {"UNLABELED"}
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8").lower()
    assert "client estate" not in md.replace("not verified as a client estate", "")
    assert "estate: unlabeled" in md


def test_bogus_env_label_is_not_trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """GRC_ESTATE_LABEL=CLIENT (or anything off-list) must not flow into exports."""
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], GRC_ESTATE_LABEL="CLIENT")
    assert {row["estate"] for row in _poam(out)} == {"UNLABELED"}


def test_register_csvs_carry_estate_label_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CISO import headers stay fixed; the watermark rides filtering_labels + ESTATE.txt."""
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], GRC_ESTATE_LABEL="LAB")
    ciso = out / "ciso-assistant"
    for name in ("findings.csv", "assets.csv"):
        with (ciso / name).open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        assert rows
        for row in rows:
            assert "estate_lab" in row["filtering_labels"].split(","), (name, row)
    estate_txt = (ciso / "ESTATE.txt").read_text(encoding="utf-8")
    assert "ESTATE: LAB" in estate_txt
    assert "not a client estate" in estate_txt
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["estate"] == "LAB"
    assert summary.get("client") in (None, False)
