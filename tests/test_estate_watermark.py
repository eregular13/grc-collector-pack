"""ESTATE_WATERMARK: exported POA&M + risk-register CSVs carry the run's estate label.

LAB / SAMPLE / DEMO output must be self-describing once it leaves the console
(export.zip, copy to a share, email). Never label a run client.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from shared.ciso_shape import (
    CISO_HEADERS,
    POAM_HEADER,
    assert_risk_register_and_poam,
    csv_rows,
    first_nonempty_line,
)


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


def test_poam_header_has_estate_column() -> None:
    # estate follows the legacy 8 columns; FedRAMP fields may be appended after it.
    assert POAM_HEADER.split(",")[8] == "estate"
    assert POAM_HEADER.startswith("weakness,asset,severity,framework_refs,recommended_fix,owner,due,status")


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"GRC_ESTATE_LABEL": "LAB"}, "LAB: TEST ENVIRONMENT"),
        ({"GRC_ESTATE_LABEL": "SAMPLE"}, "SAMPLE DATA: NOT A CLIENT"),
        ({"DROPBOX_DEMO": "1"}, "SAMPLE DATA: NOT A CLIENT"),
    ],
)
def test_poam_csv_and_md_carry_estate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env: dict, expected: str
) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], **env)
    poam = out / "poam" / "poam.csv"
    assert not poam.read_text(encoding="utf-8").lstrip().startswith("#")
    rows = csv_rows(poam)
    assert rows, "high finding must reach POA&M"
    assert {row["estate"] for row in rows} == {expected}
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8")
    assert md.lstrip().startswith("> **")
    assert expected in md.splitlines()[0]
    sr = out / "simplerisk" / "poam.csv"
    sr_text = sr.read_text(encoding="utf-8")
    assert sr_text.splitlines()[0].strip() == POAM_HEADER
    assert first_nonempty_line(sr) == POAM_HEADER
    assert not any(line.lstrip().startswith("#") for line in sr_text.splitlines())
    assert sr_text.splitlines()[0].split(",")[8] == "estate"
    sr_rows = csv_rows(sr)
    assert {row["estate"] for row in sr_rows} == {expected}
    estate_txt = (out / "simplerisk" / "ESTATE.txt").read_text(encoding="utf-8")
    assert expected in estate_txt
    assert_risk_register_and_poam(out)


def test_demo_labeled_records_default_to_demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1", labels=["nmap", "demo"])])
    assert {row["estate"] for row in csv_rows(out / "poam" / "poam.csv")} == {
        "DEMO: NOT A CLIENT"
    }


def test_lab_txt_in_dest_in_means_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lab_in = tmp_path / "in" / "nmap" / "pack_drop"
    lab_in.mkdir(parents=True)
    (lab_in / "LAB.txt").write_text("LAB/DEMO -- not a client estate.\n", encoding="utf-8")
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")])
    assert {row["estate"] for row in csv_rows(out / "poam" / "poam.csv")} == {
        "LAB: TEST ENVIRONMENT"
    }


def test_unlabeled_run_never_claims_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")])
    rows = csv_rows(out / "poam" / "poam.csv")
    assert {row["estate"] for row in rows} == {"SAMPLE DATA: NOT A CLIENT"}
    md = (out / "poam" / "poam.md").read_text(encoding="utf-8")
    assert "CLIENT:" not in md.splitlines()[0]
    assert "SAMPLE DATA: NOT A CLIENT" in md


def test_bogus_env_label_is_not_trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """GRC_ESTATE_LABEL=CLIENT on unlabeled data must fail closed (never CLIENT)."""
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], GRC_ESTATE_LABEL="CLIENT")
    assert {row["estate"] for row in csv_rows(out / "poam" / "poam.csv")} == {
        "SAMPLE DATA: NOT A CLIENT"
    }


def test_register_csvs_carry_estate_label_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CISO import CSVs keep locked headers; label lives in filtering_labels + ESTATE.txt."""
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], GRC_ESTATE_LABEL="LAB")
    ciso = out / "ciso-assistant"
    for name in ("findings.csv", "assets.csv"):
        text = (ciso / name).read_text(encoding="utf-8")
        assert not text.lstrip().startswith("#")
        assert text.splitlines()[0].strip() == CISO_HEADERS[name]
        rows = csv_rows(ciso / name)
        assert rows
        for row in rows:
            assert "estate_lab" in row["filtering_labels"].split(","), (name, row)
            assert "estate" not in row
    estate_txt = (ciso / "ESTATE.txt").read_text(encoding="utf-8")
    assert "LAB: TEST ENVIRONMENT" in estate_txt
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["estate"] == "LAB: TEST ENVIRONMENT"
    assert summary.get("client") in (None, False)
