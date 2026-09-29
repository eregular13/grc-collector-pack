"""R5-7: upgrading a 1f8d347 out/ must drop pack-owned ghosts, keep operator files.

1f8d347 wrote ``out/riskready/`` and ``risks_proposed.json``. Current does not.
The run removes those leftovers or the test fails. Files the pack never
created stay. SAMPLE/DEMO != client KEEP. No POST /api/risks.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from shared.ciso_shape import POAM_HEADER
from shared.pack_outputs import (
    RETIRED_PACK_OWNED_DIRS,
    RETIRED_PACK_OWNED_FILES,
    clean_retired_pack_outputs,
    is_retired_pack_owned,
)


def _finding(ref: str = "f1") -> dict:
    return {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": ref,
        "name": f"FTP exposed {ref}",
        "description": f"{ref} has open TCP/21 (ftp).",
        "severity": "high",
        "category": "exposure",
        "assets": ["host-a"],
        "labels": ["nmap"],
        "extra": {"port": "21", "service": "ftp", "ip": "10.0.0.5", "check_id": f"test-{ref}"},
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


def _plant_1f8d347_layout(out: Path) -> None:
    """Fixture of the 1f8d347-era out/ tree plus an operator file.

    1f8d347's MANIFEST omitted ``poam/excluded.csv`` (loader still wrote it).
    ``riskready/`` is the retired pack sink that a dirty upgrade leaves behind.
    """
    (out / "riskready").mkdir(parents=True)
    (out / "riskready" / "risks_proposed.json").write_text("[]\n", encoding="utf-8")
    (out / "risks_proposed.json").write_text("[]\n", encoding="utf-8")
    (out / "canonical").mkdir(parents=True)
    (out / "poam").mkdir(parents=True)
    (out / "ciso-assistant").mkdir(parents=True)
    # Operator-owned. The pack did not create this name.
    (out / "operator-notes.txt").write_text("keep me\n", encoding="utf-8")
    # 1f8d347 MANIFEST shape: no excluded.csv line; lists the retired sink.
    (out / "MANIFEST").write_text(
        "0" * 64 + "  poam/poam.csv\n"
        + "0" * 64 + "  ciso-assistant/assets.csv\n"
        + "0" * 64 + "  riskready/risks_proposed.json\n",
        encoding="utf-8",
    )


def _run_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: list[dict]) -> Path:
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / "canonical").mkdir(parents=True, exist_ok=True)
    with (out / "canonical" / "inventory-nmap.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    return out


def test_retired_paths_are_pack_owned_only() -> None:
    assert is_retired_pack_owned("riskready")
    assert is_retired_pack_owned("riskready/risks_proposed.json")
    assert is_retired_pack_owned("risks_proposed.json")
    assert not is_retired_pack_owned("operator-notes.txt")
    assert not is_retired_pack_owned("canonical/inventory-nmap.jsonl")
    assert not is_retired_pack_owned("poam/poam.csv")
    assert "riskready" in RETIRED_PACK_OWNED_DIRS
    assert "risks_proposed.json" in RETIRED_PACK_OWNED_FILES


def test_clean_leaves_operator_files(tmp_path: Path) -> None:
    out = tmp_path / "out"
    _plant_1f8d347_layout(out)
    removed = clean_retired_pack_outputs(out)
    assert "riskready" in removed or "riskready/risks_proposed.json" in removed
    assert not (out / "riskready").exists()
    assert not (out / "risks_proposed.json").exists()
    assert (out / "operator-notes.txt").read_text(encoding="utf-8") == "keep me\n"
    assert (out / "MANIFEST").is_file()


def test_loader_upgrade_from_1f8d347_drops_ghosts_keeps_operator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _plant_1f8d347_layout(out)
    assert (out / "riskready" / "risks_proposed.json").is_file()
    loaded = _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
    assert loaded == out
    leftover = [p for p in out.rglob("*") if "riskready" in p.as_posix().lower()]
    assert leftover == []
    assert not (out / "risks_proposed.json").exists()
    assert (out / "operator-notes.txt").read_text(encoding="utf-8") == "keep me\n"
    assert (out / "poam" / "poam.csv").is_file()
    assert (out / "poam" / "excluded.csv").is_file()
    header = (out / "poam" / "poam.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.strip() == POAM_HEADER or header.startswith("weakness,")
    manifest = (out / "MANIFEST").read_text(encoding="utf-8")
    assert "riskready" not in manifest
    assert "excluded.csv" in manifest
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert "risks_proposed" not in summary


def test_loader_does_not_delete_unrelated_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _plant_1f8d347_layout(out)
    other = tmp_path / "client-drop" / "keep.bin"
    other.parent.mkdir(parents=True)
    other.write_bytes(b"operator")
    _run_loader(tmp_path, monkeypatch, [_asset(), _finding()])
    assert other.read_bytes() == b"operator"
    assert (out / "operator-notes.txt").is_file()
