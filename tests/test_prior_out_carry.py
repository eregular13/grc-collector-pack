"""--prior-out carry: SameFileError, partial, asset copy, file vs dir."""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.asset_ledger import AssetLedger
from shared.poam_ledger import (
    carry_prior_ledgers,
    empty_ledger,
    persist_ledger,
    resolve_prior_out,
)


def _prior_tree(tmp_path: Path) -> Path:
    prior = tmp_path / "prior-out"
    persist_ledger(empty_ledger(), prior)
    AssetLedger().save(prior / "assets" / "asset-ledger.json")
    (prior / "summary.json").write_text(
        '{"estate_kind": "LAB"}\n', encoding="utf-8", newline="\n"
    )
    return prior


def test_prior_out_dest_in_samefile_is_fail(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    dest_in.mkdir()
    persist_ledger(empty_ledger(), dest_in)
    with pytest.raises(FileNotFoundError, match="PRIOR_OUT_FAIL"):
        carry_prior_ledgers(dest_in, dest_in)
    with pytest.raises(FileNotFoundError, match="PRIOR_OUT_FAIL"):
        carry_prior_ledgers(dest_in / "poam", dest_in)


def test_prior_out_partial_one_ledger_missing(tmp_path: Path) -> None:
    """po3: one missing is PRIOR_OUT_PARTIAL, not silent and not both-only FAIL."""
    prior = tmp_path / "prior-out"
    persist_ledger(empty_ledger(), prior)
    dest_in = tmp_path / "in"
    dest_in.mkdir()
    result = carry_prior_ledgers(prior, dest_in)
    assert "poam-ledger.json" in result["copied"]
    assert "asset-ledger.json" not in result["copied"]
    assert any(w.startswith("PRIOR_OUT_PARTIAL") for w in result["warnings"])
    assert (dest_in / "poam" / "poam-ledger.json").is_file()


def test_prior_out_copies_asset_ledger(tmp_path: Path) -> None:
    """po2: asset-ledger.json is copied, not only poam."""
    prior = _prior_tree(tmp_path)
    dest_in = tmp_path / "in"
    dest_in.mkdir()
    result = carry_prior_ledgers(prior, dest_in)
    assert result["copied"] == ["poam-ledger.json", "asset-ledger.json"]
    assert (dest_in / "assets" / "asset-ledger.json").is_file()
    src = (prior / "assets" / "asset-ledger.json").read_bytes()
    dest = (dest_in / "assets" / "asset-ledger.json").read_bytes()
    assert dest == src


def test_prior_out_file_vs_dir(tmp_path: Path) -> None:
    """po5: poam-ledger.json file resolves to out/; a random file is FAIL."""
    prior = _prior_tree(tmp_path)
    dest_in = tmp_path / "in"
    dest_in.mkdir()
    ledger = prior / "poam" / "poam-ledger.json"
    assert resolve_prior_out(ledger) == prior
    result = carry_prior_ledgers(resolve_prior_out(ledger), dest_in)
    assert "poam-ledger.json" in result["copied"]

    dest2 = tmp_path / "in2"
    dest2.mkdir()
    other = prior / "summary.json"
    resolved = resolve_prior_out(other)
    with pytest.raises(FileNotFoundError, match="PRIOR_OUT_FAIL"):
        carry_prior_ledgers(resolved, dest2)


def test_prior_out_overwrites_hand_and_warns(tmp_path: Path) -> None:
    prior = _prior_tree(tmp_path)
    dest_in = tmp_path / "in"
    persist_ledger(empty_ledger(), dest_in)
    result = carry_prior_ledgers(prior, dest_in)
    assert any("PRIOR_OUT_OVERWRITES_HAND" in w for w in result["warnings"])
    assert "prior-out won" in " ".join(result["warnings"])


def test_prior_out_estate_mismatch_warns(tmp_path: Path) -> None:
    prior = _prior_tree(tmp_path)
    dest_in = tmp_path / "in"
    dest_in.mkdir()
    (dest_in / "SAMPLE.txt").write_text("SAMPLE\n", encoding="utf-8", newline="\n")
    result = carry_prior_ledgers(prior, dest_in)
    assert any(w.startswith("PRIOR_ESTATE_MISMATCH") for w in result["warnings"])
