"""Lock fixtures/pack_drop/ + seed_prove_in to the all-16 E2E_PROVEN set."""

from __future__ import annotations

import inspect
from pathlib import Path

from scripts.prove_ciso import (
    E2E_PROVEN_PACK_DROP_ADAPTERS,
    pack_drop_seed_dest,
    seed_prove_in,
)
from tests.test_status_honesty import COVEY_E2E_PROVEN, COVEY_E2E_UNPROVEN

ROOT = Path(__file__).resolve().parents[1]
PACK_DROP = ROOT / "fixtures" / "pack_drop"
REQUIRED_FILES = ("meta.json", "assets.jsonl", "findings.jsonl")
PACK_DROP_ADAPTERS = E2E_PROVEN_PACK_DROP_ADAPTERS


def _fixture_dirs() -> set[str]:
    return {p.name for p in PACK_DROP.iterdir() if p.is_dir()}


def test_pack_drop_fixture_dirs_are_exactly_sixteen() -> None:
    names = _fixture_dirs()
    expected = set(PACK_DROP_ADAPTERS)
    assert len(PACK_DROP_ADAPTERS) == 16
    assert names == expected
    assert len(names) == 16
    extra = names - expected
    missing = expected - names
    assert not extra, f"17th (or extra) pack_drop fixture dir: {sorted(extra)}"
    assert not missing, f"missing pack_drop fixture dir: {sorted(missing)}"
    for name in COVEY_E2E_UNPROVEN:
        assert name not in names, f"UNPROVEN {name} must not be a pack_drop fixture dir"


def test_pack_drop_fixture_required_files_nonempty() -> None:
    for name in PACK_DROP_ADAPTERS:
        dest = PACK_DROP / name
        assert dest.is_dir(), f"missing fixtures/pack_drop/{name}/"
        for filename in REQUIRED_FILES:
            path = dest / filename
            assert path.is_file(), f"missing {path.relative_to(ROOT)}"
            assert path.stat().st_size > 0, f"empty {path.relative_to(ROOT)}"


def test_seed_prove_in_adapters_match_sixteen_1_to_1(tmp_path: Path) -> None:
    dest_in = tmp_path / "in"
    seed = seed_prove_in(dest_in, ROOT)
    adapters = seed["adapters"]
    assert set(adapters) == set(PACK_DROP_ADAPTERS)
    assert len(adapters) == 16
    assert set(adapters) == _fixture_dirs()

    src = inspect.getsource(seed_prove_in)
    assert "E2E_PROVEN_PACK_DROP_ADAPTERS" in src
    assert src.count('root / "fixtures" / "pack_drop"') == 1

    nmap_drop = dest_in / "nmap" / "pack_drop"
    nested = {p.name for p in nmap_drop.iterdir() if p.is_dir()}
    nested_adapters = {name for name in PACK_DROP_ADAPTERS if name != "nmap"}
    # evidence/ is nmap fixture content, not a 17th adapter.
    unexpected = nested - {"evidence"} - nested_adapters
    assert not unexpected, f"17th pack_drop seed adapter dir: {sorted(unexpected)}"
    assert nested - {"evidence"} == nested_adapters
    assert "nmap" not in nested

    for name in PACK_DROP_ADAPTERS:
        dest = Path(adapters[name])
        assert dest == pack_drop_seed_dest(dest_in, name)
        assert dest.is_dir(), f"seed missed adapter {name}"
        for filename in REQUIRED_FILES:
            path = dest / filename
            assert path.is_file(), f"seed missing {name}/{filename}"
            assert path.stat().st_size > 0, f"seed emptied {name}/{filename}"
        if name == "nmap":
            assert seed["covey"] == str(dest)
        else:
            assert seed[name] == str(dest)

    seeded_keys = {key for key in seed if key in PACK_DROP_ADAPTERS or key == "covey"}
    assert seeded_keys == {"covey"} | nested_adapters
    assert "nmap" not in seed


def test_shared_constant_matches_honesty_covey_e2e_proven() -> None:
    assert PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(PACK_DROP_ADAPTERS) == tuple(
        COVEY_E2E_PROVEN
    )
    assert frozenset(PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert len(PACK_DROP_ADAPTERS) == 16
    assert len(set(PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in PACK_DROP_ADAPTERS
