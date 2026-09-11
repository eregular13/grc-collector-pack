"""Lock global pack_drop asset/host/service identity.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.
Every asset / host / service row in assets.jsonl needs a stable non-blank
top-level id (accept observation_id as alias; prefer canonical id). Ids
unique within each adapter file and globally across all sixteen fixtures,
and disjoint from finding/observation ids locked by
tests/test_pack_drop_observation_ids.py.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_ADAPTERS
from tests.test_pack_drop_observation_ids import (
    _canonical_id as _observation_canonical_id,
    _required_rows as _observation_required_rows,
)
from tests.test_status_honesty import COVEY_E2E_PROVEN, COVEY_E2E_UNPROVEN

ROOT = Path(__file__).resolve().parents[1]
PACK_DROP = ROOT / "fixtures" / "pack_drop"
ASSET_KINDS = frozenset({"asset", "host", "service"})


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        row = json.loads(text)
        assert isinstance(row, dict), f"{path} JSONL row must be an object"
        rows.append(row)
    return rows


def _canonical_id(row: dict[str, Any]) -> str:
    extra = row.get("extra") or {}
    extra = extra if isinstance(extra, dict) else {}
    for key in ("id", "observation_id"):
        for bag in (row, extra):
            val = bag.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
            if val not in (None, "") and not isinstance(val, (dict, list)):
                text = str(val).strip()
                if text:
                    return text
    return ""


def _row_needs_id(row: dict[str, Any]) -> bool:
    kind = str(row.get("kind") or "").strip().lower()
    return kind in ASSET_KINDS


def _iter_asset_rows(adapter: str) -> list[tuple[Path, int, dict[str, Any]]]:
    path = PACK_DROP / adapter / "assets.jsonl"
    assert path.is_file(), f"missing {path.relative_to(ROOT)}"
    out: list[tuple[Path, int, dict[str, Any]]] = []
    for idx, row in enumerate(_load_jsonl(path), start=1):
        out.append((path, idx, row))
    return out


def _required_rows(adapter: str) -> list[tuple[Path, int, dict[str, Any]]]:
    return [
        (path, idx, row)
        for path, idx, row in _iter_asset_rows(adapter)
        if _row_needs_id(row)
    ]


def _observation_ids() -> dict[str, list[str]]:
    """Ids already covered by tests/test_pack_drop_observation_ids.py.

    Read findings.jsonl / observation (and claim) rows across the sixteen
    fixtures — the same required set the observation-id lock walks.
    """
    owners: dict[str, list[str]] = defaultdict(list)
    for adapter in E2E_PROVEN_PACK_DROP_ADAPTERS:
        findings_path = PACK_DROP / adapter / "findings.jsonl"
        if findings_path.is_file():
            for idx, row in enumerate(_load_jsonl(findings_path), start=1):
                oid = _observation_canonical_id(row)
                if oid:
                    owners[oid].append(f"{findings_path.relative_to(ROOT)}:{idx}")
        for path, idx, row in _observation_required_rows(adapter):
            oid = _observation_canonical_id(row)
            if not oid:
                continue
            loc = f"{path.relative_to(ROOT)}:{idx}"
            if loc not in owners[oid]:
                owners[oid].append(loc)
    return owners


def test_asset_id_set_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS


def test_unproven_adapters_absent_from_pack_drop_asset_lock() -> None:
    names = {path.name for path in PACK_DROP.iterdir() if path.is_dir()}
    for name in COVEY_E2E_UNPROVEN:
        assert name not in names, f"UNPROVEN {name} must not be a pack_drop fixture dir"
    assert names == set(E2E_PROVEN_PACK_DROP_ADAPTERS)
    assert names == set(COVEY_E2E_PROVEN)
    assert len(names) == 16


@pytest.mark.parametrize(
    "adapter",
    list(E2E_PROVEN_PACK_DROP_ADAPTERS),
    ids=list(E2E_PROVEN_PACK_DROP_ADAPTERS),
)
def test_pack_drop_asset_ids_per_adapter(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"
    required = _required_rows(adapter)
    assert required, f"{adapter} has no asset/host/service rows to lock"

    seen: list[str] = []
    for path, idx, row in required:
        rel = path.relative_to(ROOT)
        aid = _canonical_id(row)
        assert aid, (
            f"{rel}:{idx} asset/host/service row missing stable non-blank "
            f"id (observation_id alias accepted): {row}"
        )
        assert aid == aid.strip(), f"{rel}:{idx} id has surrounding whitespace: {aid!r}"
        assert aid.lower() not in {"none", "null", "undefined", "n/a", "-"}, (
            f"{rel}:{idx} id {aid!r} is a placeholder"
        )
        prefix = f"{adapter}-"
        assert aid.startswith(prefix), (
            f"{rel}:{idx} id {aid!r} must be namespaced as {prefix}… "
            f"(global uniqueness is then natural)"
        )
        raw_id = row.get("id")
        if raw_id in (None, ""):
            alias = row.get("observation_id")
            assert isinstance(alias, str) and alias.strip() == aid, (
                f"{rel}:{idx} missing canonical id and observation_id alias is blank"
            )
        else:
            assert str(raw_id).strip() == aid, (
                f"{rel}:{idx} canonical id {raw_id!r} disagrees with resolved {aid!r}"
            )
        seen.append(aid)

    dups = sorted({aid for aid in seen if seen.count(aid) > 1})
    assert not dups, f"{adapter} assets.jsonl has duplicate asset ids: {dups}"


def test_pack_drop_asset_ids_globally_unique() -> None:
    """Walk all sixteen assets.jsonl files; colliding sibling ids would collapse assets."""
    owners: dict[str, list[str]] = defaultdict(list)
    required_count = 0
    for adapter in E2E_PROVEN_PACK_DROP_ADAPTERS:
        for path, idx, row in _iter_asset_rows(adapter):
            if not _row_needs_id(row):
                continue
            aid = _canonical_id(row)
            required_count += 1
            if not aid:
                continue
            loc = f"{path.relative_to(ROOT)}:{idx}"
            owners[aid].append(loc)
    assert required_count >= 16, "expected at least one locked asset id per E2E_PROVEN adapter"
    collisions = {aid: locs for aid, locs in owners.items() if len(locs) > 1}
    assert not collisions, (
        "duplicate pack_drop asset/host/service ids across the sixteen-set "
        f"(would collapse CISO assets): {collisions}"
    )
    assert len(owners) == sum(len(locs) for locs in owners.values())
    for name in COVEY_E2E_UNPROVEN:
        assert name not in {p.name for p in PACK_DROP.iterdir() if p.is_dir()}


def test_pack_drop_asset_ids_disjoint_from_observation_ids() -> None:
    """Asset/host/service ids must not collide with finding/observation ids."""
    obs_owners = _observation_ids()
    obs_ids = set(obs_owners)
    assert obs_ids, "observation-id lock produced an empty set — fixtures drifted"

    asset_owners: dict[str, list[str]] = defaultdict(list)
    for adapter in E2E_PROVEN_PACK_DROP_ADAPTERS:
        for path, idx, row in _required_rows(adapter):
            aid = _canonical_id(row)
            if not aid:
                continue
            asset_owners[aid].append(f"{path.relative_to(ROOT)}:{idx}")

    overlap = sorted(set(asset_owners) & obs_ids)
    assert not overlap, (
        "asset/host/service ids collide with finding/observation ids "
        f"(keep sets disjoint): {overlap}"
    )
    assert len(asset_owners) >= 16
