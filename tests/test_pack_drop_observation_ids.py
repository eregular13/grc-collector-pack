"""Lock global pack_drop observation id uniqueness.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.
Every claim / finding / observation row needs a stable non-blank id
(accept observation_id as alias; prefer canonical id). Ids unique within
each adapter file and globally across all sixteen fixtures so sibling
rows cannot collapse CISO records. Prefer <adapter>-… namespacing.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_ADAPTERS
from tests.test_status_honesty import COVEY_E2E_PROVEN, COVEY_E2E_UNPROVEN

ROOT = Path(__file__).resolve().parents[1]
PACK_DROP = ROOT / "fixtures" / "pack_drop"
JSONL_FILES = ("assets.jsonl", "findings.jsonl")
CLAIM_OR_OBS_KINDS = frozenset({"finding", "observation"})


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


def _extra(row: dict[str, Any]) -> dict[str, Any]:
    extra = row.get("extra") or {}
    return extra if isinstance(extra, dict) else {}


def _has_claim(row: dict[str, Any]) -> bool:
    extra = _extra(row)
    for val in (row.get("claim"), extra.get("claim")):
        if isinstance(val, str) and val.strip():
            return True
        if isinstance(val, list) and any(str(item).strip() for item in val if item):
            return True
    return False


def _row_needs_id(row: dict[str, Any]) -> bool:
    kind = str(row.get("kind") or "").strip().lower()
    return _has_claim(row) or kind in CLAIM_OR_OBS_KINDS


def _canonical_id(row: dict[str, Any]) -> str:
    extra = _extra(row)
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


def _iter_adapter_rows(adapter: str) -> list[tuple[Path, int, dict[str, Any]]]:
    dest = PACK_DROP / adapter
    out: list[tuple[Path, int, dict[str, Any]]] = []
    for filename in JSONL_FILES:
        path = dest / filename
        assert path.is_file(), f"missing {path.relative_to(ROOT)}"
        for idx, row in enumerate(_load_jsonl(path), start=1):
            out.append((path, idx, row))
    return out


def _required_rows(adapter: str) -> list[tuple[Path, int, dict[str, Any]]]:
    return [
        (path, idx, row)
        for path, idx, row in _iter_adapter_rows(adapter)
        if _row_needs_id(row)
    ]


def test_observation_id_set_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS


def test_unproven_adapters_absent_from_pack_drop() -> None:
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
def test_pack_drop_observation_ids_per_adapter(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"
    required = _required_rows(adapter)
    assert required, f"{adapter} has no claim/finding/observation rows to lock"

    seen_by_file: dict[Path, list[str]] = defaultdict(list)
    for path, idx, row in required:
        rel = path.relative_to(ROOT)
        oid = _canonical_id(row)
        assert oid, (
            f"{rel}:{idx} claim/finding/observation row missing stable non-blank "
            f"id (observation_id alias accepted): {row}"
        )
        assert oid == oid.strip(), f"{rel}:{idx} id has surrounding whitespace: {oid!r}"
        assert oid.lower() not in {"none", "null", "undefined", "n/a", "-"}, (
            f"{rel}:{idx} id {oid!r} is a placeholder"
        )
        prefix = f"{adapter}-"
        assert oid.startswith(prefix), (
            f"{rel}:{idx} id {oid!r} must be namespaced as {prefix}… "
            f"(global uniqueness is then natural)"
        )
        # Prefer writing canonical `id` even when observation_id is accepted.
        raw_id = row.get("id")
        if raw_id in (None, ""):
            alias = row.get("observation_id")
            assert isinstance(alias, str) and alias.strip() == oid, (
                f"{rel}:{idx} missing canonical id and observation_id alias is blank"
            )
        else:
            assert str(raw_id).strip() == oid, (
                f"{rel}:{idx} canonical id {raw_id!r} disagrees with resolved {oid!r}"
            )
        seen_by_file[path].append(oid)

    for path, ids in seen_by_file.items():
        rel = path.relative_to(ROOT)
        dups = sorted({oid for oid in ids if ids.count(oid) > 1})
        assert not dups, f"{rel} has duplicate observation ids: {dups}"


def test_pack_drop_observation_ids_globally_unique() -> None:
    """Walk all sixteen fixtures; colliding sibling ids would collapse CISO rows."""
    owners: dict[str, list[str]] = defaultdict(list)
    required_count = 0
    for adapter in E2E_PROVEN_PACK_DROP_ADAPTERS:
        for path, idx, row in _iter_adapter_rows(adapter):
            oid = _canonical_id(row)
            if not oid:
                continue
            loc = f"{path.relative_to(ROOT)}:{idx}"
            owners[oid].append(loc)
            if _row_needs_id(row):
                required_count += 1
    assert required_count >= 16, "expected at least one locked id per E2E_PROVEN adapter"
    collisions = {oid: locs for oid, locs in owners.items() if len(locs) > 1}
    assert not collisions, (
        "duplicate pack_drop observation ids across the sixteen-set "
        f"(would collapse CISO rows): {collisions}"
    )
    assert len(owners) == sum(len(locs) for locs in owners.values())
    for name in COVEY_E2E_UNPROVEN:
        assert name not in {p.name for p in PACK_DROP.iterdir() if p.is_dir()}
