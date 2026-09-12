"""Lock global pack_drop meta.json source identity (META-ONLY).

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.

Every fixtures/pack_drop/<adapter>/meta.json must exist with:
source == evergreen-covey (exact) and schema == covey.pack_drop.v1
(schema already locked by tests/test_pack_drop_meta.py — re-asserted here).

META-ONLY: do not assert or rewrite assets.jsonl / findings.jsonl row
source fields (parse_live_hosts, pass2, svmap-table, None, …). Those
are provenance. Do not invent pack_source / export_source.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_ADAPTERS
from tests.test_pack_drop_meta import REQUIRED_SCHEMA
from tests.test_status_honesty import COVEY_E2E_PROVEN, COVEY_E2E_UNPROVEN

ROOT = Path(__file__).resolve().parents[1]
PACK_DROP = ROOT / "fixtures" / "pack_drop"
REQUIRED_SOURCE = "evergreen-covey"


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} must be a JSON object"
    return data


def test_source_lock_partition_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS


def test_unproven_adapters_absent_from_pack_drop_source() -> None:
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
def test_pack_drop_meta_source_identity(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"

    meta_path = dest / "meta.json"
    assert meta_path.is_file(), f"missing fixtures/pack_drop/{adapter}/meta.json"

    meta = _load_json(meta_path)
    source = meta.get("source")
    assert source == REQUIRED_SOURCE, (
        f"{adapter} meta.source={source!r} must be exactly {REQUIRED_SOURCE}"
    )
    schema = meta.get("schema")
    assert schema == REQUIRED_SCHEMA, (
        f"{adapter} schema={schema!r} must be exactly {REQUIRED_SCHEMA}"
    )
