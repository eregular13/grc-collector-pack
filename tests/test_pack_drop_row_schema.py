"""Lock global pack_drop JSONL row schema + adapter identity.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.

Every object in fixtures/pack_drop/<adapter>/assets.jsonl and
findings.jsonl must have:
schema == covey.pack_drop.v1 (exact; missing forbidden;
evergreen.pack_drop.v1 forbidden),
adapter == directory name (exact; missing/null forbidden,
including nmap finding/asset rows).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_ADAPTERS
from tests.test_status_honesty import COVEY_E2E_PROVEN, COVEY_E2E_UNPROVEN

ROOT = Path(__file__).resolve().parents[1]
PACK_DROP = ROOT / "fixtures" / "pack_drop"
JSONL_FILES = ("assets.jsonl", "findings.jsonl")
REQUIRED_SCHEMA = "covey.pack_drop.v1"
FORBIDDEN_SCHEMA = "evergreen.pack_drop.v1"


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


def test_row_schema_lock_partition_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS


def test_unproven_adapters_absent_from_pack_drop_row_schema() -> None:
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
def test_pack_drop_jsonl_row_schema_and_adapter_identity(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"

    for filename in JSONL_FILES:
        path = dest / filename
        assert path.is_file(), f"missing fixtures/pack_drop/{adapter}/{filename}"
        rows = _load_jsonl(path)
        assert rows, f"{adapter}/{filename} must have at least one JSONL object"

        for idx, row in enumerate(rows, start=1):
            loc = f"{adapter}/{filename}:{idx}"
            assert "schema" in row, f"{loc} missing schema (forbid missing schema)"
            schema = row.get("schema")
            assert schema == REQUIRED_SCHEMA, (
                f"{loc} schema={schema!r} must be exactly {REQUIRED_SCHEMA}"
            )
            assert schema != FORBIDDEN_SCHEMA, (
                f"{loc} schema must not be {FORBIDDEN_SCHEMA}"
            )
            assert "adapter" in row, f"{loc} missing adapter"
            got = row.get("adapter")
            assert got is not None, f"{loc} adapter must not be null"
            assert got == adapter, (
                f"{loc} adapter={got!r} must match directory name {adapter!r}"
            )
