"""Lock global pack_drop meta.json schema + adapter identity.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.

Every fixtures/pack_drop/<adapter>/meta.json must exist with:
schema == covey.pack_drop.v1 (exact; not evergreen.pack_drop.v1),
adapter == directory name, source == evergreen-covey, demo is JSON true,
and note/description (or equivalent) asserts SAMPLE/DEMO ≠ client estate.
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
REQUIRED_SCHEMA = "covey.pack_drop.v1"
FORBIDDEN_SCHEMA = "evergreen.pack_drop.v1"
REQUIRED_SOURCE = "evergreen-covey"


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} must be a JSON object"
    return data


def _string_fields(meta: dict[str, Any]) -> str:
    honesty = meta.get("honesty") if isinstance(meta.get("honesty"), dict) else {}
    parts = [
        meta.get("note"),
        meta.get("description"),
        meta.get("source"),
        honesty.get("note") if isinstance(honesty, dict) else "",
    ]
    return " ".join(str(part or "") for part in parts)


def test_meta_lock_partition_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS


def test_unproven_adapters_absent_from_pack_drop_meta() -> None:
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
def test_pack_drop_meta_schema_and_adapter_identity(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"

    meta_path = dest / "meta.json"
    assert meta_path.is_file(), f"missing fixtures/pack_drop/{adapter}/meta.json"

    meta = _load_json(meta_path)
    schema = meta.get("schema")
    assert schema == REQUIRED_SCHEMA, (
        f"{adapter} schema={schema!r} must be exactly {REQUIRED_SCHEMA}"
    )
    assert schema != FORBIDDEN_SCHEMA, (
        f"{adapter} schema must not be {FORBIDDEN_SCHEMA}"
    )
    assert meta.get("adapter") == adapter, (
        f"{adapter} meta.adapter={meta.get('adapter')!r} must match directory name"
    )
    assert meta.get("source") == REQUIRED_SOURCE, (
        f"{adapter} meta.source={meta.get('source')!r} must be {REQUIRED_SOURCE}"
    )
    demo = meta.get("demo")
    assert isinstance(demo, bool) and demo is True, (
        f"{adapter} meta.demo must be JSON boolean true, got {demo!r}"
    )

    label = _string_fields(meta).lower()
    assert "sample" in label or "demo" in label, (
        f"{adapter} note/description missing SAMPLE/DEMO"
    )
    assert "client" in label, (
        f"{adapter} note/description missing client (SAMPLE/DEMO ≠ client estate)"
    )
