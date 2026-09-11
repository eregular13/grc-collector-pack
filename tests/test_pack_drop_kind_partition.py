"""Lock global pack_drop assets/findings kind partition.

Parametrized over the shared sixteen E2E_PROVEN set so fixtures/pack_drop/
cannot drift from prove_ciso / honesty inventory locks. No 17th adapter.

Every object in fixtures/pack_drop/<adapter>/assets.jsonl must have
kind ∈ {asset, host, service} exact (absent / other forbidden).
Every object in findings.jsonl must have kind ∈ {finding, observation}
exact (absent / other forbidden). No cross-file leakage: findings
kinds never appear in assets.jsonl; asset/host/service kinds never
appear in findings.jsonl.
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
ASSET_KINDS = frozenset({"asset", "host", "service"})
FINDING_KINDS = frozenset({"finding", "observation"})


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


def test_kind_partition_lock_matches_e2e_proven_sixteen() -> None:
    assert frozenset(E2E_PROVEN_PACK_DROP_ADAPTERS) == frozenset(COVEY_E2E_PROVEN)
    assert E2E_PROVEN_PACK_DROP_ADAPTERS is COVEY_E2E_PROVEN or tuple(
        E2E_PROVEN_PACK_DROP_ADAPTERS
    ) == tuple(COVEY_E2E_PROVEN)
    assert len(E2E_PROVEN_PACK_DROP_ADAPTERS) == 16
    assert len(set(E2E_PROVEN_PACK_DROP_ADAPTERS)) == 16
    for name in COVEY_E2E_UNPROVEN:
        assert name not in E2E_PROVEN_PACK_DROP_ADAPTERS
    assert ASSET_KINDS.isdisjoint(FINDING_KINDS)


def test_unproven_adapters_absent_from_pack_drop_kind_partition() -> None:
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
def test_pack_drop_assets_findings_kind_partition(adapter: str) -> None:
    dest = PACK_DROP / adapter
    assert dest.is_dir(), f"missing fixtures/pack_drop/{adapter}/"

    assets_path = dest / "assets.jsonl"
    findings_path = dest / "findings.jsonl"
    assert assets_path.is_file(), f"missing fixtures/pack_drop/{adapter}/assets.jsonl"
    assert findings_path.is_file(), f"missing fixtures/pack_drop/{adapter}/findings.jsonl"

    asset_rows = _load_jsonl(assets_path)
    finding_rows = _load_jsonl(findings_path)
    assert asset_rows, f"{adapter}/assets.jsonl must have at least one JSONL object"
    assert finding_rows, f"{adapter}/findings.jsonl must have at least one JSONL object"

    seen_asset_kinds: set[str] = set()
    for idx, row in enumerate(asset_rows, start=1):
        loc = f"{adapter}/assets.jsonl:{idx}"
        assert "kind" in row, f"{loc} kind field is absent (forbidden)"
        kind = row.get("kind")
        assert isinstance(kind, str), f"{loc} kind={kind!r} must be a string"
        assert kind in ASSET_KINDS, (
            f"{loc} kind={kind!r} must be exactly one of {sorted(ASSET_KINDS)}"
        )
        assert kind not in FINDING_KINDS, (
            f"{loc} kind={kind!r} leaks a findings kind into assets.jsonl"
        )
        seen_asset_kinds.add(kind)

    seen_finding_kinds: set[str] = set()
    for idx, row in enumerate(finding_rows, start=1):
        loc = f"{adapter}/findings.jsonl:{idx}"
        assert "kind" in row, f"{loc} kind field is absent (forbidden)"
        kind = row.get("kind")
        assert isinstance(kind, str), f"{loc} kind={kind!r} must be a string"
        assert kind in FINDING_KINDS, (
            f"{loc} kind={kind!r} must be exactly one of {sorted(FINDING_KINDS)}"
        )
        assert kind not in ASSET_KINDS, (
            f"{loc} kind={kind!r} leaks an assets kind into findings.jsonl"
        )
        seen_finding_kinds.add(kind)

    assert seen_asset_kinds.isdisjoint(FINDING_KINDS), (
        f"{adapter}/assets.jsonl leaked findings kinds {sorted(seen_asset_kinds & FINDING_KINDS)}"
    )
    assert seen_finding_kinds.isdisjoint(ASSET_KINDS), (
        f"{adapter}/findings.jsonl leaked assets kinds {sorted(seen_finding_kinds & ASSET_KINDS)}"
    )
    assert seen_asset_kinds.isdisjoint(seen_finding_kinds), (
        f"{adapter} cross-file kind leakage {sorted(seen_asset_kinds & seen_finding_kinds)}"
    )
