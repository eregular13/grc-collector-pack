"""Indexed _find_match: correctness + scale benchmark (synthetic only)."""
from __future__ import annotations

import math
import time

from shared.asset_ids import stamp_ids
from shared.asset_ledger import AssetLedger, attach_asset_uids
from shared.schema import make_record

NOW = "2026-03-01T00:00:00Z"


def _host(i: int, *, now: str = NOW, with_ip: bool = True) -> dict:
    name = f"host-{i}.example.test"
    ids: dict = {
        "agent": f"agent:example:{i:05d}",
        "fqdn": name,
    }
    if with_ip:
        # Unique addresses inside TEST-NET-3 by packing i into the low 8 bits
        # only when i < 250; larger benches omit IP (agent+fqdn are enough).
        ids["ip"] = f"203.0.113.{(i % 250) + 1}"
    extra = stamp_ids({"asset_type": "PR"}, **ids)
    return make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id=f"NMAP-asset-{name}",
        name=name,
        description=f"Host {name}",
        category="host",
        assets=[name],
        labels=["synthetic"],
        collected_at=now,
        extra=extra,
    )


def test_indexed_match_reuses_uid_on_second_observe() -> None:
    ledger = AssetLedger()
    first = _host(1)
    uid1 = ledger.observe(first, now=NOW, source="inventory-nmap")
    second = _host(1)
    uid2 = ledger.observe(second, now=NOW, source="inventory-nmap")
    assert uid1 == uid2
    assert len([a for a in ledger.assets.values() if a.get("status") == "active"]) == 1
    hits = ledger._indexed_candidates("agent", ["agent:example:00001"])
    assert [h["asset_uid"] for h in hits] == [uid1]


def test_indexed_match_distinguishes_hosts() -> None:
    ledger = AssetLedger()
    uids = [ledger.observe(_host(i), now=NOW, source="inventory-nmap") for i in range(20)]
    assert len(set(uids)) == 20
    again = ledger.observe(_host(7), now=NOW, source="inventory-nmap")
    assert again == uids[7]


def test_indexed_match_scale_subquadratic() -> None:
    """Doubling host count should stay near-linear with the id index.

    Pre-index, _find_match scanned every active asset per observation (~O(n^2)).
    After indexing strong aliases (and IP reassign/split/late-merge), growth on
    synthetic agent+fqdn hosts should stay well below quadratic.
    """

    def _run(n: int) -> float:
        records = [_host(i, with_ip=False) for i in range(n)]
        for i in range(n):
            name = f"host-{i}.example.test"
            records.append(
                make_record(
                    kind="finding",
                    source="vuln-scan",
                    ref_id=f"VULN-{i}",
                    name=f"synthetic finding {i}",
                    description="bench",
                    severity="low",
                    category="vuln",
                    assets=[name],
                    labels=["synthetic"],
                    collected_at=NOW,
                    extra=stamp_ids(
                        {},
                        agent=f"agent:example:{i:05d}",
                        fqdn=name,
                    ),
                )
            )
        ledger = AssetLedger()
        t0 = time.perf_counter()
        attach_asset_uids(records, ledger, now=NOW)
        elapsed = time.perf_counter() - t0
        active = sum(1 for a in ledger.assets.values() if a.get("status") == "active")
        assert active == n
        return elapsed

    _run(50)
    t_small = min(_run(300), _run(300))
    t_large = min(_run(600), _run(600))
    ratio = t_large / max(t_small, 1e-6)
    growth = math.log(ratio) / math.log(2.0)
    assert growth < 1.55, (
        f"indexed match still superlinear: n=300 -> {t_small:.4f}s, "
        f"n=600 -> {t_large:.4f}s, ratio={ratio:.2f}, log2-growth={growth:.2f}"
    )
