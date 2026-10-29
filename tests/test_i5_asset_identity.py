"""prior-unit: multi-collector asset identity folds loopback + distro suffix."""
from __future__ import annotations
from shared.asset_ledger import AssetLedger, attach_asset_uids
from shared.host_canon import canonical_host_key
from shared.schema import make_record, make_ref
from shared.asset_ids import classify_name

def _asset(source: str, name: str, **extra):
    return make_record(
        kind="asset", source=source, ref_id=make_ref(source, f"a-{name}"),
        name=name, description="synthetic", severity="info", category="host",
        assets=[name], labels=["host"], collected_at="2026-10-07T00:00:00Z",
        extra={"asset_type": "PR", **extra},
    )

def test_host_canon_loopback_and_distro_unit():
    assert canonical_host_key("localhost") == "127.0.0.1"
    assert canonical_host_key("host1.debian") == "host1"

def test_multi_collector_loopback_one_asset():
    recs = [
        _asset("host-wazuh", "localhost", hostname="localhost"),
        _asset("inventory-nmap", "127.0.0.1", ip="127.0.0.1"),
    ]
    assets = [r for r in attach_asset_uids(recs, AssetLedger()) if r.get("kind") == "asset"]
    assert len(assets) == 1, [a.get("name") for a in assets]

def test_multi_collector_distro_suffix_one_asset():
    recs = [
        _asset("host-wazuh", "host1.debian", hostname="host1.debian"),
        _asset("inventory-nmap", "host1", hostname="host1", ip="10.0.0.50"),
    ]
    assets = [r for r in attach_asset_uids(recs, AssetLedger()) if r.get("kind") == "asset"]
    assert len(assets) == 1, [a.get("name") for a in assets]

def test_multi_label_local_fqdn_not_stripped_in_classify():
    got = classify_name("web.corp.local")
    assert got.get("fqdn") == "web.corp.local"
