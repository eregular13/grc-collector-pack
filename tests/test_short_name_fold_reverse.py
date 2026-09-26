"""CR6-A: short-name↔FQDN fold must wait until every FQDN in the run is visible.

Argus cold-review-6: #172 refused the fold when FQDNs arrived first, but
_find_match still merged the first FQDN onto an existing bare hostname.
Normal grc_loader order (host-wazuh before inventory-nmap) always hits
that reverse direction — agent web01 folded into whichever of
web01.corp-a.local / web01.corp-b.local arrived first.

Fixtures match the /tmp/cr6-r172 shape: two nmap FQDNs sharing the
short label plus a Wazuh agent named web01.
"""

from __future__ import annotations

from shared.asset_ids import stamp_ids
from shared.asset_ledger import AssetLedger, attach_asset_uids
from shared.schema import make_record, make_ref

NOW = "2026-09-01T00:00:00Z"

CORP_A = ("web01.corp-a.local", "10.1.0.10")
CORP_B = ("web01.corp-b.local", "10.2.0.10")
UNAMBIGUOUS = ("web01.corp.local", "10.0.0.5")


def _nmap_fqdn(fqdn: str, ip: str) -> dict:
    return make_record(
        kind="asset",
        source="inventory-nmap",
        ref_id=make_ref("inventory-nmap", f"asset-{fqdn}"),
        name=fqdn,
        description=f"Host {fqdn}",
        category="host",
        assets=[fqdn],
        labels=["nmap"],
        collected_at=NOW,
        extra=stamp_ids({}, fqdn=fqdn, ip=ip),
    )


def _wazuh_agent(name: str) -> dict:
    return make_record(
        kind="asset",
        source="host-wazuh",
        ref_id=make_ref("host-wazuh", f"asset-{name}"),
        name=name,
        description=f"Wazuh agent {name}",
        category="host",
        assets=[name],
        labels=["wazuh", "host"],
        collected_at=NOW,
        extra=stamp_ids({}, hostname=name),
    )


def _active_uids(ledger: AssetLedger) -> set[str]:
    return {
        str(a["asset_uid"])
        for a in ledger.assets.values()
        if a.get("status") == "active"
    }


def _stamped_uids(records: list[dict]) -> set[str]:
    stamped = attach_asset_uids(records, AssetLedger(), now=NOW)
    return {
        str((r.get("extra") or {}).get("asset_uid") or "")
        for r in stamped
        if r.get("kind") == "asset"
    }


def test_ambiguous_web01_stays_separate_both_arrival_orders() -> None:
    """web01.corp-a + web01.corp-b + Wazuh web01 → three EGAs, any order."""
    pair_orders = ((CORP_A, CORP_B), (CORP_B, CORP_A))
    for first, second in pair_orders:
        nmap = [_nmap_fqdn(*first), _nmap_fqdn(*second)]
        wazuh = _wazuh_agent("web01")
        for recs, label in (
            (nmap + [wazuh], f"fqdn-first:{first[0]}"),
            ([wazuh] + nmap, f"wazuh-first:{first[0]}"),
        ):
            uids = _stamped_uids(recs)
            assert len(uids) == 3, label


def test_unambiguous_single_fqdn_folds_both_arrival_orders() -> None:
    """One FQDN sharing the short label still attaches to the agent."""
    nmap = _nmap_fqdn(*UNAMBIGUOUS)
    wazuh = _wazuh_agent("web01")
    for recs, label in (
        ([nmap, wazuh], "fqdn-first"),
        ([wazuh, nmap], "wazuh-first"),
    ):
        uids = _stamped_uids(recs)
        assert len(uids) == 1, label


def test_reverse_observe_does_not_eager_fold_first_fqdn() -> None:
    """First FQDN must not absorb bare web01 during observe — corp-b is not visible yet."""
    ledger = AssetLedger()
    uid_bare = ledger.observe(_wazuh_agent("web01"), now=NOW, source="host-wazuh")
    uid_a = ledger.observe(_nmap_fqdn(*CORP_A), now=NOW, source="inventory-nmap")
    assert uid_a != uid_bare
    uid_b = ledger.observe(_nmap_fqdn(*CORP_B), now=NOW, source="inventory-nmap")
    assert len({uid_bare, uid_a, uid_b}) == 3
    ledger.late_merge_pass(now=NOW)
    assert len(_active_uids(ledger)) == 3


def test_unambiguous_reverse_fold_waits_for_late_merge() -> None:
    """Two-pass: wazuh then one FQDN stay split until late_merge_pass."""
    ledger = AssetLedger()
    uid_bare = ledger.observe(_wazuh_agent("web01"), now=NOW, source="host-wazuh")
    uid_fq = ledger.observe(_nmap_fqdn(*UNAMBIGUOUS), now=NOW, source="inventory-nmap")
    assert uid_bare != uid_fq
    ledger.late_merge_pass(now=NOW)
    assert len(_active_uids(ledger)) == 1
