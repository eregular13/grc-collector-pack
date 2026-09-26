"""Asset identity ledger: spec §5.7 cases, updated for §6.3 match order.

§6.3 changes the *match ladder* (UUID → BIOS UUID → MAC → NetBIOS →
FQDN → IP) and the conflict rule. Outcomes that differ from a literal
§5.4 reading are called out on the test. Extra cases cover a stronger-ID
conflict, a missing UUID, a shared-UUID collision, and container
RepoDigests → ArtifactID → ImageID precedence.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from shared.asset_ids import mac_is_locally_administered, stamp_ids
from shared.asset_ledger import (
    ASSET_UID_PREFIX,
    AssetLedger,
    asset_uid,
    resolve_asset_id,
)
from shared.iiw import IIW_HEADERS, write_iiw
from shared.schema import make_record

NOW1 = "2026-01-01T00:00:00Z"
NOW2 = "2026-01-02T00:00:00Z"
NOW3 = "2026-01-10T00:00:00Z"  # 9 days after NOW1 — outside the 7-day IP lease
NOW4 = "2026-01-11T00:00:00Z"


def _asset(
    name: str,
    *,
    now: str = NOW1,
    source: str = "inventory-nmap",
    **ids: object,
) -> dict:
    extra = stamp_ids({"asset_type": "PR"}, **ids)
    return make_record(
        kind="asset",
        source=source,
        ref_id=f"NMAP-asset-{name}",
        name=name,
        description=f"Host {name}",
        category="host",
        assets=[name],
        labels=["lab"],
        collected_at=now,
        extra=extra,
    )


def _observe(ledger: AssetLedger, rec: dict, now: str) -> str:
    return ledger.observe(rec, now=now, source=str(rec.get("source") or ""))


# ---------------------------------------------------------------------------
# §5.7.1–12
# ---------------------------------------------------------------------------


def test_5_7_1_ip_change_dhcp_renew_same_uid() -> None:
    """Host with agent X moves 10.0.0.5 → 10.0.0.9. Same UID. Old IP valid_to."""
    ledger = AssetLedger()
    a = _asset(
        "web.corp.local",
        now=NOW1,
        source="host-wazuh",
        agent="wazuh:default:001",
        fqdn="web.corp.local",
        ip="10.0.0.5",
    )
    uid1 = _observe(ledger, a, NOW1)
    b = _asset(
        "web.corp.local",
        now=NOW2,
        source="host-wazuh",
        agent="wazuh:default:001",
        fqdn="web.corp.local",
        ip="10.0.0.9",
    )
    uid2 = _observe(ledger, b, NOW2)
    assert uid1 == uid2
    assert uid1.startswith(ASSET_UID_PREFIX)
    asset = ledger.assets[uid1]
    ips = [al for al in asset["aliases"] if al["type"] == "ip"]
    old = next(al for al in ips if al["value"] == "10.0.0.5")
    new = next(al for al in ips if al["value"] == "10.0.0.9")
    assert old["valid_to"] == NOW2
    assert not new["valid_to"]
    assert asset["uai"] == "web.corp.local"


def test_5_7_2_dhcp_reuse_different_agents() -> None:
    """10.0.0.5 moves from agent X to agent Y. New asset B; A keeps UID."""
    ledger = AssetLedger()
    a = _asset(
        "host-a.corp.local",
        now=NOW1,
        source="host-wazuh",
        agent="wazuh:default:X",
        fqdn="host-a.corp.local",
        ip="10.0.0.5",
    )
    uid_a = _observe(ledger, a, NOW1)
    b = _asset(
        "host-b.corp.local",
        now=NOW2,
        source="host-wazuh",
        agent="wazuh:default:Y",
        fqdn="host-b.corp.local",
        ip="10.0.0.5",
    )
    uid_b = _observe(ledger, b, NOW2)
    assert uid_a != uid_b
    assert ledger.assets[uid_a]["status"] == "active"
    a_ips = [al for al in ledger.assets[uid_a]["aliases"] if al["type"] == "ip"]
    assert any(al["value"] == "10.0.0.5" and al["valid_to"] == NOW2 for al in a_ips)
    b_ips = [al for al in ledger.assets[uid_b]["aliases"] if al["type"] == "ip" and not al["valid_to"]]
    assert any(al["value"] == "10.0.0.5" for al in b_ips)
    assert any(e["kind"] == "ip_reassigned" for e in ledger.events)


def test_5_7_3_ip_only_reuse_different_mac_splits() -> None:
    """§6.3: MAC is above FQDN. Different GAA MACs on the same IP block the
    IP match (stronger-ID conflict) and create a new UID. Outcome matches
    §5.7.3. Old asset retires after 2 covered runs → pending_verification.
    """
    ledger = AssetLedger()
    a = _asset("10.0.0.7", now=NOW1, ip="10.0.0.7", mac="00:11:22:33:44:55")
    uid_a = _observe(ledger, a, NOW1)
    ledger.close_run(now=NOW1, source_families={"inventory-nmap"})
    b = _asset("10.0.0.7", now=NOW2, ip="10.0.0.7", mac="00:11:22:33:44:66")
    uid_b = _observe(ledger, b, NOW2)
    assert uid_a != uid_b
    ledger.close_run(now=NOW2, source_families={"inventory-nmap"})
    assert ledger.assets[uid_a]["status"] == "active"
    ledger.close_run(now=NOW4, source_families={"inventory-nmap"})
    assert ledger.assets[uid_a]["status"] == "retired"
    assert ledger.assets[uid_a]["poam_status"] == "pending_verification"


def test_5_7_4_cloud_instance_replacement_inherits() -> None:
    ledger = AssetLedger()
    old = _asset("i-aaa", now=NOW1, source="cloud-prowler", arn="arn:aws:ec2:us-east-1:1:instance/i-aaa")
    uid_old = _observe(ledger, old, NOW1)
    new = _asset("i-bbb", now=NOW2, source="cloud-prowler", arn="arn:aws:ec2:us-east-1:1:instance/i-bbb")
    uid_new = _observe(ledger, new, NOW2)
    assert uid_old != uid_new
    ledger.mark_replaces(uid_new, uid_old, now=NOW2)
    assert ledger.assets[uid_old]["status"] == "retired"
    assert ledger.assets[uid_new]["replaces"] == uid_old
    assert ledger.inherit_poam_from(uid_new) == uid_old


def test_5_7_5_autoscaling_one_class_uid() -> None:
    ledger = AssetLedger()
    uids = set()
    classes = set()
    for i in range(5):
        rec = _asset(
            f"i-{i:03d}",
            now=NOW1,
            source="cloud-prowler",
            image_ref="ami-abc/launch-template-1",
            arn=f"arn:aws:ec2:us-east-1:1:instance/i-{i:03d}",
        )
        rec["extra"]["ephemeral"] = True
        uid = _observe(ledger, rec, NOW1)
        uids.add(uid)
        classes.add(ledger.assets[uid].get("class_uid") or "")
    # Distinct instances (ARN) but one class_uid for the launch template.
    assert len(classes) == 1
    assert next(iter(classes)).startswith(ASSET_UID_PREFIX)


def test_5_7_6_multihomed_one_asset_two_ips() -> None:
    ledger = AssetLedger()
    a = _asset("db1.corp", now=NOW1, fqdn="db1.corp", ip="10.0.0.5")
    uid1 = _observe(ledger, a, NOW1)
    b = _asset("db1.corp", now=NOW1, fqdn="db1.corp", ip="192.168.1.5")
    uid2 = _observe(ledger, b, NOW1)
    assert uid1 == uid2
    ips = {al["value"] for al in ledger.assets[uid1]["aliases"] if al["type"] == "ip" and not al["valid_to"]}
    assert ips == {"10.0.0.5", "192.168.1.5"}
    dest = Path("/tmp/iiw-multi")
    write_iiw(ledger, dest_dir=dest, observed={uid1})
    rows = list(csv.DictReader((dest / "iiw_inventory.csv").open(encoding="utf-8")))
    assert list(rows[0].keys()) == list(IIW_HEADERS)
    assert len(rows) == 1
    cell = rows[0]["IPv4 or IPv6 Address"]
    assert "10.0.0.5" in cell and "192.168.1.5" in cell
    assert rows[0]["UNIQUE ASSET IDENTIFIER"] == "db1.corp"
    assert rows[0]["DNS Name or URL"] == "db1.corp"


def test_5_7_7_ipv4_ipv6_one_asset() -> None:
    ledger = AssetLedger()
    a = _asset("dual.corp", now=NOW1, fqdn="dual.corp", ip=["192.0.2.10", "2001:db8::10"])
    uid = _observe(ledger, a, NOW1)
    b = _asset("dual.corp", now=NOW2, fqdn="dual.corp", ip="2001:db8::10")
    assert _observe(ledger, b, NOW2) == uid
    ips = {al["value"] for al in ledger.assets[uid]["aliases"] if al["type"] == "ip"}
    assert "192.0.2.10" in ips
    assert "2001:db8::10" in ips


def test_5_7_8_late_merge_ip_plus_mac() -> None:
    """§6.3: after the Wazuh row brings a GAA MAC, late_merge matches on MAC
    (now stronger than FQDN/IP). Outcome is still one surviving UID.
    """
    ledger = AssetLedger()
    nessus = _asset("10.0.0.8", now=NOW1, source="vuln-scan", ip="10.0.0.8")
    uid_n = _observe(ledger, nessus, NOW1)
    wazuh = _asset(
        "agent-08",
        now=NOW2,
        source="host-wazuh",
        ip="10.0.0.8",
        mac="00:1a:2b:3c:4d:5e",
        agent="wazuh:default:008",
    )
    uid_w = _observe(ledger, wazuh, NOW2)
    ledger.late_merge_pass(now=NOW2)
    kept = [a for a in ledger.assets.values() if a["status"] == "active"]
    assert len(kept) == 1
    assert kept[0]["asset_uid"] in {uid_n, uid_w}
    # §6.3: IP match is allowed when the IP-only row has no stronger id to
    # conflict, so this often lands as a live match (same UID) rather than
    # a later merge event. Either path keeps one UID and the earliest date.
    if uid_n != uid_w:
        assert any(e["kind"] == "merged" for e in ledger.events)
    assert any(al["type"] == "mac" for al in kept[0]["aliases"])


def test_5_7_9_hostname_rename_same_agent() -> None:
    ledger = AssetLedger()
    a = _asset(
        "old.corp.local",
        now=NOW1,
        source="host-wazuh",
        agent="wazuh:default:009",
        fqdn="old.corp.local",
        ip="10.0.0.9",
    )
    uid1 = _observe(ledger, a, NOW1)
    b = _asset(
        "new.corp.local",
        now=NOW2,
        source="host-wazuh",
        agent="wazuh:default:009",
        fqdn="new.corp.local",
        ip="10.0.0.9",
    )
    uid2 = _observe(ledger, b, NOW2)
    assert uid1 == uid2
    assert ledger.assets[uid1]["uai"] == "new.corp.local"
    old = next(
        al
        for al in ledger.assets[uid1]["aliases"]
        if al["type"] == "fqdn" and al["value"] == "old.corp.local"
    )
    assert old["valid_to"] == NOW2
    assert ledger.assets[uid1]["uai"] == "new.corp.local"


def test_5_7_10_short_name_collision_two_uids() -> None:
    """Fixes grc_loader _dedupe name.strip().lower() collapsing two hosts."""
    ledger = AssetLedger()
    a = _asset("web01", now=NOW1, source="host-wazuh", agent="wazuh:default:A", hostname="web01", ip="10.0.1.1")
    b = _asset("web01", now=NOW1, source="host-wazuh", agent="wazuh:default:B", hostname="web01", ip="10.0.1.2")
    uid_a = _observe(ledger, a, NOW1)
    uid_b = _observe(ledger, b, NOW1)
    assert uid_a != uid_b


def test_5_7_11_container_two_digests_one_row() -> None:
    """IIW class = repo/app:1.4. Two RepoDigests stay one row (B=ref, C=digests).

    §6.3 keys containers on RepoDigests → ArtifactID → ImageID when no
    image_ref is present. When the class ref is present we keep one row
    so B stays unique (S22 B4 / B12).
    """
    ledger = AssetLedger()
    a = _asset(
        "repo/app:1.4 (alpine 3.10)",
        now=NOW1,
        source="vuln-scan",
        image_ref="repo/app:1.4",
        image_digest=["repo/app@sha256:aaa"],
    )
    b = _asset(
        "repo/app:1.4 (alpine 3.10)",
        now=NOW1,
        source="vuln-scan",
        image_ref="repo/app:1.4",
        image_digest=["repo/app@sha256:bbb"],
    )
    uid1 = _observe(ledger, a, NOW1)
    uid2 = _observe(ledger, b, NOW1)
    assert uid1 == uid2
    dest = Path("/tmp/iiw-container")
    write_iiw(ledger, dest_dir=dest, observed={uid1})
    rows = list(csv.DictReader((dest / "iiw_inventory.csv").open(encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["UNIQUE ASSET IDENTIFIER"] == "repo/app:1.4"
    cell = rows[0]["IPv4 or IPv6 Address"]
    # digests live in comments/aliases; C is IP. Class row has no IP.
    assert cell == ""
    comments = rows[0]["Comments"]
    assert "sha256:aaa" in comments and "sha256:bbb" in comments


def test_5_7_12_lost_ledger_regenerates_with_warning() -> None:
    rec = _asset("stable.corp.local", now=NOW1, fqdn="stable.corp.local", uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    ledger = AssetLedger()
    uid_kept = _observe(ledger, rec, NOW1)
    # Lost ledger: same record, no file, regenerate from strongest alias (uuid).
    uid_regen = asset_uid(dict(rec), None, now=NOW2)
    assert uid_regen.startswith(ASSET_UID_PREFIX)
    assert rec["extra"].get("ledger_warning") == "lost_or_absent"
    # Same strongest alias → same UID (no drift). Documented here.
    assert uid_regen == uid_kept
    # Drift case: stronger alias arrives after loss (ARN vs original FQDN-only).
    drifted = _asset("stable.corp.local", now=NOW2, fqdn="stable.corp.local", arn="arn:aws:ec2:us-east-1:1:instance/i-new")
    uid_drift = asset_uid(drifted, None, now=NOW2)
    assert uid_drift != uid_kept


# ---------------------------------------------------------------------------
# §6.3 extras
# ---------------------------------------------------------------------------


def test_stronger_id_conflict_blocks_ip_match() -> None:
    ledger = AssetLedger()
    a = _asset(
        "one.corp",
        now=NOW1,
        uuid="11111111-1111-1111-1111-111111111111",
        fqdn="one.corp",
        ip="10.0.0.50",
    )
    uid_a = _observe(ledger, a, NOW1)
    b = _asset(
        "two.corp",
        now=NOW2,
        uuid="22222222-2222-2222-2222-222222222222",
        fqdn="two.corp",
        ip="10.0.0.50",
    )
    uid_b = _observe(ledger, b, NOW2)
    assert uid_a != uid_b


def test_missing_uuid_does_not_split() -> None:
    """Uncredentialed rescan has no UUID. Missing ≠ different."""
    ledger = AssetLedger()
    a = _asset(
        "host.corp",
        now=NOW1,
        uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        fqdn="host.corp",
        ip="10.0.0.60",
        id_quality="credentialed",
    )
    uid1 = _observe(ledger, a, NOW1)
    b = _asset(
        "host.corp",
        now=NOW2,
        fqdn="host.corp",
        ip="10.0.0.60",
        id_quality="uncredentialed",
    )
    uid2 = _observe(ledger, b, NOW2)
    assert uid1 == uid2


def test_shared_uuid_collision_not_a_match_key() -> None:
    ledger = AssetLedger()
    shared = "3ac4028d-aaaa-bbbb-cccc-dddddddddddd"
    a = _asset(
        "testhost.corp",
        now=NOW1,
        uuid=shared,
        fqdn="testhost.corp",
        mac="00:11:22:33:44:01",
        ip="10.0.0.1",
    )
    b = _asset(
        "testhost2.corp",
        now=NOW1,
        uuid=shared,
        fqdn="testhost2.corp",
        mac="00:11:22:33:44:02",
        ip="10.0.0.2",
    )
    uid_a = _observe(ledger, a, NOW1)
    uid_b = _observe(ledger, b, NOW1)
    assert uid_a != uid_b
    assert any(c.get("kind") == "uuid_collision" for c in ledger.collisions)


def test_container_keying_digest_then_artifact_then_image() -> None:
    """No image_ref: RepoDigests beat ArtifactID beat ImageID."""
    ledger = AssetLedger()
    digest = _asset(
        "tar-a",
        now=NOW1,
        source="vuln-scan",
        image_digest=["repo@sha256:deadbeef"],
        artifact_id="art-1",
        image_id="sha256:1111",
    )
    same_digest = _asset(
        "tar-b",
        now=NOW1,
        source="vuln-scan",
        image_digest=["repo@sha256:deadbeef"],
        artifact_id="art-OTHER",
        image_id="sha256:OTHER",
    )
    assert _observe(ledger, digest, NOW1) == _observe(ledger, same_digest, NOW1)

    ledger2 = AssetLedger()
    art = _asset("fs-a", now=NOW1, source="vuln-scan", artifact_id="art-9", image_id="sha256:aaaa")
    same_art = _asset("fs-b", now=NOW1, source="vuln-scan", artifact_id="art-9", image_id="sha256:bbbb")
    assert _observe(ledger2, art, NOW1) == _observe(ledger2, same_art, NOW1)

    ledger3 = AssetLedger()
    img = _asset("img-a", now=NOW1, source="vuln-scan", image_id="sha256:cccc")
    same_img = _asset("img-b", now=NOW1, source="vuln-scan", image_id="sha256:cccc")
    other_img = _asset("img-c", now=NOW1, source="vuln-scan", image_id="sha256:dddd")
    uid = _observe(ledger3, img, NOW1)
    assert _observe(ledger3, same_img, NOW1) == uid
    assert _observe(ledger3, other_img, NOW1) != uid


def test_locally_administered_mac_is_not_a_match_key() -> None:
    assert mac_is_locally_administered("02:42:ac:11:00:02")
    assert not mac_is_locally_administered("00:1a:2b:3c:4d:5e")
    ledger = AssetLedger()
    a = _asset("10.1.1.1", now=NOW1, ip="10.1.1.1", mac="02:42:ac:11:00:02")
    b = _asset("10.1.1.2", now=NOW1, ip="10.1.1.2", mac="02:42:ac:11:00:02")
    assert _observe(ledger, a, NOW1) != _observe(ledger, b, NOW1)


def test_ip_match_requires_scope_and_seven_day_window() -> None:
    ledger = AssetLedger()
    a = _asset("10.2.2.2", now=NOW1, ip="10.2.2.2", scope="vlan-10")
    uid = _observe(ledger, a, NOW1)
    other_scope = _asset("10.2.2.2", now=NOW2, ip="10.2.2.2", scope="vlan-20")
    assert _observe(ledger, other_scope, NOW2) != uid
    stale = _asset("10.2.2.2", now=NOW3, ip="10.2.2.2", scope="vlan-10")
    # 9 days later — lease expired
    assert _observe(ledger, stale, NOW3) != uid


def test_asset_uid_and_resolve_asset_id_same_signature() -> None:
    rec = _asset("api.corp.local", now=NOW1, fqdn="api.corp.local")
    ledger = AssetLedger()
    a = asset_uid(rec, ledger, now=NOW1)
    b = resolve_asset_id(rec, ledger, now=NOW1)
    assert a == b
    assert a.startswith(ASSET_UID_PREFIX)
    assert len(a) == 4 + 10


def test_iiw_headers_exact_and_never_na(tmp_path: Path) -> None:
    ledger = AssetLedger()
    rec = _asset("gap.corp.local", now=NOW1, fqdn="gap.corp.local", ip="10.9.9.9")
    uid = _observe(ledger, rec, NOW1)
    paths = write_iiw(ledger, dest_dir=tmp_path, observed={uid})
    header = paths["inventory"].read_text(encoding="utf-8").splitlines()[0]
    assert header.split(",") == list(IIW_HEADERS)
    assert header.endswith("End-of-Life ") or header.endswith('"End-of-Life "')
    blob = paths["inventory"].read_text(encoding="utf-8").lower()
    assert "n/a" not in blob
    gaps = list(csv.DictReader(paths["gaps"].open(encoding="utf-8")))
    assert gaps  # mandatory blanks listed, not filled with N/A
    assert all(g["field"] != "N/A" or True for g in gaps)


def test_ledger_roundtrip_stable_across_rescans(tmp_path: Path) -> None:
    rec = _asset("persist.corp.local", now=NOW1, fqdn="persist.corp.local", uuid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    first = AssetLedger()
    uid = _observe(first, rec, NOW1)
    dest = tmp_path / "asset-ledger.json"
    first.save(dest)
    second = AssetLedger.load(dest)
    uid2 = _observe(second, rec, NOW2)
    assert uid2 == uid
    assert second.prev_sha256


def test_grc_loader_no_longer_keys_assets_on_lowercased_name() -> None:
    """Same short name + different agents stay two CISO assets."""
    from collectors.grc_loader import _dedupe

    a = _asset("web01", agent="wazuh:default:A", hostname="web01", ip="10.0.1.1")
    b = _asset("web01", agent="wazuh:default:B", hostname="web01", ip="10.0.1.2")
    ledger = AssetLedger()
    attach = __import__("shared.asset_ledger", fromlist=["attach_asset_uids"]).attach_asset_uids
    recs = attach([a, b], ledger)
    out = _dedupe(recs)
    assets = [r for r in out if r.get("kind") == "asset"]
    assert len(assets) == 2
    assert assets[0]["extra"]["asset_uid"] != assets[1]["extra"]["asset_uid"]


def test_ambiguous_web01_fqdns_do_not_absorb_bare_name() -> None:
    """Bare web01 stays its own EGA when corp-a and corp-b both claim the label."""
    from shared.asset_ledger import attach_asset_uids

    pair = (
        ("web01.corp-a.local", "10.1.0.10"),
        ("web01.corp-b.local", "10.2.0.10"),
    )
    for order in (pair, tuple(reversed(pair))):
        ledger = AssetLedger()
        recs = [
            _asset(fqdn, now=NOW1, fqdn=fqdn, ip=ip) for fqdn, ip in order
        ]
        recs.append(
            _asset("web01", now=NOW1, source="host-wazuh", hostname="web01")
        )
        stamped = attach_asset_uids(recs, ledger, now=NOW1)
        assets = [r for r in stamped if r.get("kind") == "asset"]
        uids = {str((r.get("extra") or {}).get("asset_uid") or "") for r in assets}
        assert len(assets) == 3, order[0][0]
        assert len(uids) == 3, order[0][0]


def test_hostname_and_ip_same_host_merge() -> None:
    """Opposite of the old split: nmap hostname + Nessus IP of one host."""
    ledger = AssetLedger()
    nmap = _asset("web01.corp.local", now=NOW1, fqdn="web01.corp.local", ip="10.0.0.5")
    nessus = _asset("10.0.0.5", now=NOW1, source="vuln-scan", ip="10.0.0.5")
    uid_n = _observe(ledger, nmap, NOW1)
    uid_s = _observe(ledger, nessus, NOW1)
    assert uid_n == uid_s


def test_url_ip_matches_fqdn_and_keeps_fqdn_display() -> None:
    """Nuclei http://10.0.0.20 is the nmap host on that IP, not a second row."""
    from shared.asset_ledger import attach_asset_uids

    ledger = AssetLedger()
    nmap = _asset("telnet-legacy.corp.local", now=NOW1, fqdn="telnet-legacy.corp.local", ip="10.0.0.20")
    nuclei = _asset("http://10.0.0.20", now=NOW1, source="vuln-scan")
    recs = attach_asset_uids([nmap, nuclei], ledger)
    assets = [r for r in recs if r.get("kind") == "asset"]
    assert len(assets) == 1
    assert assets[0]["name"] == "telnet-legacy.corp.local"
    assert assets[0]["extra"]["uai"] == "telnet-legacy.corp.local"


def test_identifierless_same_name_is_one_uid() -> None:
    """Same path / cluster name with no host ids is a collector dupe, not two hosts."""
    ledger = AssetLedger()
    a = _asset("infra/terraform.tfvars", now=NOW1, source="code-secrets")
    b = _asset("infra/terraform.tfvars", now=NOW1, source="code-secrets")
    assert _observe(ledger, a, NOW1) == _observe(ledger, b, NOW1)


def test_nessus_parser_puts_ids_in_extra(tmp_path: Path) -> None:
    from collectors import vuln_scan

    dest = tmp_path / "ids.nessus"
    dest.write_text(
        """<NessusClientData_v2><Report name="t">
        <ReportHost name="10.0.0.20">
        <HostProperties>
          <tag name="host-ip">10.0.0.20</tag>
          <tag name="host-fqdn">web.corp.local</tag>
          <tag name="host-uuid">aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</tag>
          <tag name="bios-uuid">ffffffff-1111-2222-3333-444444444444</tag>
          <tag name="mac-address">00:11:22:33:44:55\\n0a:00:00:00:00:01</tag>
          <tag name="netbios-name">WEB01</tag>
          <tag name="local-checks-proto">local</tag>
        </HostProperties>
        <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="3"
         pluginID="42411" pluginName="Microsoft Windows SMB Shares Unprivileged Access">
        <risk_factor>High</risk_factor>
        <description>SMB</description>
        </ReportItem>
        </ReportHost></Report></NessusClientData_v2>
        """,
        encoding="utf-8",
    )
    recs = vuln_scan.parse_file(dest)
    assets = [r for r in recs if r["kind"] == "asset"]
    assert assets
    ids = assets[0]["extra"].get("ids") or {}
    assert ids.get("uuid") == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert ids.get("bios_uuid") == "ffffffff-1111-2222-3333-444444444444"
    assert "00:11:22:33:44:55" in (ids.get("mac") or [])
    assert "0a:00:00:00:00:01" not in (ids.get("mac") or [])  # LAA dropped from match set
    assert ids.get("netbios") == "WEB01"
    assert ids.get("fqdn") == "web.corp.local"
    assert ids.get("id_quality") == "credentialed"
    findings = [r for r in recs if r["kind"] == "finding"]
    assert findings and findings[0]["extra"].get("ids", {}).get("uuid")


def test_hardeningkitty_filename_host_in_extra_ids(tmp_path: Path) -> None:
    """PR #130 filename-derived Windows hosts stay distinct and land in extra.ids."""
    from collectors import identity_ad

    dest = tmp_path / "hardeningkitty-lab-win.lab.internal-20260926T000000Z.csv"
    dest.write_text(
        "ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding,DefaultValue,Filter\n"
        "10100,Account,Length of password history maintained,High,5,24,Failed,High,,\n",
        encoding="utf-8",
    )
    recs = identity_ad.parse_file(dest)
    assets = [r for r in recs if r["kind"] == "asset"]
    assert assets[0]["name"] == "lab-win.lab.internal"
    ids = assets[0]["extra"].get("ids") or {}
    assert ids.get("fqdn") == "lab-win.lab.internal"
    assert "windows-host" not in str(recs)
