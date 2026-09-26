"""Slim #149: GA-by-UPN merge + alias collapsed IDs + exec poam.csv marker.

Does not rewrite FedRAMP (#179) or port/identity pack_drop (#180).
Does not add excluded.csv poam_id (#181). Does not merge group-name vs FQDN.
"""

from __future__ import annotations

from datetime import datetime

from shared.estate_pages import (
    LABEL_FOR_KIND,
    SENTENCE_FOR_KIND,
    EstateStamp,
    PageContext,
    build_executive_summary,
)
from shared.finding_types import (
    dedupe_key,
    dedupe_weaknesses,
    finding_identity,
    finding_type,
    primary_asset,
    register_asset_key,
)
from shared.kev import KevCatalog
from shared.poam_ledger import apply_ledger, empty_ledger, fp_v1, payload_sha256
from shared.schema import make_record


def _unevaluated() -> KevCatalog:
    return KevCatalog(kev_evaluated=False, reason="snapshot_missing")


def _run(when: str) -> datetime:
    return datetime.fromisoformat(when.replace("Z", "+00:00"))


def _ga_scuba() -> dict:
    return make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-entra-ga-without-pim-gacontoso",
        name="Entra GA without PIM",
        description="ga@contoso.onmicrosoft.com is Global Administrator without PIM eligibility.",
        severity="critical",
        category="identity-posture",
        assets=["ga@contoso.onmicrosoft.com"],
        extra={"check_id": "bh-entra-ga-no-pim"},
    )


def _ga_graph() -> dict:
    return make_record(
        kind="finding",
        source="saas-idp",
        ref_id="SAAS-graph-ga-gacontoso",
        name="Entra Global Administrator via Graph",
        description="ga@contoso.onmicrosoft.com holds Global Administrator (Microsoft Graph export)",
        severity="critical",
        category="identity-gap",
        assets=["ga@contoso.onmicrosoft.com", "contoso.onmicrosoft.com"],
        extra={"role": "Global Administrator"},
    )


def _ga_standing() -> dict:
    return make_record(
        kind="finding",
        source="saas-idp",
        ref_id="SAAS-standing-admin-gacontoso",
        name="Standing Global Administrator",
        description=(
            "Export lists a standing Global Administrator assignment for "
            "ga@contoso.onmicrosoft.com (PIM-eligible is false in this drop)."
        ),
        severity="critical",
        category="identity-gap",
        assets=["ga@contoso.onmicrosoft.com", "contoso.onmicrosoft.com"],
        extra={"role": "Global Administrator", "pim_eligible": False},
    )


def test_privileged_role_disclaimer_is_not_entra_ga_pim() -> None:
    rec = make_record(
        kind="finding",
        source="saas-idp",
        ref_id="SAAS-standing-admin-adminexample-com",
        name="Privileged role (unspecified)",
        description=(
            "Export lists Privileged role (unspecified) for admin@example.com. "
            "This is not a Global Administrator claim. This is an identity-posture "
            "assessment finding from a dropped IdP export, not evidence of a breach "
            "or a live Graph/Okta/Google API call."
        ),
        severity="high",
        category="identity-gap",
        assets=["admin@example.com", "example.com"],
        extra={"role": "Privileged role (unspecified)", "pim_eligible": None},
    )
    assert finding_type(rec) != "entra_ga_pim"


def test_super_admin_disclaimer_is_not_entra_ga_pim() -> None:
    rec = make_record(
        kind="finding",
        source="saas-idp",
        ref_id="SAAS-standing-admin-itadmin",
        name="Privileged role",
        description=(
            "Export lists SUPER_ADMIN for it-admin@example.com. "
            "This is not a Global Administrator claim. This is an identity-posture "
            "assessment finding from a dropped IdP export, not evidence of a breach "
            "or a live Graph/Okta/Google API call."
        ),
        severity="high",
        category="identity-gap",
        assets=["it-admin@example.com"],
        extra={"role": "SUPER_ADMIN"},
    )
    assert finding_type(rec) != "entra_ga_pim"


def test_entra_ga_three_sources_share_dedupe_key() -> None:
    scuba, graph, standing = _ga_scuba(), _ga_graph(), _ga_standing()
    assert finding_type(scuba) == finding_type(graph) == finding_type(standing) == "entra_ga_pim"
    assert register_asset_key(scuba) == register_asset_key(graph) == register_asset_key(standing)
    assert dedupe_key(scuba) == dedupe_key(graph) == dedupe_key(standing)
    merged = [r for r in dedupe_weaknesses([scuba, graph, standing]) if r.get("kind") == "finding"]
    assert len(merged) == 1
    also = {str(x) for x in (merged[0].get("extra") or {}).get("also_ids") or []}
    assert "SAAS-graph-ga-gacontoso" in also or merged[0]["ref_id"] == "SAAS-graph-ga-gacontoso"
    assert "SAAS-standing-admin-gacontoso" in also or merged[0]["ref_id"] == "SAAS-standing-admin-gacontoso"


def test_register_asset_key_upn_only_for_entra_ga() -> None:
    """#177 keeps group-name/FQDN on primary_asset; only entra_ga_pim prefers @."""
    da = make_record(
        kind="finding",
        source="identity-ad",
        ref_id="ID-da-group",
        name="Domain Admins standing members",
        description="Domain Admins has standing members.",
        severity="critical",
        category="identity-posture",
        assets=["DOMAIN ADMINS@CORP.LOCAL", "dc01.corp.local"],
        extra={"check_id": "domain-admins"},
    )
    other_ga = _ga_graph()
    other_ga["assets"] = ["breakglass@contoso.onmicrosoft.com", "contoso.onmicrosoft.com"]
    other_ga["ref_id"] = "SAAS-graph-ga-breakglass"
    other_ga["description"] = (
        "breakglass@contoso.onmicrosoft.com holds Global Administrator "
        "(Microsoft Graph export)"
    )
    assert finding_type(da) == "ad_domain_admins"
    assert register_asset_key(da) == primary_asset(da)
    assert dedupe_key(_ga_graph()) != dedupe_key(other_ga)
    merged = [
        r
        for r in dedupe_weaknesses([_ga_graph(), other_ga])
        if r.get("kind") == "finding"
    ]
    assert len(merged) == 2


def test_httpx_admin_root_and_login_stay_two_dedupe_keys() -> None:
    root = {
        "kind": "finding",
        "source": "easm",
        "ref_id": "EASM-admin-root",
        "name": "Exposed admin interface on admin.example.com",
        "assets": ["admin.example.com"],
        "extra": {
            "check_id": "httpx-admin",
            "path": "https://admin.example.com",
            "url": "https://admin.example.com",
        },
    }
    login = {
        "kind": "finding",
        "source": "easm",
        "ref_id": "EASM-admin-login",
        "name": "Exposed admin interface on admin.example.com",
        "assets": ["admin.example.com"],
        "extra": {
            "check_id": "httpx-admin",
            "path": "/login",
            "url": "https://admin.example.com/login",
        },
    }
    assert finding_identity(root) != finding_identity(login)
    assert dedupe_key(root) != dedupe_key(login)


def test_port_only_does_not_swallow_smb_signing() -> None:
    """#180 owns port-only collapse. Slim must not fold signing into the port row."""
    port = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-filesrv-445",
        "name": "SMB 445 exposed",
        "assets": ["filesrv"],
        "extra": {"check_id": "nmap-port-445/tcp", "port": "445", "protocol": "tcp"},
    }
    signing = {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": "NMAP-filesrv-smb-signing",
        "name": "SMB signing not required",
        "assets": ["filesrv"],
        "extra": {"nse_script": "smb-security-mode", "port": "445", "protocol": "tcp"},
    }
    assert dedupe_key(port) != dedupe_key(signing)
    merged = [r for r in dedupe_weaknesses([port, signing]) if r.get("kind") == "finding"]
    assert len(merged) == 2


def test_merged_away_ga_ids_are_aliased_upgrade_equals_fresh() -> None:
    scuba, graph, standing = _ga_scuba(), _ga_graph(), _ga_standing()
    fresh_merged = [r for r in dedupe_weaknesses([scuba, graph, standing]) if r.get("kind") == "finding"]
    assert len(fresh_merged) == 1
    fresh = apply_ledger(
        fresh_merged,
        catalog=_unevaluated(),
        run_at=_run("2026-09-21T00:00:00Z"),
        prior_existed=False,
    )
    fresh_open = [
        it for it in fresh["items"].values() if str(it.get("status") or "") != "closed"
    ]
    assert len(fresh_open) == 1

    prior = empty_ledger()
    old_ids = []
    for i, rec in enumerate((scuba, graph, standing), start=1):
        old_fp = fp_v1(rec)
        pid = f"EGP-OLDGA{i:04d}X"
        old_ids.append(pid)
        prior["items"][old_fp] = {
            "poam_id": pid,
            "fp": old_fp,
            "source_family": rec["source"],
            "ref_id": rec["ref_id"],
            "name": rec["name"],
            "original_detection_date": "2024-01-15",
            "first_seen": "2024-01-15T00:00:00Z",
            "status": "open",
            "severity": "critical",
            "missed_covered_runs": 0,
            "kev_comments": [],
        }
    prior["sha256"] = payload_sha256(prior)
    upgraded = apply_ledger(
        fresh_merged,
        catalog=_unevaluated(),
        run_at=_run("2026-09-22T00:00:00Z"),
        ledger_in=prior,
        prior_existed=True,
    )
    open_items = [
        it for it in upgraded["items"].values() if str(it.get("status") or "") != "closed"
    ]
    aliases = {x for it in open_items for x in (it.get("aliased_poam_ids") or [])}
    created = [e for e in (upgraded.get("events_this_run") or []) if e.get("kind") == "created"]
    stolen = [
        e for e in (upgraded.get("events_this_run") or []) if e.get("kind") == "migrated_alias"
    ]
    assert created == []
    assert len(open_items) == len(fresh_open) == 1
    survivor_id = open_items[0]["poam_id"]
    assert survivor_id in old_ids
    assert set(old_ids) - {survivor_id} <= aliases
    assert len(aliases) == 2
    assert len(stolen) == 2
    assert all(m.get("reason") == "merged_away_alias" for m in upgraded.get("fp_migrations") or [] if m.get("alias_of"))


def test_exec_names_open_poam_from_poam_csv() -> None:
    stamp = EstateStamp(
        kind="LAB",
        label=LABEL_FOR_KIND["LAB"],
        sentence=SENTENCE_FOR_KIND["LAB"],
    )
    text = build_executive_summary(
        PageContext(
            stamp=stamp,
            findings=[],
            poam_rows=[{"severity": "high"}, {"severity": "critical"}],
            mapped_by_ref={},
            poam_n=2,
        )
    )
    assert "Open POA&M (poam.csv): 2" in text
