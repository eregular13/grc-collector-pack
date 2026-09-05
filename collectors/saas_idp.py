#!/usr/bin/env python3
"""Parse ScubaGear / Graph / Okta / Maester posture into SaaS findings.

Parse-only. Does not call Microsoft Graph or the Okta API.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, read_jsonl, run_collector
from shared.schema import make_record, make_ref

SOURCE = "saas-idp"
LABELS = ["saas", "idp"]
_PASS = frozenset(
    {
        "pass",
        "passed",
        "true",
        "success",
        "ok",
        "skip",
        "skipped",
        "info",
        "informational",
        "n/a",
        "na",
        "notapplicable",
        "notrun",
    }
)
_FAIL = frozenset({"fail", "failed", "error", "unsuccessful", "false"})
_LOW = frozenset({"info", "informational", "low"})


def _load(path: Path) -> Any:
    try:
        return read_json(path)
    except Exception:
        rows = read_jsonl(path)
        return rows if rows else {}


def _unwrap(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    for key in ("data", "ScubaResults", "scuba", "okta", "export"):
        inner = payload.get(key)
        if isinstance(inner, dict) and inner:
            return inner
        if isinstance(inner, list) and inner:
            return inner
    return payload


def _as_scuba(payload: Any) -> Any:
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        row = payload[0]
        if row.get("Requirement") or row.get("requirement") or (
            "Result" in row and "Tenant" in row
        ):
            return {"Results": payload}
    return payload


def _failing(result: Any, passed: Any = None) -> bool:
    if passed is True:
        return False
    if passed is False:
        return True
    token = str(result or "").lower()
    if token in _PASS:
        return False
    return token in _FAIL


def _high_enough(sev: Any) -> bool:
    return str(sev or "high").strip().lower() not in _LOW


def parse_file(path: Path) -> list[dict]:
    payload = _as_scuba(_unwrap(_load(path)))
    now = iso_now()
    records: list[dict] = []
    if not isinstance(payload, dict):
        return records
    seen_assets: set[str] = set()

    def add_asset(name: str, desc: str, extra_labels: list[str]) -> None:
        key = name.lower()
        if key in seen_assets:
            return
        seen_assets.add(key)
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{name}"),
                name=name,
                description=desc,
                category="saas-tenant" if "tenant" in desc.lower() or "org" in desc.lower() else "identity",
                assets=[name],
                labels=LABELS + extra_labels,
                collected_at=now,
                extra={"asset_type": "SP"},
            )
        )

    results = payload.get("Results") or payload.get("results")
    if isinstance(results, list):
        for row in results:
            if not isinstance(row, dict):
                continue
            if not _failing(row.get("Result") or row.get("result") or row.get("Status")):
                continue
            sev = row.get("Severity") or row.get("severity") or "high"
            if not _high_enough(sev):
                continue
            tenant = str(row.get("Tenant") or row.get("tenant") or "m365")
            add_asset(tenant, f"M365/Entra tenant {tenant}", ["m365", "scuba"])
            req = str(row.get("Requirement") or row.get("name") or "saas-check")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, req),
                    name=req,
                    description=str(row.get("Details") or req),
                    severity=sev,
                    category="cloud-misconfiguration",
                    assets=[tenant],
                    labels=LABELS + [str(row.get("ProductName") or "aad").lower(), "scuba"],
                    collected_at=now,
                    extra={"product": row.get("ProductName")},
                )
            )
        return records

    maester = (
        payload.get("TestResults")
        or payload.get("tests")
        or payload.get("Tests")
        or payload.get("Maester")
    )
    if isinstance(maester, list):
        tenant = str(
            payload.get("Tenant")
            or payload.get("tenant")
            or payload.get("TenantId")
            or payload.get("tenantId")
            or "contoso.onmicrosoft.com"
        )
        for row in maester:
            if not isinstance(row, dict):
                continue
            result = (
                row.get("Result") or row.get("result") or row.get("Status") or row.get("Outcome")
            )
            if not _failing(result, row.get("Passed")):
                continue
            sev = row.get("Severity") or row.get("severity") or "high"
            if not _high_enough(sev):
                continue
            add_asset(tenant, f"Maester tenant {tenant}", ["maester"])
            name = str(row.get("Name") or row.get("Id") or row.get("id") or row.get("title") or "maester")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{name}-{tenant}"),
                    name=f"Maester {name}",
                    description=str(row.get("Description") or row.get("Details") or name),
                    severity=sev,
                    category="cloud-misconfiguration",
                    assets=[tenant],
                    labels=LABELS + ["maester"],
                    collected_at=now,
                    extra={"result": "failed", "id": row.get("Id") or row.get("id") or name},
                )
            )
        return records

    graph_ctx = str(payload.get("@odata.context") or "")
    roles = None
    if isinstance(payload.get("directoryRoles"), list):
        roles = payload["directoryRoles"]
    elif "directoryRoles" in graph_ctx or (
        "graph.microsoft.com" in graph_ctx and isinstance(payload.get("value"), list)
    ):
        roles = payload.get("value")
    if isinstance(roles, list) and (
        payload.get("directoryRoles") or "graph.microsoft.com" in graph_ctx or payload.get("graph")
    ):
        tenant = str(payload.get("tenant") or "contoso.onmicrosoft.com")
        for role in roles:
            if not isinstance(role, dict):
                continue
            rname = str(role.get("displayName") or role.get("name") or "role")
            members = role.get("members") or role.get("value") or []
            if not isinstance(members, list):
                members = [members]
            if "Global Administrator" not in rname and rname.lower() != "global administrator":
                continue
            for mem in members:
                if mem is None:
                    continue
                upn = (
                    mem
                    if isinstance(mem, str)
                    else str((mem or {}).get("userPrincipalName") or (mem or {}).get("id") or "")
                )
                if not upn:
                    continue
                add_asset(tenant, f"Entra tenant {tenant}", ["graph", "entra"])
                records.append(
                    make_record(
                        kind="finding",
                        source=SOURCE,
                        ref_id=make_ref(SOURCE, f"graph-ga-{upn}"),
                        name="Entra Global Administrator via Graph",
                        description=f"{upn} holds {rname} (Microsoft Graph export)",
                        severity="critical",
                        category="identity-gap",
                        assets=[upn, tenant],
                        labels=LABELS + ["graph"],
                        collected_at=now,
                        extra={"role": rname},
                    )
                )
        return records

    if "users" in payload or "policies" in payload or payload.get("org") or payload.get("okta_org"):
        org = str(payload.get("org") or payload.get("okta_org") or "okta")
        users = payload.get("users") or []
        policies = payload.get("policies") or []
        if not isinstance(users, list):
            users = []
        if not isinstance(policies, list):
            policies = []
        for pol in policies:
            if not isinstance(pol, dict):
                continue
            if str(pol.get("status") or "").upper() != "INACTIVE":
                continue
            if str(pol.get("type") or "") != "MFA_ENROLL" and "MFA" not in str(
                pol.get("name") or ""
            ).upper():
                continue
            add_asset(org, f"Okta org {org}", ["okta"])
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, str(pol.get("name") or "okta-mfa")),
                    name="Okta admin MFA gap",
                    description=str(pol.get("description") or pol.get("name") or "MFA policy inactive"),
                    severity="critical",
                    category="identity-gap",
                    assets=[org],
                    labels=LABELS + ["okta", "mfa"],
                    collected_at=now,
                    extra={"policy": pol.get("id")},
                )
            )
        if any(r.get("kind") == "finding" for r in records):
            for user in users:
                if not isinstance(user, dict):
                    continue
                profile = user.get("profile") if isinstance(user.get("profile"), dict) else {}
                login = str(profile.get("login") or user.get("id") or "user")
                roles = user.get("roles") or []
                records.append(
                    make_record(
                        kind="asset",
                        source=SOURCE,
                        ref_id=make_ref(SOURCE, f"asset-{login}"),
                        name=login,
                        description=f"Okta user {login}",
                        category="identity",
                        assets=[login],
                        labels=LABELS + ["okta"],
                        collected_at=now,
                        extra={"asset_type": "SP", "roles": roles},
                    )
                )
        return records

    return records


def main() -> None:
    run_collector(SOURCE, (".json", ".jsonl"), parse_file)


if __name__ == "__main__":
    main()
