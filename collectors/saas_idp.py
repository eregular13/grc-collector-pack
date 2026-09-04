#!/usr/bin/env python3
"""Parse ScubaGear / Graph / Okta posture into SaaS findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.io_util import iso_now, read_json, run_collector
from shared.schema import make_record, make_ref

SOURCE = "saas-idp"
LABELS = ["saas", "idp"]


def parse_file(path: Path) -> list[dict]:
    payload = read_json(path)
    now = iso_now()
    records: list[dict] = []
    if not isinstance(payload, dict):
        return records

    results = payload.get("Results") or payload.get("results")
    if isinstance(results, list):
        tenants: set[str] = set()
        for row in results:
            if not isinstance(row, dict):
                continue
            tenant = str(row.get("Tenant") or row.get("tenant") or "m365")
            if tenant not in tenants:
                tenants.add(tenant)
                records.append(
                    make_record(
                        kind="asset",
                        source=SOURCE,
                        ref_id=make_ref(SOURCE, f"asset-{tenant}"),
                        name=tenant,
                        description=f"M365/Entra tenant {tenant}",
                        category="saas-tenant",
                        assets=[tenant],
                        labels=LABELS + ["m365"],
                        collected_at=now,
                        extra={"asset_type": "SP"},
                    )
                )
            result = str(row.get("Result") or row.get("result") or "").lower()
            if result in {"pass", "passed", "true"}:
                continue
            req = str(row.get("Requirement") or row.get("name") or "saas-check")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, req),
                    name=req,
                    description=str(row.get("Details") or req),
                    severity=row.get("Severity") or row.get("severity") or "high",
                    category="cloud-misconfiguration",
                    assets=[tenant],
                    labels=LABELS + [str(row.get("ProductName") or "aad").lower()],
                    collected_at=now,
                    extra={"product": row.get("ProductName")},
                )
            )
        if records:
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
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{tenant}"),
                name=tenant,
                description=f"Maester tenant {tenant}",
                category="saas-tenant",
                assets=[tenant],
                labels=LABELS + ["maester"],
                collected_at=now,
                extra={"asset_type": "SP"},
            )
        )
        for row in maester:
            if not isinstance(row, dict):
                continue
            if row.get("Passed") is True:
                continue
            result = str(
                row.get("Result") or row.get("result") or row.get("Status") or row.get("Outcome") or ""
            ).lower()
            if row.get("Passed") is False:
                result = result or "failed"
            if result in {"pass", "passed", "success", "ok", "skipped", "skip", "notrun", "notapplicable", "n/a"}:
                continue
            if result not in {"fail", "failed", "error", "unsuccessful"}:
                continue
            name = str(row.get("Name") or row.get("Id") or row.get("id") or row.get("title") or "maester")
            records.append(
                make_record(
                    kind="finding",
                    source=SOURCE,
                    ref_id=make_ref(SOURCE, f"{name}-{tenant}"),
                    name=f"Maester {name}",
                    description=str(row.get("Description") or row.get("Details") or name),
                    severity=row.get("Severity") or row.get("severity") or "high",
                    category="cloud-misconfiguration",
                    assets=[tenant],
                    labels=LABELS + ["maester"],
                    collected_at=now,
                    extra={"result": result or "failed", "id": row.get("Id") or row.get("id") or name},
                )
            )
        if any(r.get("kind") == "finding" for r in records):
            return records

    graph_ctx = str(payload.get("@odata.context") or "")
    roles = payload.get("directoryRoles") or payload.get("value") if "directoryRoles" in graph_ctx or payload.get("directoryRoles") else None
    if roles is None and "graph.microsoft.com" in graph_ctx and isinstance(payload.get("value"), list):
        roles = payload.get("value")
    if isinstance(payload.get("directoryRoles"), list):
        roles = payload["directoryRoles"]
    if isinstance(roles, list) and (
        payload.get("directoryRoles") or "graph.microsoft.com" in graph_ctx or payload.get("graph")
    ):
        tenant = str(payload.get("tenant") or "contoso.onmicrosoft.com")
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{tenant}"),
                name=tenant,
                description=f"Entra tenant {tenant}",
                category="saas-tenant",
                assets=[tenant],
                labels=LABELS + ["graph", "entra"],
                collected_at=now,
                extra={"asset_type": "SP"},
            )
        )
        for role in roles:
            if not isinstance(role, dict):
                continue
            rname = str(role.get("displayName") or role.get("name") or "role")
            members = role.get("members") or role.get("value") or []
            if not isinstance(members, list):
                members = [members]
            if "Global Administrator" in rname or rname.lower() == "global administrator":
                for mem in members:
                    if mem is None:
                        continue
                    upn = mem if isinstance(mem, str) else str((mem or {}).get("userPrincipalName") or (mem or {}).get("id") or "")
                    if not upn:
                        continue
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
        if any(r.get("kind") == "finding" for r in records):
            return records

    org = str(payload.get("org") or payload.get("okta_org") or "okta")
    if payload.get("users") or payload.get("policies"):
        records.append(
            make_record(
                kind="asset",
                source=SOURCE,
                ref_id=make_ref(SOURCE, f"asset-{org}"),
                name=org,
                description=f"Okta org {org}",
                category="saas-tenant",
                assets=[org],
                labels=LABELS + ["okta"],
                collected_at=now,
                extra={"asset_type": "SP"},
            )
        )
        for user in payload.get("users") or []:
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
        for pol in payload.get("policies") or []:
            if not isinstance(pol, dict):
                continue
            if str(pol.get("status") or "").upper() != "INACTIVE":
                continue
            if str(pol.get("type") or "") == "MFA_ENROLL" or "MFA" in str(pol.get("name") or "").upper():
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
    return records


def main() -> None:
    run_collector(SOURCE, (".json",), parse_file)


if __name__ == "__main__":
    main()
