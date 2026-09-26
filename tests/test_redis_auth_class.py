"""Redis-without-auth must get the Redis auth class, not SI-2/RA-5 vuln_patch.

cold-review-4 R2-4: nuclei exposed-redis / redis_noauth is an auth gap
(requirepass or ACL -@dangerous), not a generic upgrade playbook.
Reuses MISCONFIG_RULES nse-redis-noauth — not a second playbook.
"""

from __future__ import annotations

import json
from pathlib import Path

from collectors import vuln_scan
from shared.control_map import map_finding
from shared.finding_types import finding_type
from shared.framework_class_map import classify_weakness_class
from shared.poam_fields import poam_fields
from shared.poam_ledger import weakness_key
from shared.schema import make_record

ROOT = Path(__file__).resolve().parents[1]
DEMO_NUCLEI = ROOT / "fixtures" / "demo" / "vuln" / "nuclei-multi-host.jsonl"

REDIS_CONTROL = "Require authentication on Redis"
REDIS_N53 = {"IA-2", "AC-3", "CM-6", "CM-7", "SC-7"}
VULN_PATCH_N53 = {"SI-2", "RA-5"}
FIX_TOKS = ("requirepass", "-@dangerous", "protected-mode")


def _nuclei_rec(**extra_over) -> dict:
    extra = {"template_id": "exposed-redis", "rule": "exposed-redis", "cve": ""}
    extra.update(extra_over)
    return make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-exposed-redis-redis-a",
        name="Redis without auth",
        description="Unauthenticated Redis on a LAB host.",
        severity="high",
        category="vulnerability",
        assets=["https://redis-a.lab.internal"],
        labels=["nuclei"],
        extra=extra,
    )


def _assert_redis_auth_class(rec: dict) -> dict:
    mapped = map_finding(rec)
    n53 = set(mapped.get("nist_800_53") or [])
    fix = str(mapped.get("recommended_fix") or "").lower()
    assert mapped.get("control_name") == REDIS_CONTROL, mapped.get("control_name")
    assert REDIS_N53 <= n53, n53
    assert not (VULN_PATCH_N53 & n53), n53
    assert mapped.get("finding_type") == "nse-redis-noauth"
    assert classify_weakness_class(mapped, rec) == "exposure_access"
    assert mapped.get("csf_subcategory") == "PR.AA-05"
    refs = str(mapped.get("framework_refs") or "")
    assert "csf_PR_AA_05" in refs
    assert "cpg_3_I" in refs or "cpg_3_S" in refs
    assert "csf_PR_PS_02" not in refs
    assert "nist80053_SI-2" not in refs
    assert "nist80053_RA-5" not in refs
    for tok in FIX_TOKS:
        assert tok.lower() in fix, (tok, mapped.get("recommended_fix"))
    assert "upgrade" not in fix or "requirepass" in fix
    assert "apply vulnerability remediation" not in str(mapped.get("control_name") or "").lower()
    fields = poam_fields(rec, mapped, None)
    controls = {c.strip() for c in str(fields.get("controls") or "").split(",") if c.strip()}
    assert REDIS_N53 <= controls, controls
    assert not (VULN_PATCH_N53 & controls), controls
    return mapped


def test_synthetic_nuclei_exposed_redis_fires_auth_class() -> None:
    _assert_redis_auth_class(_nuclei_rec())


def test_check_id_cve_does_not_shadow_template_id() -> None:
    rec = _nuclei_rec(check_id="CVE-2021-32761", id="32761")
    _assert_redis_auth_class(rec)


def test_redis_noauth_rule_alias() -> None:
    rec = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-redis-noauth",
        name="redis_noauth",
        description="Redis accepts unauthenticated clients.",
        severity="high",
        category="vulnerability",
        assets=["10.0.0.41"],
        extra={"rule": "redis_noauth"},
    )
    assert finding_type(rec) == "nse-redis-noauth"
    _assert_redis_auth_class(rec)


def test_extra_id_only_exposed_redis() -> None:
    rec = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-id-only",
        name="exposed-redis",
        description="Redis INFO without authentication.",
        severity="high",
        category="vulnerability",
        assets=["10.0.0.41"],
        extra={"id": "exposed-redis"},
    )
    _assert_redis_auth_class(rec)


def test_demo_nuclei_multi_host_three_rows() -> None:
    recs = [r for r in vuln_scan.parse_file(DEMO_NUCLEI) if r.get("kind") == "finding"]
    assert len(recs) == 3
    keys = [weakness_key(r) for r in recs]
    assert len(set(keys)) == 1
    assert keys[0] == "nuclei:exposed-redis"
    hosts = {str((r.get("assets") or [""])[0]) for r in recs}
    assert hosts == {
        "https://redis-a.lab.internal",
        "https://redis-b.lab.internal",
        "https://redis-c.lab.internal",
    }
    for rec in recs:
        _assert_redis_auth_class(rec)


def test_real_redis_cve_stays_vuln_patch() -> None:
    rec = make_record(
        kind="finding",
        source="vuln-scan",
        ref_id="VULN-cve-2022-0543",
        name="CVE-2022-0543 Redis Lua sandbox escape",
        description="Lua sandbox escape in Redis.",
        severity="critical",
        category="vulnerability",
        assets=["app-server:latest"],
        extra={"cve": "CVE-2022-0543", "template_id": "CVE-2022-0543"},
    )
    mapped = map_finding(rec)
    n53 = set(mapped.get("nist_800_53") or [])
    assert VULN_PATCH_N53 <= n53
    assert mapped.get("control_name") != REDIS_CONTROL
    assert classify_weakness_class(mapped, rec) == "vuln_patch"


def test_nuclei_json_wrapper_maps_redis_auth(tmp_path: Path) -> None:
    dest = tmp_path / "scan.json"
    dest.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "template_id": "exposed-redis",
                        "info": {
                            "name": "Redis without auth",
                            "severity": "high",
                            "description": "Unauthenticated Redis",
                        },
                        "host": "10.0.0.40",
                        "matched_at": "10.0.0.40:6379",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    findings = [r for r in vuln_scan.parse_file(dest) if r["kind"] == "finding"]
    assert len(findings) == 1
    _assert_redis_auth_class(findings[0])
