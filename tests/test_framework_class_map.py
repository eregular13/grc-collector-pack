"""CSF 2.0 subcategory + CISA CPG 2.0 per weakness class.

Official IDs only. No csf_PR catch-all. poam.csv and poam_fedramp.csv
carry the same CSF/CPG tags per EGP- ID.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from shared.control_map import map_finding
from shared.framework_class_map import (
    CPG20_GOALS,
    CSF20_FUNCTION_OF,
    CSF20_SUBCATEGORIES,
    UNMAPPED,
    WEAKNESS_CLASS_MAP,
    apply_class_mapping,
    classify_weakness_class,
    cpg_stamp,
    csf_cpg_tag_set,
    csf_stamp,
    resolve_class_tags,
)
from shared.schema import make_record


def _finding(**kwargs):
    return make_record(
        kind="finding",
        source=kwargs.pop("source", "inventory-nmap"),
        ref_id=kwargs.pop("ref", "X-1"),
        name=kwargs.pop("name", "finding"),
        description=kwargs.pop("description", "desc"),
        severity=kwargs.pop("severity", "high"),
        category=kwargs.pop("category", "exposure"),
        assets=kwargs.pop("assets", ["host-a"]),
        extra=kwargs.pop("extra", {}),
        **kwargs,
    )


def test_every_mapped_csf_id_is_official_csf20() -> None:
    for cls, row in WEAKNESS_CLASS_MAP.items():
        if cls == UNMAPPED:
            assert row["by_function"] == {}
            continue
        for fn, sid in (row.get("by_function") or {}).items():
            assert sid in CSF20_SUBCATEGORIES, (cls, sid)
            assert CSF20_FUNCTION_OF[sid] == fn, (cls, sid, fn)


def test_every_mapped_cpg_id_is_official_cpg20() -> None:
    for cls, row in WEAKNESS_CLASS_MAP.items():
        cid = row["cpg"]
        if cid == UNMAPPED:
            continue
        assert cid in CPG20_GOALS, (cls, cid)
        assert row["source_note"], cls


def test_unmapped_never_emits_csf_pr() -> None:
    tags = resolve_class_tags(UNMAPPED, "identify")
    assert tags["csf_stamp"] == "csf_unmapped"
    assert tags["cpg_stamp"] == "cpg_unmapped"
    assert "csf_PR" not in tags["csf_stamp"]
    rec = _finding(
        ref="UNK-1",
        name="Obscure widget misaligned",
        description="A one-off finding with no control family.",
        category="other",
    )
    mapped = map_finding(rec)
    assert mapped["csf_subcategory"] == UNMAPPED
    refs = mapped["framework_refs"]
    assert "csf_unmapped" in refs
    assert "cpg_unmapped" in refs
    assert "csf_PR" not in refs.split(",")
    assert "csf_protect" not in refs


def test_subcategory_sits_under_stamped_function() -> None:
    tls = map_finding(
        _finding(
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            extra={"port": "443", "service": "https"},
        )
    )
    assert tls["csf_function"] == "protect"
    assert tls["csf_subcategory"] == "PR.DS-02"
    assert CSF20_FUNCTION_OF[tls["csf_subcategory"]] == tls["csf_function"]
    assert "csf_PR_DS_02" in tls["framework_refs"]
    assert "cpg_3_K" in tls["framework_refs"]

    smb = map_finding(
        _finding(
            name="SMB 445 exposed",
            description="filesrv has open TCP/445 (microsoft-ds).",
            extra={"port": "445", "service": "microsoft-ds"},
        )
    )
    assert smb["csf_function"] == "protect"
    assert smb["csf_subcategory"] == "PR.IR-01"
    assert "csf_PR" not in smb["framework_refs"].split(",")
    assert "cpg_3_S" in smb["cpg"]

    honeypot = map_finding(
        _finding(
            name="Deception-sensor stage-2 hit",
            description="deception-sensor evidence / an agent-behavior signal.",
            category="deception-sensor",
            source="honeypot",
            extra={"honesty": "deception-sensor", "stage": 2},
        )
    )
    assert honeypot["csf_function"] == "detect"
    assert honeypot["csf_subcategory"] == "DE.CM-01"
    assert CSF20_FUNCTION_OF[honeypot["csf_subcategory"]] == "detect"

    perimeter = map_finding(
        _finding(
            name="Sensitive external hostname on the public perimeter",
            description="vpn.example.com is published on the public perimeter.",
            source="easm",
        )
    )
    assert perimeter["csf_function"] == "identify"
    assert perimeter["csf_subcategory"] == "ID.AM-01"
    assert "cpg_2_A" in perimeter["cpg"]


def test_vuln_reconciles_id_ra_or_pr_ps() -> None:
    log4j = map_finding(
        _finding(
            ref="VULN-log4j",
            name="Apache Log4j RCE",
            description="Log4Shell JNDI lookup CVE-2021-44228",
            category="vulnerability",
            source="vuln-scan",
            extra={"cve": "CVE-2021-44228"},
        )
    )
    assert log4j["weakness_class"] == "vuln_patch"
    assert log4j["csf_function"] in {"identify", "protect"}
    assert log4j["csf_subcategory"] in {"ID.RA-01", "PR.PS-02"}
    assert CSF20_FUNCTION_OF[log4j["csf_subcategory"]] == log4j["csf_function"]
    assert "cpg_2_B" in log4j["cpg"]


def test_identity_and_config_classes() -> None:
    mfa = map_finding(
        _finding(
            name="Root account has no MFA",
            description="Root user has no MFA device.",
            extra={"check_id": "iam_root_mfa_enabled"},
        )
    )
    assert mfa["csf_subcategory"] == "PR.AA-03"
    assert "cpg_3_F" in mfa["cpg"]
    dcsync = map_finding(
        _finding(
            name="BloodHound DCSync",
            description="SVC-SQL@CORP.LOCAL|CORP.LOCAL DCSync",
            source="identity-ad",
            extra={"edge": "DCSync"},
        )
    )
    assert dcsync["csf_subcategory"] == "PR.AA-05"
    assert "cpg_3_H" in dcsync["cpg"]
    patch = map_finding(
        _finding(
            name="Install outstanding security patches",
            description="security patch missing",
            category="hardening",
            source="host-wazuh",
            extra={"control_key": "patching"},
        )
    )
    assert patch["weakness_class"] == "vuln_patch"
    assert patch["csf_subcategory"] in {"ID.RA-01", "PR.PS-02"}


def test_wizard_safe_stamps_have_no_colon() -> None:
    assert ":" not in csf_stamp("PR.IR-01")
    assert csf_stamp("PR.IR-01") == "csf_PR_IR_01"
    assert cpg_stamp("3.S") == "cpg_3_S"
    assert ":" not in cpg_stamp("2.B")


def test_loader_poam_and_fedramp_tags_match_per_egp(
    tmp_path: Path, monkeypatch
) -> None:
    from collectors.grc_loader import load
    from shared.io_util import out_dir, write_canonical

    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    (tmp_path / "in").mkdir()
    recs = [
        _finding(
            ref="NMAP-smb",
            name="SMB 445 exposed",
            description="filesrv has open TCP/445 (microsoft-ds).",
            extra={"port": "445", "service": "microsoft-ds"},
        ),
        _finding(
            ref="NMAP-tls",
            name="TLS expired on vpn.example.com",
            description="https listener presents an expired certificate.",
            extra={"port": "443", "service": "https"},
        ),
        _finding(
            ref="ID-mfa",
            name="Root account has no MFA",
            description="Root user has no MFA device.",
            extra={"check_id": "iam_root_mfa_enabled"},
        ),
        _finding(
            ref="VULN-xz",
            name="xz-utils supply chain backdoor",
            description="Malicious code in xz-utils liblzma CVE-2024-3094",
            category="vulnerability",
            source="vuln-scan",
            extra={"cve": "CVE-2024-3094", "pkg": "xz-utils"},
        ),
        _finding(
            ref="WAZ-time",
            name="chrony is not enabled",
            description="Enable chrony so audit timestamps stay trustworthy.",
            category="hardening",
            source="host-wazuh",
            extra={"control_key": "time_sync"},
        ),
    ]
    write_canonical("inventory-nmap", recs)
    load()
    poam_path = out_dir() / "poam" / "poam.csv"
    fed_path = out_dir() / "poam" / "poam_fedramp.csv"
    ledger = json.loads((out_dir() / "poam" / "poam-ledger.json").read_text(encoding="utf-8"))
    with poam_path.open(encoding="utf-8", newline="") as fh:
        poam = list(csv.DictReader(fh))
    with fed_path.open(encoding="utf-8", newline="") as fh:
        fed = list(csv.DictReader(fh))
    assert "Framework Tags" in (fed[0] if fed else {})
    by_ref_item = {
        str(item.get("ref_id") or ""): item for item in (ledger.get("items") or {}).values()
    }
    poam_by_ref = {r.get("finding_ref_id") or "": r for r in poam}
    fed_by_id = {r.get("POAM ID") or "": r for r in fed}
    matched = 0
    for ref, prow in poam_by_ref.items():
        item = by_ref_item.get(ref)
        if not item:
            continue
        egp = str(item.get("poam_id") or "")
        assert egp.startswith("EGP-")
        frow = fed_by_id[egp]
        assert csf_cpg_tag_set(prow.get("framework_refs") or "") == csf_cpg_tag_set(
            frow.get("Framework Tags") or ""
        )
        matched += 1
    assert matched >= 4
    csf_counts: Counter[str] = Counter()
    cpg_goals: set[str] = set()
    for row in poam:
        csf, cpg = csf_cpg_tag_set(row.get("framework_refs") or "")
        csf_counts.update(csf)
        cpg_goals.update(t for t in cpg if t != "cpg_unmapped")
    n = len(poam)
    assert n >= 4
    top = max(csf_counts.values()) / n
    assert top <= 0.40, csf_counts
    assert len(cpg_goals) >= 5, cpg_goals


def test_classify_unknown_is_unmapped() -> None:
    mapped = {"control_name": "Review and remediate per control widget", "finding_type": ""}
    assert classify_weakness_class(mapped, {}) == UNMAPPED
    tagged = apply_class_mapping(
        {
            "control_name": "Review and remediate per control widget",
            "csf_function": "identify",
            "csf": ["csf_ID", "csf_identify", "csf_unmapped"],
            "nist_800_53": [],
            "cis": [],
        }
    )
    assert tagged["csf_subcategory"] == UNMAPPED
    assert "csf_PR" not in tagged["framework_refs"]
