"""Freedom45 control_map heuristics folded into framework_class_map."""

from __future__ import annotations

import pytest

from shared.control_map import map_finding
from shared.framework_class_map import (
    CIS_V8_PREFIX,
    ENV_EVAL_HEURISTICS,
    ENV_EVAL_SENSOR_RULES,
    UNMAPPED,
    cis_v8_internal_ids,
    classify_weakness_class,
    nist_800_53_ids,
    normalize_csf20_id,
)
from shared.schema import make_record
from shared.web_tls import parse_file
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "samples" / "web_tls"


def test_normalize_csf11_to_csf20() -> None:
    assert normalize_csf20_id("PR.AC-5") == "PR.IR-01"
    assert normalize_csf20_id("PR.AC-05") == "PR.IR-01"
    assert normalize_csf20_id("NIST.CSF.PR.PT-03") == "PR.PS-01"
    assert normalize_csf20_id("PR.IP-1") == "PR.PS-01"
    assert normalize_csf20_id("PR.DS-2") == "PR.DS-02"
    assert normalize_csf20_id("ID.AM-1") == "ID.AM-01"
    assert normalize_csf20_id("PR.DS-02") == "PR.DS-02"
    assert normalize_csf20_id("csf_PR_DS_02") == "PR.DS-02"
    assert normalize_csf20_id("not-a-control") == UNMAPPED


def test_sensor_map_covers_core_env_eval_sensors() -> None:
    needed = [
        "sense-surface",
        "sense-http-headers",
        "sense-cleartext-http",
        "sense-ssh-banner",
        "sense-tls",
        "sense-tls-expiry",
        "sense-cookie-flags",
        "sense-cors",
        "sense-service-exposure",
        "sense-git-exposed",
        "sense-dir-listing",
        "sense-http-methods",
        "sense-tech-disclosure",
        "sense-default-page",
        "sense-http-https-redirect",
    ]
    for sensor in needed:
        assert sensor in ENV_EVAL_SENSOR_RULES
        ids = nist_800_53_ids(sensor=sensor)
        assert len(ids) >= 1
        assert "UNMAPPED" not in ids
        cis = cis_v8_internal_ids(sensor=sensor)
        assert cis
        assert all(t.startswith(CIS_V8_PREFIX) for t in cis)


def test_heuristics_smb_s3_rdp_weak_tls() -> None:
    assert nist_800_53_ids(title="SMBv1 enabled") == ["CM-7"]
    assert nist_800_53_ids(title="S3 bucket public access") == ["AC-3"]
    assert nist_800_53_ids(title="RDP 3389 exposed") == ["AC-17"]
    assert "SC-8" in nist_800_53_ids(title="weak cipher TLSv1.0")
    assert nist_800_53_ids(title="WordPress site") == []
    assert nist_800_53_ids(title="Apache 2.4.23") == []
    assert nist_800_53_ids(title="Build 19200") == []
    assert len(ENV_EVAL_HEURISTICS) >= 8


def test_heuristics_smtp_open_relay_and_world_writable() -> None:
    """nmap smtp-open-relay / Lynis world-writable; 777 is word-bounded."""
    nmap_relay = "Host is an open relay (smtp-open-relay NSE)"
    assert nist_800_53_ids(title=nmap_relay) == ["SC-7", "CM-7"]
    assert nist_800_53_ids(title="SMTP capture / open mail relay") == ["SC-7", "CM-7"]
    assert nist_800_53_ids(title="SMTP banner on port 25") == []
    assert nist_800_53_ids(title="captured packet on 25/tcp") == []
    assert nist_800_53_ids(title="not an open relay") == []
    assert nist_800_53_ids(title="relay access denied") == []
    assert nist_800_53_ids(title="check: closed") == []

    lynis = "World-writable file /etc/cron.d/backup (mode 0777)"
    assert nist_800_53_ids(title=lynis) == ["AC-6", "CM-6"]
    assert nist_800_53_ids(title="File permissions too open") == ["AC-6", "CM-6"]
    assert nist_800_53_ids(title="mode 0777") == ["AC-6", "CM-6"]
    assert nist_800_53_ids(title="chmod 0777 /tmp/x") == ["AC-6", "CM-6"]
    assert nist_800_53_ids(title="octal 777") == ["AC-6", "CM-6"]
    assert nist_800_53_ids(title="Plugin 17770") == []
    assert nist_800_53_ids(title="Port 17770/tcp open") == []
    assert nist_800_53_ids(title="Build 27770") == []
    assert nist_800_53_ids(title="10.0.777.1") == []
    assert nist_800_53_ids(title="1.7.777") == []
    assert nist_800_53_ids(title="SN-777-0042") == []
    assert nist_800_53_ids(title="CVE-2017-0777") == []
    assert nist_800_53_ids(title="error code 777") == []
    from shared.framework_class_map import CSF20_SUBCATEGORIES, _lookup_env_eval_rule

    smtp = _lookup_env_eval_rule(title=nmap_relay)
    perms = _lookup_env_eval_rule(title=lynis)
    assert smtp and smtp["csf20"] in CSF20_SUBCATEGORIES
    assert perms and perms["csf20"] in CSF20_SUBCATEGORIES


def test_cis_v8_never_on_client_framework_refs() -> None:
    recs = parse_file(SAMPLES / "probe-cleartext-http.json")
    git = next(r for r in recs if r["extra"]["sensor"] == "sense-git-exposed")
    mapped = map_finding(git)
    refs = str(mapped.get("framework_refs") or "")
    assert CIS_V8_PREFIX not in refs
    assert "cis_v8_internal" not in refs
    assert git["extra"]["cis_v8_internal"]
    assert all(t.startswith(CIS_V8_PREFIX) for t in git["extra"]["cis_v8_internal"])
    assert mapped["csf_subcategory"] != UNMAPPED
    assert mapped.get("cpg_id")
    assert "cpg_" in refs


def test_heuristics_do_not_remap_demo_nmap_titles() -> None:
    rec = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-smb",
        name="SMB 445 exposed",
        description="filesrv has open TCP/445 (microsoft-ds).",
        severity="high",
        extra={"port": "445", "service": "microsoft-ds"},
    )
    mapped = map_finding(rec)
    assert classify_weakness_class(mapped, rec) == "exposure_network"
    # Heuristic RDP must not fire on a DEMO-shaped nmap title without sense-.
    rdp = make_record(
        kind="finding",
        source="inventory-nmap",
        ref_id="NMAP-rdp",
        name="RDP 3389 exposed",
        description="legacy-corp has open TCP/3389.",
        severity="high",
        extra={"port": "3389", "service": "ms-wbt-server"},
    )
    mapped_rdp = map_finding(rdp)
    assert classify_weakness_class(mapped_rdp, rdp) == "exposure_network"


def test_one_map_helper_is_the_800_53_source() -> None:
    git = nist_800_53_ids(sensor="sense-git-exposed")
    assert git == ["CM-7", "AC-3", "SI-12"]
    assert nist_800_53_ids(finding_type="web_cors") == ["AC-3", "SC-7"]
    assert nist_800_53_ids(sensor="sense-unknown-xyz") == []
    # Same map as classify: sensor wins over title.
    assert (
        classify_weakness_class(
            {"finding_type": "web_sensitive_file"},
            {"source": "web-tls", "extra": {"sensor": "sense-git-exposed"}},
        )
        == ENV_EVAL_SENSOR_RULES["sense-git-exposed"]["weakness_class"]
    )


def test_helper_matches_poam_controls_for_web_tls_sensors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Helper must follow TYPE_REMEDIATIONS (POA&M), not the sensor map.

    Comparing only to ``nist_800_53_ids(sensor=)`` / ENV_EVAL_SENSOR_RULES
    is a no-op once those tables were realigned. This test looks up
    TYPE_REMEDIATIONS independently and then patches one entry so a helper
    that skips the POA&M path fails.
    """
    from shared.finding_types import TYPE_REMEDIATIONS, finding_type, type_remediation

    recs = parse_file(SAMPLES / "probe-cleartext-http.json")
    recs += parse_file(SAMPLES / "probe-https-weak.json")
    seen: set[str] = set()
    sentinel_rec = None
    for rec in recs:
        sensor = str((rec.get("extra") or {}).get("sensor") or "")
        if not sensor or sensor in seen:
            continue
        seen.add(sensor)
        ftype = finding_type(rec)
        assert ftype, sensor
        typed = type_remediation(rec)
        assert typed is not None
        independent = list(TYPE_REMEDIATIONS[ftype].get("nist_800_53") or [])
        assert independent == list(typed.get("nist_800_53") or [])
        assert nist_800_53_ids(rec) == independent
        if sentinel_rec is None and independent:
            sentinel_rec = rec
    assert sentinel_rec is not None
    ftype = finding_type(sentinel_rec)
    patched = dict(TYPE_REMEDIATIONS[ftype])
    patched["nist_800_53"] = ["XX-99-SENTINEL"]
    monkeypatch.setitem(TYPE_REMEDIATIONS, ftype, patched)
    assert nist_800_53_ids(sentinel_rec) == ["XX-99-SENTINEL"]


def test_env_eval_csf_ids_are_official_csf20() -> None:
    from shared.framework_class_map import CSF20_SUBCATEGORIES

    for sensor, rule in ENV_EVAL_SENSOR_RULES.items():
        sid = normalize_csf20_id(str(rule["csf20"]))
        assert sid in CSF20_SUBCATEGORIES, (sensor, rule["csf20"], sid)
        assert sid == rule["csf20"]
