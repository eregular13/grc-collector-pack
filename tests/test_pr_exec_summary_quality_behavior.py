"""Exec summary quality (prior-unit/149): top-5 collapse, area labels. No invented run_id."""
from __future__ import annotations

from shared.estate_pages import (
    EstateStamp,
    NOT_RECORDED,
    PageContext,
    _area_for,
    _exec_top_findings,
    build_executive_summary,
    run_id_from_records,
)


def _f(name, host, *, source="testssl", category="tls", sev="high", ref=None, **extra):
    return {
        "kind": "finding",
        "name": name,
        "severity": sev,
        "category": category,
        "assets": [host],
        "source": source,
        "ref_id": ref or f"{source}-{host}-{name[:12]}",
        "extra": {
            "check_id": extra.get("check_id", f"{source}-self-signed"),
            "tool": source,
            **extra,
        },
        "labels": [source],
    }


def test_top5_collapses_duplicate_cert_weakness_across_hosts():
    findings = [
        _f("Self-signed certificate", f"10.0.0.{10+i}", ref=f"TLS-ss-{i}")
        for i in range(6)
    ] + [
        _f("OpenSSH ancient", "10.0.0.50", source="nmap", category="exposure", sev="critical", ref="N1"),
        _f("SMB exposed", "10.0.0.51", source="nmap", category="exposure", sev="high", ref="N2"),
        _f("Admin panel open", "10.0.0.52", source="nmap", category="exposure", sev="high", ref="N3"),
    ]
    mapped = {
        str(r["ref_id"]): {
            "include_poam": True,
            "framework_refs": "csf_PR",
            "recommended_fix": "fix",
        }
        for r in findings
    }
    top = _exec_top_findings(findings, mapped, 5)
    names = [str(r.get("name") or "") for r in top]
    assert len(top) >= 4 and len(top) <= 5
    assert names.count("Self-signed certificate") == 1, names
    assert len(set(names)) >= 4, names
    cert = next(r for r in top if r.get("name") == "Self-signed certificate")
    assert len([str(a) for a in (cert.get("assets") or [])]) >= 2


def test_run_id_missing_stays_not_recorded(monkeypatch):
    monkeypatch.delenv("GRC_RUN_ID", raising=False)
    monkeypatch.delenv("GRC_OUT_TAG", raising=False)
    monkeypatch.delenv("OUT_DIR", raising=False)
    monkeypatch.delenv("WORK", raising=False)
    monkeypatch.delenv("IN_DIR", raising=False)
    assert run_id_from_records([{"name": "x"}]) == NOT_RECORDED


def test_admin_substring_not_identity_and_testssl_tls_area():
    rec = _f(
        "Nikto: /admin login",
        "10.0.0.9",
        source="vuln-scan",
        category="exposure",
        ref="nikto-admin",
    )
    assert _area_for(rec) != "identity"
    tls = _f("Self-signed certificate", "10.0.0.8", source="testssl", category="tls", ref="tls1")
    area = _area_for(tls)
    assert area != "identity"
    assert "tls" in area.lower() or "certificate" in area.lower() or "ssl" in area.lower()


def test_exec_summary_top5_distinct_with_run_id_when_set(monkeypatch):
    monkeypatch.setenv("GRC_RUN_ID", "lab-prior-unit-synth")
    findings = [
        _f("Self-signed certificate", f"10.0.0.{10+i}", ref=f"TLS-ss-{i}")
        for i in range(6)
    ] + [
        _f("OpenSSH ancient", "10.0.0.50", source="nmap", category="exposure", sev="critical", ref="N1"),
        _f("SMB exposed", "10.0.0.51", source="nmap", category="exposure", ref="N2"),
        _f("Admin panel open", "10.0.0.52", source="nmap", category="exposure", ref="N3"),
    ]
    mapped = {
        str(r["ref_id"]): {
            "include_poam": True,
            "framework_refs": "csf_PR_IR_01",
            "recommended_fix": "Restrict exposure",
        }
        for r in findings
    }
    stamp = EstateStamp(
        kind="LAB",
        label="LAB: TEST ENVIRONMENT",
        sentence="From scans of an Evergreen-controlled test environment.",
        run_id="lab-prior-unit-synth",
        pack_commit="6a82705",
    )
    text = build_executive_summary(
        PageContext(stamp=stamp, records=findings, findings=findings, mapped_by_ref=mapped)
    )
    assert "lab-prior-unit-synth" in text
    section = text.split("Fix these first", 1)[1][:2000]
    rows = [ln for ln in section.splitlines() if ln.startswith("| ") and len(ln) > 3 and ln[2].isdigit()]
    names = [ln.split("|")[2].strip() for ln in rows[:5]]
    assert names.count("Self-signed certificate") <= 1, names
