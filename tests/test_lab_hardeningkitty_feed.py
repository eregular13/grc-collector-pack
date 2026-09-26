"""LAB HardeningKitty dest_in feed (MS Security Baseline, not CIS).

Synthetic fixture under fixtures/lab-drop/identity/ ingests through the
same drop path as lab nmap + Lynis/oscap. Every row is LAB. LAB never
enters KEEP / keep_real. Failed-only. CIS v8 IDs stay INTERNAL-ONLY.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from collectors import identity_ad
from keep.adapters import (
    client_keep_ready,
    detect_family,
    pack_in_is_lab,
    sample_as_client_reason,
    scan_keep_dir,
)
from keep.lab import keep_lab
from scripts.prove_ciso import prove_ciso
from shared.control_map import map_finding
from shared.drop_manifest import parse_manifest_hashes, write_drop_manifest
from shared.hardening_dedup import dedupe_hardening
from shared.hardening_map import (
    CIS_V8_INTERNAL_FIELD,
    CIS_V8_PREFIX,
    all_cis_v8_internal_tokens,
    extra_control_fields,
    hk_control,
)
from shared.lab_stamp import LAB_LABEL
from tests.test_lab_prove_lock import stage_lab_drop_dest_in

ROOT = Path(__file__).resolve().parents[1]
LAB_DROP = ROOT / "fixtures" / "lab-drop"
IDENTITY = LAB_DROP / "identity"
HK_CSV = IDENTITY / "hardeningkitty-lab-SYNTHETIC.csv"
README = IDENTITY / "README.md"
GITATTRIBUTES = ROOT / ".gitattributes"
RUNNER = ROOT / "lab-estate" / "scan-windows-hardening.ps1"
DEMO_HK = ROOT / "fixtures" / "demo" / "identity" / "hardeningkitty.csv"

# Official HK report: TestResult=Failed, Result=actual. Plus ComputerName.
HK_OFFICIAL_COLS = (
    "ID",
    "Category",
    "Name",
    "Severity",
    "Result",
    "Recommended",
    "TestResult",
    "SeverityFinding",
)

# Real MS baseline IDs from finding_list_msft_security_baseline_windows_11_24h2_machine.csv
EXPECTED_MAP = {
    "10100": ("password_policy", ["IA-5"], "csf_PR", "cpg_2_W"),
    "10101": ("password_policy", ["IA-5"], "csf_PR", "cpg_2_W"),
    "10001": ("account_lockout", ["AC-7"], "csf_PR", "cpg_2_W"),
    "10208": ("session_lock", ["AC-11"], "csf_PR", "cpg_2_W"),
    "10400": ("audit_logging", ["AU-2", "AU-12"], "csf_DE", "cpg_1_E"),
    "10501": ("host_firewall", ["CM-6", "CM-7"], "csf_PR", "cpg_2_W"),
    "10219": ("password_policy", ["IA-5"], "csf_PR", "cpg_2_W"),
    "11014": ("malware_protection", ["SI-3"], "csf_PR", "cpg_2_W"),
    "10964": ("encryption_in_transit", ["SC-8"], "csf_PR", "cpg_2_W"),
}

CLIENT_OUTPUT_GLOBS = (
    "ciso-assistant/*.csv",
    "ciso-assistant/*.md",
    "ciso-assistant/*.txt",
    "ciso-assistant/*.json",
    "poam/*",
    "opengrc/*",
    "probo/*",
    "import_preview/*",
    "simplerisk/*",
)


def test_gitattributes_pins_lab_drop_eol_lf() -> None:
    text = GITATTRIBUTES.read_text(encoding="utf-8")
    assert "fixtures/lab-drop/**" in text
    pinned = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("fixtures/lab-drop/**") and "eol=lf" in stripped:
            pinned = True
    assert pinned
    for path in (HK_CSV, IDENTITY / "LAB.txt", README):
        assert bytes([13]) not in path.read_bytes(), path.name


def test_synthetic_fixture_is_honest_ms_baseline_not_seen() -> None:
    assert (IDENTITY / "LAB.txt").is_file()
    assert HK_CSV.is_file()
    assert README.is_file()
    banner = (IDENTITY / "LAB.txt").read_text(encoding="utf-8")
    note = README.read_text(encoding="utf-8") + HK_CSV.read_text(encoding="utf-8")
    assert "LAB/DEMO" in banner
    assert "not a client" in banner.lower()
    assert "SYNTHETIC" in HK_CSV.name
    assert "not an observed" in note.lower()
    assert "schema fixture" in note.lower()
    assert "not" in note.lower() and "seen" in note.lower()
    assert "finding_list_msft_security_baseline" in note
    assert "not a CIS" in note.lower() or "never cis" in note.lower()
    assert "finding_list_cis_" not in HK_CSV.read_text(encoding="utf-8").split("ID,", 1)[-1]
    head = next(
        ln for ln in HK_CSV.read_text(encoding="utf-8").splitlines() if ln.startswith("ID,")
    )
    for col in HK_OFFICIAL_COLS:
        assert col in head.split(",")[0] or col in head


def test_hk_failed_only_and_lab_labeled() -> None:
    recs = identity_ad.parse_file(HK_CSV)
    findings = [r for r in recs if r["kind"] == "finding"]
    assets = [r for r in recs if r["kind"] == "asset"]
    assert assets and assets[0]["name"] == "lab-win.lab.internal"
    ids = {str(r["extra"].get("check_id") or r["extra"].get("id")) for r in findings}
    assert "10100" in ids
    assert "10501" in ids
    assert "10219" in ids
    assert "10102" not in ids  # Passed complexity stays silent
    assert len(findings) == len(EXPECTED_MAP)
    for rec in recs:
        assert LAB_LABEL in (rec.get("labels") or [])
        assert "SAMPLE" not in (rec.get("labels") or [])
        assert rec["extra"].get("lab") is True
        assert "cis-cat" not in (rec.get("labels") or [])
        assert "CIS Benchmark" not in rec["name"]
        assert "CIS-CAT" not in rec["name"]
        names = " ".join(str(x) for x in rec.get("labels") or [])
        assert "CIS-CAT" not in names
    blob = str(recs)
    assert " actual=5" not in blob
    assert "[REDACTED]" in blob
    hist = next(r for r in findings if r["extra"].get("check_id") == "10100")
    assert hist["extra"].get("category") == "Account Policies"
    assert hist["extra"].get("recommended") == "24"
    assert hist["extra"].get("result") == "failed"
    assert hist["extra"].get("tool") == "hardeningkitty"
    assert hist["extra"].get("baseline") == "msft_security_baseline"


def test_demo_hk_is_not_lab_labeled() -> None:
    recs = identity_ad.parse_file(DEMO_HK)
    findings = [r for r in recs if r["kind"] == "finding"]
    assert any("password history" in r["name"] for r in findings)
    assert not any("Guest account" in r["name"] for r in findings)
    for rec in recs:
        assert LAB_LABEL not in (rec.get("labels") or [])


def test_hk_control_map_and_800_53() -> None:
    for hid, (key, n53, csf, cpg) in EXPECTED_MAP.items():
        assert hk_control(hid) == key, hid
        extra = extra_control_fields(key, include_cis_internal=True)
        assert extra["control_key"] == key
        assert extra["csf"] == csf
        assert extra["cpg"] == cpg
        assert extra["nist_800_53"] == n53
        assert extra[CIS_V8_INTERNAL_FIELD]
        assert all(str(t).startswith(CIS_V8_PREFIX) for t in extra[CIS_V8_INTERNAL_FIELD])
    lynis_extra = extra_control_fields("host_firewall")
    assert CIS_V8_INTERNAL_FIELD not in lynis_extra


def test_hk_same_tool_keeps_distinct_checks() -> None:
    merged = dedupe_hardening(identity_ad.parse_file(HK_CSV))
    findings = [r for r in merged if r["kind"] == "finding"]
    keys = [r["extra"].get("control_key") for r in findings]
    assert keys.count("host_firewall") == 1
    assert keys.count("password_policy") == 3  # history, minlen, LM hash
    assert keys.count("account_lockout") == 1


def test_hk_lynis_dedupe_cross_tool_same_host() -> None:
    hk = identity_ad.parse_file(HK_CSV)
    twin = {
        "kind": "finding",
        "source": "host-wazuh",
        "name": "Lynis FIRE-4590: No firewall software installed",
        "assets": ["lab-win.lab.internal"],
        "labels": ["lynis"],
        "extra": {"control_key": "host_firewall", "check_id": "FIRE-4590", "tool": "lynis"},
    }
    merged = dedupe_hardening(hk + [twin])
    findings = [r for r in merged if r["kind"] == "finding"]
    keys = [r["extra"].get("control_key") for r in findings]
    assert keys.count("host_firewall") == 1
    fw = next(r for r in findings if r["extra"].get("control_key") == "host_firewall")
    assert set(fw["extra"].get("sources") or []) >= {"hardeningkitty", "lynis"}


def test_lab_hk_ingest_e2e_and_cis_stays_internal(tmp_path: Path) -> None:
    dest = tmp_path / "prove"
    dest_in = dest / "in"
    stage_lab_drop_dest_in(dest_in)
    assert (dest_in / "identity" / HK_CSV.name).is_file()
    stamp = prove_ciso(root=ROOT, dest=dest, use_existing_in=True)
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["lab"] is True
    assert stamp["sample"] is False
    assert stamp["client"] is False
    assert stamp["client_keep"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    out = Path(stamp["out_dir"])
    findings_csv = (out / "ciso-assistant" / "findings.csv").read_text(encoding="utf-8")
    assert "HardeningKitty" in findings_csv
    assert "10100" in findings_csv or "password history" in findings_csv.lower()
    assert "CIS-CAT" not in findings_csv
    assert "CIS Benchmark" not in findings_csv
    assert CIS_V8_PREFIX not in findings_csv
    canonical = (out / "canonical" / "identity-ad.jsonl").read_text(encoding="utf-8")
    assert '"LAB"' in canonical or ", \"LAB\"" in canonical
    assert "lab-win.lab.internal" in canonical
    assert CIS_V8_INTERNAL_FIELD in canonical
    hidden = all_cis_v8_internal_tokens()
    assert hidden
    client_blob = []
    for pattern in CLIENT_OUTPUT_GLOBS:
        for path in out.glob(pattern):
            if path.is_file():
                client_blob.append(path.read_text(encoding="utf-8", errors="replace"))
    joined = "\n".join(client_blob)
    assert joined
    for tok in hidden:
        assert tok not in joined, tok
    assert CIS_V8_PREFIX not in joined
    assert "CIS Controls v8" not in joined
    poam = (out / "poam" / "poam.csv").read_text(encoding="utf-8")
    assert "IA-5" in poam or "nist80053_IA-5" in findings_csv or "IA-5" in findings_csv
    mapped = map_finding(next(
        r for r in identity_ad.parse_file(HK_CSV) if r["kind"] == "finding" and r["extra"].get("check_id") == "10100"
    ))
    assert mapped["nist_800_53"] == ["IA-5"]
    assert mapped.get("cis") == []
    assert CIS_V8_PREFIX not in mapped["framework_refs"]
    assert CIS_V8_INTERNAL_FIELD not in mapped["framework_refs"]


def test_lab_hk_cannot_enter_keep_path(tmp_path: Path) -> None:
    assert detect_family(HK_CSV) is None
    assert pack_in_is_lab(LAB_DROP) is True
    rows = scan_keep_dir(LAB_DROP)
    assert not any(r.get("family") == "hardeningkitty" for r in rows)
    assert client_keep_ready(rows) is False
    reason = sample_as_client_reason(
        [{"lab": True, "path": str(HK_CSV)}],
        sample=False,
        client_keep=True,
    )
    assert reason and "LAB" in reason
    stamp = keep_lab(ROOT, pack_in=LAB_DROP, work=tmp_path / "keep-work")
    assert stamp["client_keep"] is False
    assert stamp["sample"] is True
    assert stamp["origin"] == "keep-samples"
    assert stamp["paying_day"] == "FAIL"
    assert stamp.get("keep_real") in (None, 0, "0/4") or stamp["origin"] == "keep-samples"


def test_identity_manifest_sha256_matches(tmp_path: Path) -> None:
    dest = tmp_path / "identity"
    dest.mkdir()
    for src in (HK_CSV, IDENTITY / "LAB.txt", README):
        (dest / src.name).write_bytes(src.read_bytes())
    write_drop_manifest(
        dest,
        header="LAB dest_in identity drop — test\nLAB != SAMPLE != client.",
        relative_to=dest,
    )
    text = (dest / "MANIFEST").read_text(encoding="utf-8")
    hashes = parse_manifest_hashes(text)
    assert hashes
    for name, digest in hashes.items():
        got = hashlib.sha256((dest / name).read_bytes()).hexdigest()
        assert got == digest
    checked = IDENTITY / "MANIFEST"
    assert checked.is_file()
    pinned = parse_manifest_hashes(checked.read_text(encoding="utf-8"))
    for rel, digest in pinned.items():
        path = IDENTITY / rel
        assert path.is_file(), rel
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest


def test_windows_runner_is_lab_ms_baseline_not_cis() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "LAB-only" in text
    assert "Authorized-lab-only" in text or "AuthorizedLab" in text
    assert "finding_list_msft_security_baseline" in text
    assert "finding_list_cis_*" in text
    assert "Refusing CIS-benchmark" in text or "Never finding_list_cis" in text
    assert "Does NOT start Docker" in text or "Does not start Docker" in text
    assert "Invoke-HardeningKitty" in text
    assert "-Mode Audit" in text
    assert "POST /api/risks" in text
    assert "scipag/HardeningKitty" in text
    assert "CIS-CAT" in text
    assert "CIS Benchmark" in text
