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
from shared.io_util import load_sensor_coverage, run_collector
from shared.hardening_map import (
    CIS_V8_INTERNAL_FIELD,
    CIS_V8_PREFIX,
    all_cis_v8_internal_tokens,
    extra_control_fields,
    hk_control,
)
from shared.hardeningkitty_csv import (
    HK_AUDIT_COLUMNS,
    HK_AUDIT_HEADER,
    WINDOWS_HOST_DEFAULT,
    hk_host_from_filename,
    hk_row_failed,
)
from shared.lab_stamp import LAB_LABEL
from tests.test_lab_prove_lock import stage_lab_drop_dest_in

ROOT = Path(__file__).resolve().parents[1]
LAB_DROP = ROOT / "fixtures" / "lab-drop"
IDENTITY = LAB_DROP / "identity"
HK_CSV_A = IDENTITY / "hardeningkitty-lab-win.lab.internal-20260926T000000Z-SYNTHETIC.csv"
HK_CSV_B = IDENTITY / "hardeningkitty-lab-win-b.lab.internal-20260926T000001Z-SYNTHETIC.csv"
HK_CSV = HK_CSV_A
README = IDENTITY / "README.md"
GITATTRIBUTES = ROOT / ".gitattributes"
RUNNER = ROOT / "lab-estate" / "scan-windows-hardening.ps1"
DEMO_HK = ROOT / "fixtures" / "demo" / "identity" / "hardeningkitty.csv"
HOST_A = "lab-win.lab.internal"
HOST_B = "lab-win-b.lab.internal"

# Official HK Audit Export-Csv header (HardeningKitty.psm1 @ da0976073caa).
HK_OFFICIAL_COLS = HK_AUDIT_COLUMNS

# Real MS baseline IDs from finding_list_msft_security_baseline_windows_11_24h2_machine.csv
EXPECTED_MAP = {
    "10100": ("password_policy", ["IA-5"], "csf_PR", ""),
    "10101": ("password_policy", ["IA-5"], "csf_PR", ""),
    "10001": ("account_lockout", ["AC-7"], "csf_PR", ""),
    "10208": ("session_lock", ["AC-11"], "csf_PR", ""),
    "10400": ("audit_logging", ["AU-2", "AU-12"], "csf_DE", ""),
    "10501": ("host_firewall", ["CM-6", "CM-7"], "csf_PR", "cpg_2_W"),
    "10219": ("password_policy", ["IA-5"], "csf_PR", ""),
    "11014": ("malware_protection", ["SI-3"], "csf_PR", ""),
    "10964": ("encryption_in_transit", ["SC-8"], "csf_PR", ""),
}

# Client-facing weakness column: check titles are policy names, not failures.
HK_FAILURE_WEAKNESS = {
    "10100": "Password history is shorter than required",
    "10101": "Password policy is not enforced",
    "10001": "Account lockout is not enforced",
    "10208": "Session lock after inactivity is not enforced",
    "10400": "Audit logging is not enabled",
    "10501": "Host firewall is disabled",
    "10219": "LM hashes are stored",
    "11014": "Malware real-time protection is disabled",
    "10964": "Remote session encryption is not required",
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
    for path in (HK_CSV_A, HK_CSV_B, IDENTITY / "LAB.txt", README):
        assert bytes([13]) not in path.read_bytes(), path.name


def test_synthetic_fixture_is_honest_ms_baseline_not_seen() -> None:
    assert (IDENTITY / "LAB.txt").is_file()
    assert HK_CSV_A.is_file()
    assert HK_CSV_B.is_file()
    assert README.is_file()
    banner = (IDENTITY / "LAB.txt").read_text(encoding="utf-8")
    note = README.read_text(encoding="utf-8") + HK_CSV_A.read_text(encoding="utf-8")
    assert "LAB/DEMO" in banner
    assert "not a client" in banner.lower()
    assert "SYNTHETIC" in HK_CSV_A.name and "SYNTHETIC" in HK_CSV_B.name
    assert "not an observed" in note.lower()
    assert "schema fixture" in note.lower()
    assert "not" in note.lower() and "seen" in note.lower()
    assert "finding_list_msft_security_baseline" in note
    assert "not a CIS" in note.lower() or "never cis" in note.lower()
    assert "ComputerName" not in HK_AUDIT_HEADER
    for csv_path in (HK_CSV_A, HK_CSV_B):
        body = csv_path.read_text(encoding="utf-8")
        assert "finding_list_cis_" not in body.split("ID,", 1)[-1]
        head = next(ln for ln in body.splitlines() if ln.startswith("ID,"))
        assert head == HK_AUDIT_HEADER
        assert "ComputerName" not in head
        cols = head.split(",")
        assert tuple(cols) == HK_OFFICIAL_COLS


def test_hk_failed_only_and_lab_labeled() -> None:
    recs = identity_ad.parse_file(HK_CSV)
    findings = [r for r in recs if r["kind"] == "finding"]
    assets = [r for r in recs if r["kind"] == "asset"]
    assert assets and assets[0]["name"] == HOST_A
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


def test_hk_lab_rows_failure_titles_and_honest_cpg() -> None:
    """HK check titles are policy names; CPG only from 800-53 (CM-7/SC-7/CM-8)."""
    findings = [r for r in identity_ad.parse_file(HK_CSV) if r["kind"] == "finding"]
    assert findings
    by_id = {str(r["extra"].get("check_id")): r for r in findings}
    for hid, expected in HK_FAILURE_WEAKNESS.items():
        rec = by_id[hid]
        mapped = map_finding(rec)
        assert mapped["weakness_name"] == expected, (hid, mapped["weakness_name"])
        assert mapped["weakness_name"] != rec["name"]
        assert not mapped["weakness_name"].lower().startswith("hardeningkitty")
        key, n53, _csf, extra_cpg = EXPECTED_MAP[hid]
        # extra.nist_800_53 unions with CONTROL_800_53 for the same control.
        for cid in n53:
            assert cid in mapped["nist_800_53"], (hid, cid, mapped["nist_800_53"])
        honest = ["cpg_2_W"] if any(
            cid in mapped["nist_800_53"] for cid in ("CM-7", "SC-7")
        ) else (
            ["cpg_1_E"] if "CM-8" in mapped["nist_800_53"] else []
        )
        assert mapped["cpg"] == honest, (hid, mapped["cpg"], mapped["nist_800_53"])
        if extra_cpg:
            assert extra_cpg in mapped["framework_refs"]
        else:
            assert "cpg_" not in mapped["framework_refs"]
        assert CIS_V8_PREFIX not in mapped["framework_refs"]
        assert rec["extra"].get("control_key") == key


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
        "assets": [HOST_A],
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
    assert (dest_in / "identity" / HK_CSV_A.name).is_file()
    assert (dest_in / "identity" / HK_CSV_B.name).is_file()
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
    assert HOST_A in canonical
    assert HOST_B in canonical
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


def test_lab_hk_run_collector_does_not_fill_demo(tmp_path: Path, monkeypatch) -> None:
    """LAB dest_in identity loads HK fixtures; never substitutes demo win-dc01."""
    dest_in = tmp_path / "in"
    dest_out = tmp_path / "out"
    dest_out.mkdir(parents=True)
    stage_lab_drop_dest_in(dest_in)
    monkeypatch.setenv("IN_DIR", str(dest_in))
    monkeypatch.setenv("OUT_DIR", str(dest_out))
    monkeypatch.setenv("FIXTURES_DIR", str(ROOT / "fixtures" / "demo"))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "LAB")
    monkeypatch.delenv("DROPBOX_DEMO", raising=False)

    recs = run_collector(
        identity_ad.SOURCE,
        (".json", ".xml", ".csv", ".txt"),
        identity_ad.parse_file,
        finalize=dedupe_hardening,
    )
    assert recs
    hosts: set[str] = set()
    for rec in recs:
        hosts.update(rec.get("assets") or [])
        if rec.get("kind") == "asset" and rec.get("name"):
            hosts.add(str(rec["name"]))
        labels = rec.get("labels") or []
        assert "demo" not in labels
        assert LAB_LABEL in labels
        assert "win-dc01" not in str(rec)
    assert HOST_A in hosts
    assert HOST_B in hosts
    assert "win-dc01" not in hosts
    assert WINDOWS_HOST_DEFAULT not in hosts
    status = next(
        row for row in load_sensor_coverage(dest_out) if row["source"] == identity_ad.SOURCE
    )
    assert status["demo"] is False
    assert status["status"] == "ok"
    assert status["records"] >= 1


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
    for src in (HK_CSV_A, HK_CSV_B, IDENTITY / "LAB.txt", README):
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
    assert "hardeningkitty-" in text
    assert "yyyyMMdd-HHmmss" in text
    assert "Add-Member" not in text
    assert ".host" in text


def _official_hk_row(
    hid: str,
    name: str,
    result: str,
    recommended: str,
    test_result: str,
    *,
    severity: str = "Medium",
) -> str:
    return (
        f"{hid},Account Policies,{name},{severity},{result},"
        f"{recommended},{test_result},{severity},,"
    )


def test_official_header_testresult_failed_is_finding_passed_is_not(tmp_path: Path) -> None:
    """Real HK Export-Csv: Result is measured; TestResult decides fail/pass."""
    dest = tmp_path / f"hardeningkitty-win-official-20260926T010000Z.csv"
    dest.write_text(
        HK_AUDIT_HEADER
        + "\n"
        + _official_hk_row("10100", "Length of password history maintained", "5", "24", "Failed")
        + "\n"
        + _official_hk_row("10102", "Password must meet complexity requirements", "1", "1", "Passed")
        + "\n"
        + _official_hk_row("10101", "Minimum password length", "Failed", "14", "Passed")
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    recs = identity_ad.parse_file(dest)
    findings = [r for r in recs if r["kind"] == "finding"]
    ids = {str(r["extra"].get("check_id")) for r in findings}
    assert "10100" in ids
    assert "10102" not in ids
    assert "10101" not in ids  # TestResult=Passed wins over Result=Failed
    assert all(r["assets"] == ["win-official"] for r in recs)
    assert WINDOWS_HOST_DEFAULT not in {r["name"] for r in recs}
    blob = str(recs)
    assert " actual=5" not in blob
    assert "[REDACTED]" in blob


def test_two_official_files_are_two_hosts() -> None:
    assert hk_host_from_filename(HK_CSV_A.name) == HOST_A
    assert hk_host_from_filename(HK_CSV_B.name) == HOST_B
    recs = identity_ad.parse_file(HK_CSV_A) + identity_ad.parse_file(HK_CSV_B)
    assets = sorted({r["name"] for r in recs if r["kind"] == "asset"})
    assert assets == sorted([HOST_A, HOST_B])
    assert WINDOWS_HOST_DEFAULT not in assets
    by_host = {}
    for rec in recs:
        if rec["kind"] != "finding":
            continue
        for host in rec["assets"]:
            by_host.setdefault(host, []).append(rec["extra"].get("check_id"))
    assert "10100" in by_host[HOST_A]
    assert "10501" in by_host[HOST_B]
    assert by_host[HOST_A] != by_host[HOST_B] or HOST_A != HOST_B


def test_missing_host_does_not_collapse_onto_windows_host(tmp_path: Path) -> None:
    header_rows = (
        HK_AUDIT_HEADER
        + "\n"
        + _official_hk_row("10100", "Length of password history maintained", "5", "24", "Failed")
        + "\n"
    )
    one = tmp_path / "left" / "audit.csv"
    two = tmp_path / "right" / "audit.csv"
    one.parent.mkdir()
    two.parent.mkdir()
    one.write_text(header_rows, encoding="utf-8", newline="\n")
    two.write_text(header_rows, encoding="utf-8", newline="\n")
    recs_one = identity_ad.parse_file(one)
    recs_two = identity_ad.parse_file(two)
    names_one = {r["name"] for r in recs_one if r["kind"] == "asset"}
    names_two = {r["name"] for r in recs_two if r["kind"] == "asset"}
    assert names_one
    assert names_two
    assert WINDOWS_HOST_DEFAULT not in names_one
    assert WINDOWS_HOST_DEFAULT not in names_two
    assert names_one != names_two
    assert all(r["extra"].get("host_unresolved") is True for r in recs_one)
    assert all(r["extra"].get("host_unresolved") is True for r in recs_two)
    assert hk_row_failed({"testresult": "passed", "result": "failed"}) == ("passed", False)
    assert hk_row_failed({"testresult": "failed", "result": "5"}) == ("failed", True)
    assert hk_row_failed({"result": "failed"}) == ("failed", True)
