"""KEEP-chain samples + adapters + Eval handoff. SAMPLE ≠ client KEEP."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from keep.adapters import (
    KEEP_FAMILIES,
    client_keep_ready,
    detect_family,
    land_keep_files,
    scan_keep_dir,
)
from keep.ciso_import import CISO_REQUIRED, honest_paying_day, read_paying_day
from shared.ciso_shape import assert_risk_register_and_poam
from keep.handoff import MAX_FINDINGS, build_eval_handoff, select_max_findings
from keep.lab import keep_lab

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "fixtures" / "keep-samples"


def test_samples_are_labeled_not_client_keep() -> None:
    readme = (SAMPLES / "README.md").read_text(encoding="utf-8")
    assert "not" in readme.lower() and "client KEEP" in readme
    assert "SAMPLE" in readme
    rows = scan_keep_dir(SAMPLES)
    groups = {row["group"] for row in rows}
    assert set(KEEP_FAMILIES) <= groups
    assert all(row["sample"] for row in rows)
    assert client_keep_ready(rows) is False
    by_group = {row["group"]: row for row in rows}
    assert detect_family(SAMPLES / "identity" / "hardeningkitty.csv") == "hardeningkitty"
    assert detect_family(SAMPLES / "saas" / "maester.json") == "maester"
    assert detect_family(SAMPLES / "vuln" / "testssl.json") == "testssl"
    assert detect_family(SAMPLES / "cloud" / "prowler.json") == "prowler"
    assert detect_family(SAMPLES / "cloud" / "scoutsuite.json") == "scoutsuite"
    assert by_group["hardeningkitty"]["sensor"] == "identity"
    assert by_group["maester"]["sensor"] == "saas"
    assert by_group["testssl"]["sensor"] == "vuln"
    assert by_group["cloud"]["sensor"] == "cloud"


def test_adapters_land_without_subprocess(tmp_path: Path) -> None:
    rows = scan_keep_dir(SAMPLES)
    landed = land_keep_files(rows, tmp_path / "in")
    assert landed
    assert all(row.get("invoke") is False for row in landed)
    assert (tmp_path / "in" / "identity" / "hardeningkitty.csv").is_file()
    assert (tmp_path / "in" / "saas" / "maester.json").is_file()
    assert (tmp_path / "in" / "vuln" / "testssl.json").is_file()
    assert (tmp_path / "in" / "cloud" / "prowler.json").is_file()
    blob = (tmp_path / "in" / "identity" / "hardeningkitty.csv").read_text(encoding="utf-8")
    assert "sample-dc01.keep.invalid" in blob
    assert "[REDACTED]" in blob


def test_keep_lab_uses_samples_when_pack_in_empty(tmp_path: Path) -> None:
    empty = tmp_path / "empty-in"
    empty.mkdir()
    stamp = keep_lab(ROOT, pack_in=empty, work=tmp_path / "work")
    assert stamp["status"] == "pass"
    assert stamp["sample"] is True
    assert stamp["client_keep"] is False
    assert stamp["origin"] == "keep-samples"
    assert stamp["posted"] is False
    assert stamp["http"] is False
    assert stamp["wrap"] == "review-only"
    assert "SAMPLE" in stamp["label"]
    assert "client KEEP" in stamp["label"]
    assert set(KEEP_FAMILIES) <= set(stamp["families"])
    assert stamp["counts"]["handoff_findings"] >= 1
    assert stamp["counts"]["handoff_findings"] <= MAX_FINDINGS
    assert stamp["counts"]["handoff_assets"] >= 1
    assert stamp["counts"]["demo"] is True
    handoff = json.loads(Path(stamp["handoff"]).read_text(encoding="utf-8"))
    assert handoff["consumer"] == "origin-eval"
    assert handoff["posted"] is False
    assert handoff["http"] is False
    assert handoff["sample"] is True
    assert handoff["client_keep"] is False
    assert handoff["paying_day"] == "FAIL"
    assert handoff["wrap"] == "review-only"
    assert len(handoff["findings"]) <= MAX_FINDINGS
    assert handoff["findings"]
    assert handoff["ciso"]["shape"] == "ciso-assistant"
    assert "findings.csv" in handoff["ciso"]["files"]
    assert stamp["paying_day"] == "FAIL"
    assert stamp["paying_day"] == honest_paying_day(read_paying_day(ROOT), sample=True)
    assert stamp["wrap"] == "review-only"
    assert stamp["ciso_files"]
    for name in CISO_REQUIRED:
        assert name in stamp["ciso_files"]
        assert (Path(stamp["ciso_dir"]) / name).is_file()
    import_doc = json.loads((Path(stamp["ciso_dir"]) / "IMPORT.json").read_text(encoding="utf-8"))
    assert import_doc["demo"] is True
    assert import_doc["sample"] is True
    assert import_doc["client_keep"] is False
    assert import_doc["paying_day"] == "FAIL"
    assert import_doc["posted"] is False
    assert import_doc["http"] is False
    assert "SAMPLE" in import_doc["estate"] and "not a client" in import_doc["estate"].lower()
    guide = (Path(stamp["ciso_dir"]) / "IMPORT.md").read_text(encoding="utf-8")
    assert "SAMPLE" in guide and "not a client" in guide.lower()
    findings = (Path(stamp["ciso_dir"]) / "findings.csv").read_text(encoding="utf-8")
    assert "demo" in findings.lower() or "sample" in findings.lower()
    shape = assert_risk_register_and_poam(Path(stamp["out_dir"]))
    assert shape["findings"] >= 1
    assert shape["poam_rows"] >= 1
    assert stamp["pack_in_written"] is False
    assert stamp["sinks_posted"] is False
    opengrc = Path(stamp["opengrc"])
    assert (opengrc / "risks.csv").is_file()
    assert (opengrc / "assets.csv").is_file()
    assert (opengrc / "MANIFEST.json").is_file()
    og = json.loads((opengrc / "MANIFEST.json").read_text(encoding="utf-8"))
    assert og["demo"] is True
    assert og["sample"] is True
    assert og["posted"] is False
    assert og["client"] is False
    probo_path = Path(stamp["probo"])
    assert probo_path.is_file()
    probo = json.loads(probo_path.read_text(encoding="utf-8"))
    assert probo["demo"] is True
    assert probo["posted"] is False
    assert probo["addFinding"]
    assert handoff["sinks"]["demo"] is True
    assert handoff["sinks"]["riskready"] == "stay-out"
    pack_in_files = [p for p in (ROOT / "in").rglob("*") if p.is_file() and p.name != ".gitkeep"]
    assert pack_in_files == [] or stamp["pack_in_preexisting"] == len(pack_in_files)


def test_keep_lab_samples_pass_with_preexisting_pack_in_estate(tmp_path: Path) -> None:
    """Desktop: estate already in pack in/ must not fail sample keep-lab isolation."""
    pack_in = tmp_path / "estate-in"
    (pack_in / "nmap").mkdir(parents=True)
    (pack_in / "cloud").mkdir()
    estate_xml = pack_in / "nmap" / "client-scan.xml"
    estate_xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.9"/></host></nmaprun>\n',
        encoding="utf-8",
    )
    estate_json = pack_in / "cloud" / "not-keep.json"
    estate_json.write_text('{"estate": true, "note": "not a KEEP family"}\n', encoding="utf-8")
    before_xml = estate_xml.read_bytes()
    before_json = estate_json.read_bytes()
    stamp = keep_lab(ROOT, pack_in=pack_in, work=tmp_path / "work")
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["origin"] == "keep-samples"
    assert stamp["sample"] is True
    assert stamp["client_keep"] is False
    assert stamp["pack_in_written"] is False
    assert stamp["pack_in_preexisting"] >= 2
    assert stamp["posted"] is False
    assert stamp["http"] is False
    assert set(KEEP_FAMILIES) <= set(stamp["families"])
    assert stamp["counts"]["handoff_findings"] == 5 or stamp["counts"]["handoff_findings"] >= 1
    assert estate_xml.read_bytes() == before_xml
    assert estate_json.read_bytes() == before_json
    work_in = tmp_path / "work" / "in"
    assert (work_in / "identity" / "hardeningkitty.csv").is_file()
    assert not (pack_in / "identity" / "hardeningkitty.csv").exists()


def test_keep_lab_client_keep_when_four_non_sample_files(tmp_path: Path) -> None:
    pack_in = tmp_path / "client-in"
    (pack_in / "identity").mkdir(parents=True)
    (pack_in / "saas").mkdir()
    (pack_in / "vuln").mkdir()
    (pack_in / "cloud").mkdir()
    (pack_in / "identity" / "hardeningkitty.csv").write_text(
        "ID,Name,Severity,Result,RecommendedValue,TestedValue,ComputerName\n"
        "1.1,Enforce password history,High,Failed,24,5,win-keep-client\n",
        encoding="utf-8",
    )
    (pack_in / "saas" / "maester.json").write_text(
        json.dumps(
            {
                "Tenant": "contoso.onmicrosoft.com",
                "TestResults": [
                    {
                        "Id": "MT.1035",
                        "Name": "MT.1035",
                        "Result": "Failed",
                        "Severity": "high",
                        "Description": "Privileged users should have phishing-resistant MFA",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (pack_in / "vuln" / "testssl.json").write_text(
        json.dumps(
            [
                {
                    "id": "heartbleed",
                    "severity": "HIGH",
                    "cve": "CVE-2014-0160",
                    "finding": "Heartbleed still offered on TLS",
                    "ip": "vpn.client.example/192.0.2.9",
                }
            ]
        ),
        encoding="utf-8",
    )
    (pack_in / "cloud" / "prowler.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "CheckID": "s3_bucket_public_access",
                        "CheckTitle": "S3 bucket prohibits public access",
                        "Status": "FAIL",
                        "Severity": "critical",
                        "ResourceId": "client-public-assets",
                        "Description": "Bucket ACL allows public List/Get.",
                        "ServiceName": "s3",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = scan_keep_dir(pack_in)
    assert client_keep_ready(rows) is True
    stamp = keep_lab(ROOT, pack_in=pack_in, work=tmp_path / "work")
    assert stamp["status"] == "pass"
    assert stamp["sample"] is False
    assert stamp["client_keep"] is True
    assert stamp["origin"] == "pack-in"
    handoff = json.loads(Path(stamp["handoff"]).read_text(encoding="utf-8"))
    assert handoff["client_keep"] is True
    assert handoff["sample"] is False
    names = " ".join(str(row.get("name") or "") for row in handoff["findings"])
    assets = " ".join(str(row.get("name") or "") for row in handoff["assets"])
    blob = names + " " + assets
    assert "sample-dc01" not in blob
    assert "win-keep-client" in blob or "client-public-assets" in blob or "heartbleed" in names.lower()


def test_eval_handoff_caps_at_five() -> None:
    records = []
    for i, sev in enumerate(("critical", "high", "high", "medium", "low", "info", "medium")):
        records.append(
            {
                "kind": "finding",
                "ref_id": f"F-{i}",
                "name": f"finding-{i}",
                "severity": sev,
                "assets": [f"asset-{i}"],
                "source": "cloud-prowler",
            }
        )
        records.append(
            {
                "kind": "asset",
                "ref_id": f"A-{i}",
                "name": f"asset-{i}",
                "source": "cloud-prowler",
            }
        )
    selected = select_max_findings(records)
    assert len(selected) == MAX_FINDINGS
    assert selected[0]["severity"] == "critical"
    assert all(row["severity"] != "info" for row in selected)


def test_demo_keep_files_do_not_stamp_client_keep(tmp_path: Path) -> None:
    """fixtures/demo KEEP-shaped files must not look like a client KEEP drop."""
    pack_in = tmp_path / "demo-as-client"
    mapping = (
        ("identity", "hardeningkitty.csv"),
        ("saas", "maester.json"),
        ("vuln", "testssl.json"),
        ("cloud", "prowler.json"),
    )
    for sensor, name in mapping:
        dest = pack_in / sensor
        dest.mkdir(parents=True)
        src = ROOT / "fixtures" / "demo" / sensor / name
        dest.joinpath(name).write_bytes(src.read_bytes())
    rows = scan_keep_dir(pack_in)
    groups = {row["group"] for row in rows}
    assert set(KEEP_FAMILIES) <= groups
    assert any(row["sample"] for row in rows)
    assert client_keep_ready(rows) is False
    stamp = keep_lab(ROOT, pack_in=pack_in, work=tmp_path / "work")
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["sample"] is True
    assert stamp["client_keep"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["origin"] == "keep-samples"
    import_doc = json.loads((Path(stamp["ciso_dir"]) / "IMPORT.json").read_text(encoding="utf-8"))
    assert import_doc["client_keep"] is False
    assert import_doc["demo"] is True


def test_handoff_docs_and_no_eval_http() -> None:
    banned = ("socket.socket", "urllib.request", "http.client", "requests.get", "urllib3")
    for rel in (
        "keep/adapters.py",
        "keep/handoff.py",
        "keep/lab.py",
        "keep/wipe.py",
        "keep/ciso_import.py",
        "keep/export.py",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, rel
    handoff = (ROOT / "keep" / "handoff.py").read_text(encoding="utf-8")
    lab = (ROOT / "keep" / "lab.py").read_text(encoding="utf-8")
    assert "api/risks" in handoff and "does not POST" in handoff
    assert "api/risks" in lab
    op = (ROOT / "keep" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "SAMPLE ≠ client KEEP" in op or "SAMPLE ≠ client" in op
    assert "npm start" in op or "Origin Eval" in op
    assert "handoff.json" in op
    assert "python -m keep lab" in op or "python3 -m keep lab" in op
    assert "ciso-assistant" in op
    assert "IMPORT.md" in op or "IMPORT.json" in op
    assert "paying_day" in op or "paying_day" in op.lower() or "FAIL" in op
    assert "keep-lab never" in op.lower() or "never touching pack" in op.lower() or "never writes pack" in op.lower()
    assert "DESKTOP_DRY_RUN.md" in op
    assert "DRY_RUN=1" in op and "CISO_PUSH=0" in op
    doc = (ROOT / "docs" / "KEEP_EVAL_HANDOFF.md").read_text(encoding="utf-8")
    assert "max-5" in doc or "max 5" in doc or "max_findings" in doc
    assert "No live Eval HTTP" in doc or "no live Eval HTTP" in doc.lower()
    assert "ciso-assistant" in doc
    samples = (SAMPLES / "README.md").read_text(encoding="utf-8")
    assert "SAMPLE ≠ client KEEP" in samples or "not" in samples.lower()
    prove = (ROOT / "docs" / "PROVE_CISO.md").read_text(encoding="utf-8")
    assert "python3 -m keep lab" in prove
    assert "keep-samples" in prove
    main = (ROOT / "keep" / "__main__.py").read_text(encoding="utf-8")
    assert '"ciso"' in main or "ciso" in main


def test_eval_handoff_builder_stays_file_drop(tmp_path: Path) -> None:
    (tmp_path / "canonical").mkdir()
    (tmp_path / "canonical" / "cloud-prowler.jsonl").write_text(
        json.dumps(
            {
                "kind": "finding",
                "ref_id": "CLD-1",
                "name": "Public bucket",
                "severity": "critical",
                "assets": ["bucket-a"],
                "source": "cloud-prowler",
            }
        )
        + "\n"
        + json.dumps(
            {
                "kind": "asset",
                "ref_id": "CLD-A",
                "name": "bucket-a",
                "source": "cloud-prowler",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "ciso-assistant").mkdir()
    (tmp_path / "ciso-assistant" / "findings.csv").write_text("ref_id\nCLD-1\n", encoding="utf-8")
    payload = build_eval_handoff(tmp_path, sample=True, client_keep=False)
    assert payload["http"] is False
    assert payload["posted"] is False
    assert payload["sample"] is True
    assert payload["paying_day"] == "FAIL"
    assert payload["wrap"] == "review-only"
    assert payload["findings"][0]["name"] == "Public bucket"
    assert payload["assets"][0]["name"] == "bucket-a"


def test_honest_paying_day_cannot_pass_from_sample() -> None:
    assert honest_paying_day("PASS", sample=True) == "FAIL"
    assert honest_paying_day("FAIL", sample=True) == "FAIL"
    assert honest_paying_day("PASS", sample=False) == "FAIL"
    assert honest_paying_day("FAIL", sample=False) == "FAIL"
    from keep.ciso_import import build_ciso_import_manifest

    payload = build_ciso_import_manifest(
        ROOT / "keep" / "work" / "out",
        sample=True,
        client_keep=False,
        paying_day="PASS",
        origin="keep-samples",
    )
    assert payload["paying_day"] == "FAIL"
    assert payload["sample"] is True
    assert payload["client_keep"] is False
    assert payload["wrap"] == "review-only"


def test_sample_keep_lab_cannot_inherit_paying_day_pass(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("keep.lab.read_paying_day", lambda root: "PASS")
    empty = tmp_path / "empty-in"
    empty.mkdir()
    stamp = keep_lab(ROOT, pack_in=empty, work=tmp_path / "work")
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["sample"] is True
    assert stamp["paying_day"] == "FAIL"
    import_doc = json.loads((Path(stamp["ciso_dir"]) / "IMPORT.json").read_text(encoding="utf-8"))
    assert import_doc["paying_day"] == "FAIL"
    handoff = json.loads(Path(stamp["handoff"]).read_text(encoding="utf-8"))
    assert handoff["paying_day"] == "FAIL"


def test_keep_lab_forces_dry_run_and_refuses_wrap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CISO_PUSH", "1")
    monkeypatch.setenv("DRY_RUN", "0")
    monkeypatch.setenv("RISKREADY_PUSH", "1")
    monkeypatch.setenv("GRC_LIVE_SCAN", "1")
    empty = tmp_path / "empty-in"
    empty.mkdir()
    stamp = keep_lab(ROOT, pack_in=empty, work=tmp_path / "work")
    assert stamp["status"] == "pass", stamp.get("reason")
    assert stamp["posted"] is False
    assert stamp["http"] is False
    assert stamp["sinks_posted"] is False
    assert stamp["wrap"] == "review-only"
    assert stamp["paying_day"] == "FAIL"
    og = json.loads((Path(stamp["opengrc"]) / "MANIFEST.json").read_text(encoding="utf-8"))
    assert og["posted"] is False
    assert og.get("riskready", "").startswith("stay-out") or "stay-out" in json.dumps(og)
    probo = json.loads(Path(stamp["probo"]).read_text(encoding="utf-8"))
    assert probo["posted"] is False
    assert probo["paying_day"] == "FAIL"


def test_keep_lab_cli_desktop_dry_run(tmp_path: Path) -> None:
    """Operator CLI: python3 -m keep lab --pack-in/--work with DRY_RUN=1 CISO_PUSH=0."""
    import os
    import subprocess
    import sys

    empty = tmp_path / "empty-in"
    empty.mkdir()
    work = tmp_path / "cli-work"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DRY_RUN"] = "1"
    env["CISO_PUSH"] = "0"
    env["RISKREADY_PUSH"] = "0"
    env["GRC_LIVE_SCAN"] = "0"
    env["DROPBOX_LIVE"] = "0"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "keep",
            "lab",
            "--pack-in",
            str(empty),
            "--work",
            str(work),
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    stamp = json.loads((work / "keep-lab.json").read_text(encoding="utf-8"))
    assert stamp["status"] == "pass"
    assert stamp["sample"] is True
    assert stamp["client_keep"] is False
    assert stamp["paying_day"] == "FAIL"
    assert stamp["posted"] is False
    assert stamp["wrap"] == "review-only"
    assert (work / "out" / "ciso-assistant" / "IMPORT.json").is_file()
    assert (work / "out" / "opengrc" / "risks.csv").is_file()
    assert (work / "out" / "import_preview" / "probo.json").is_file()
    assert "SAMPLE" in proc.stdout


def test_desktop_dry_run_doc_is_operator_followable() -> None:
    doc = (ROOT / "docs" / "DESKTOP_DRY_RUN.md").read_text(encoding="utf-8")
    low = doc.lower()
    assert "DRY_RUN=1" in doc
    assert "CISO_PUSH=0" in doc
    assert "RISKREADY_PUSH=0" in doc
    assert "GRC_LIVE_SCAN=0" in doc
    assert "python3 -m keep lab" in doc
    assert "SAMPLE ≠ client" in doc or "SAMPLE ≠ client KEEP" in doc
    assert "paying_day" in doc and "FAIL" in doc
    assert "/api/risks" in doc
    assert "stay-out" in low or "review-only" in low
    assert "opengrc" in low
    assert "probo" in low
    assert "0/4" in doc
    assert "keep/work/out/ciso-assistant" in doc
    assert "--pack-in" in doc and "--work" in doc
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "DESKTOP_DRY_RUN.md" in readme
    og = (ROOT / "docs" / "IMPORT_OPENGRC.md").read_text(encoding="utf-8")
    assert "DESKTOP_DRY_RUN.md" in og
    assert "DRY_RUN=1" in og and "CISO_PUSH=0" in og


def test_keep_lab_fails_closed_on_incomplete_keep_samples(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dropbox.keep_preflight import KeepFixtureIncomplete, require_keep_samples

    monkeypatch.setattr(
        "keep.lab.require_keep_samples",
        lambda root: require_keep_samples(tmp_path),
    )
    monkeypatch.setattr(
        "keep.lab._choose_sources",
        lambda root, pack_in: ([], False, "keep-samples"),
    )
    empty = tmp_path / "empty-in"
    empty.mkdir()
    stamp = keep_lab(ROOT, pack_in=empty, work=tmp_path / "work")
    assert stamp["status"] == "fail"
    reason = str(stamp.get("reason") or "")
    assert "keep fixture incomplete" in reason
    assert "four families" in reason
    with pytest.raises(KeepFixtureIncomplete):
        require_keep_samples(tmp_path)


def test_keep_lab_fails_closed_on_malformed_keep_samples(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    samples = tmp_path / "broken-samples"
    shutil.copytree(SAMPLES, samples)
    (samples / "cloud" / "prowler.json").write_text("{", encoding="utf-8")
    (samples / "cloud" / "scoutsuite.json").write_text("{", encoding="utf-8")

    def _broken_sources(root: Path, pack_in: Path):
        return scan_keep_dir(samples), False, "keep-samples"

    monkeypatch.setattr("keep.lab._choose_sources", _broken_sources)
    empty = tmp_path / "empty-in"
    empty.mkdir()
    stamp = keep_lab(ROOT, pack_in=empty, work=tmp_path / "work")
    assert stamp["status"] == "fail"
    reason = str(stamp.get("reason") or "")
    assert "keep fixture malformed" in reason
    assert "cloud" in reason
