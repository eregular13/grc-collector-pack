"""KEEP-chain samples + adapters + Eval handoff. SAMPLE ≠ client KEEP."""

from __future__ import annotations

import json
from pathlib import Path

from keep.adapters import (
    KEEP_FAMILIES,
    client_keep_ready,
    detect_family,
    land_keep_files,
    scan_keep_dir,
)
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
    assert len(handoff["findings"]) <= MAX_FINDINGS
    assert handoff["findings"]
    assert handoff["ciso"]["shape"] == "ciso-assistant"
    assert "findings.csv" in handoff["ciso"]["files"]
    assert stamp["pack_in_written"] is False
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


def test_handoff_docs_and_no_eval_http() -> None:
    banned = ("socket.socket", "urllib.request", "http.client", "requests.get", "urllib3")
    for rel in ("keep/adapters.py", "keep/handoff.py", "keep/lab.py"):
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
    assert "keep-lab never" in op.lower() or "never touching pack" in op.lower() or "never writes pack" in op.lower()
    doc = (ROOT / "docs" / "KEEP_EVAL_HANDOFF.md").read_text(encoding="utf-8")
    assert "max-5" in doc or "max 5" in doc or "max_findings" in doc
    assert "No live Eval HTTP" in doc or "no live Eval HTTP" in doc.lower()
    samples = (SAMPLES / "README.md").read_text(encoding="utf-8")
    assert "SAMPLE ≠ client KEEP" in samples or "not" in samples.lower()


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
    assert payload["findings"][0]["name"] == "Public bucket"
    assert payload["assets"][0]["name"] == "bucket-a"
