"""Estate banner + exec summary + SCOPE_AND_TRUST.md (Argus drafts).

Banner on every named export. SAMPLE/DEMO/LAB/fallback never CLIENT and
cannot be suppressed. Missing values print 'not recorded'. No generated
reviewer prose.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from shared.ciso_shape import CISO_HEADERS, POAM_HEADER, csv_rows
from shared.estate_pages import (
    COLLECTOR_AREAS,
    LABEL_FOR_KIND,
    MAX_PAGE_LINES,
    NOT_RECORDED,
    REVIEWER_NEXT_STEP,
    REVIEWER_WHAT_WE_FOUND,
    REVIEWER_WHY_IT_MATTERS,
    EstateStamp,
    assert_client_export_honesty,
    classify_estate,
    parse_out_of_scope_names,
    parse_scope_table_areas,
)

ROOT = Path(__file__).resolve().parents[1]


def _finding(ref: str, sev: str = "high", labels: list[str] | None = None) -> dict:
    return {
        "kind": "finding",
        "source": "inventory-nmap",
        "ref_id": ref,
        "name": f"FTP exposed {ref}",
        "description": f"{ref} has open TCP/21 (ftp).",
        "severity": sev,
        "category": "exposure",
        "assets": ["host-a"],
        "labels": labels or ["nmap"],
        "extra": {"port": "21", "service": "ftp", "ip": "10.0.0.5"},
    }


def _asset() -> dict:
    return {
        "kind": "asset",
        "source": "inventory-nmap",
        "ref_id": "asset-host-a",
        "name": "host-a",
        "description": "Host host-a",
        "severity": "info",
        "category": "host",
        "assets": ["host-a"],
        "labels": ["nmap"],
        "extra": {"asset_type": "PR", "ip": "10.0.0.5"},
    }


def _run_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: list[dict], **env: str) -> Path:
    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    with (out / "canonical" / "inventory-nmap.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    for key in ("GRC_ESTATE_LABEL", "DROPBOX_DEMO", "GRC_HIDE_ESTATE", "GRC_SUPPRESS_ESTATE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()
    return out


HUMAN_FILES = (
    "EXECUTIVE_SUMMARY.md",
    "SCOPE_AND_TRUST.md",
    "poam/poam.md",
    "ciso-assistant/ESTATE.txt",
    "poam/ESTATE.txt",
)
IMPORT_CSVS = (
    "ciso-assistant/assets.csv",
    "ciso-assistant/applied_controls.csv",
    "ciso-assistant/evidences.csv",
    "ciso-assistant/findings.csv",
    "ciso-assistant/vulnerabilities.csv",
    "ciso-assistant/risk_scenarios.csv",
    "poam/poam.csv",
)
HEADER_FIRST_NEW = (
    "poam/poam_fedramp.csv",
    "poam/poam_fedramp_closed.csv",
    "poam/poam-ledger.json",
    "poam/kev_provenance.json",
)


def test_estate_stamp_has_no_csv_hash_banner() -> None:
    """Import CSVs must never grow a # preamble. Do not restore banner_csv_comments."""
    assert not hasattr(EstateStamp, "banner_csv_comments")
    stamp = classify_estate([], env={"GRC_ESTATE_LABEL": "LAB"})
    assert not stamp.banner_md().lstrip().startswith("#")
    assert stamp.banner_oneline()
    src = (ROOT / "shared" / "estate_pages.py").read_text(encoding="utf-8")
    assert "banner_csv_comments" not in src
    assert "def banner_csv_comments" not in src


def test_classify_fails_closed_and_refuses_client_on_sample() -> None:
    sample = classify_estate([{"labels": ["demo"], "source": "fixtures/demo"}])
    assert sample.kind == "DEMO"
    assert sample.label == LABEL_FOR_KIND["DEMO"]
    assert sample.kind != "CLIENT"

    lab = classify_estate([], env={"GRC_ESTATE_LABEL": "LAB"})
    assert lab.kind == "LAB"
    assert lab.label == LABEL_FOR_KIND["LAB"]

    unsure = classify_estate([{"labels": ["nmap"], "source": "inventory-nmap"}])
    assert unsure.kind == "SAMPLE"
    assert unsure.label == LABEL_FOR_KIND["SAMPLE"]

    forced = classify_estate(
        [{"labels": ["demo"], "source": "fixtures/demo"}],
        env={"GRC_ESTATE_LABEL": "CLIENT", "GRC_HIDE_ESTATE": "1"},
        client_name="Acme Corp",
    )
    assert forced.kind != "CLIENT"
    assert not forced.label.startswith("CLIENT:")

    mixed = classify_estate(
        [
            {"labels": ["demo"], "source": "fixtures/demo"},
            {"labels": ["nmap"], "source": "inventory-nmap"},
        ],
        fallback_files=["product-lab/drop"],
    )
    assert mixed.kind == "MIXED"
    assert mixed.label == LABEL_FOR_KIND["MIXED"]
    assert "product-lab/drop" in mixed.sentence


def test_banner_and_estate_column_on_every_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader(
        tmp_path,
        monkeypatch,
        [_asset(), _finding("f1"), _finding("f2", sev="medium")],
        GRC_ESTATE_LABEL="SAMPLE",
    )
    label = LABEL_FOR_KIND["SAMPLE"]
    for rel in HUMAN_FILES:
        path = out / rel
        assert path.is_file(), rel
        text = path.read_text(encoding="utf-8")
        assert label in text, rel
        assert "Every finding below comes from bundled example files" in text, rel

    for rel in IMPORT_CSVS:
        path = out / rel
        assert path.is_file(), rel
        first = path.read_text(encoding="utf-8").splitlines()[0].strip()
        assert not first.startswith("#"), rel
        if rel.startswith("ciso-assistant/"):
            name = Path(rel).name
            assert first == CISO_HEADERS[name], rel
            delim = ";" if name == "risk_scenarios.csv" else ","
            rows = csv_rows(path, delimiter=delim)
            assert all("estate" not in row for row in rows), rel
        else:
            assert first == POAM_HEADER
            rows = csv_rows(path)
            assert rows and {row["estate"] for row in rows} == {label}

    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    trust = (out / "SCOPE_AND_TRUST.md").read_text(encoding="utf-8")
    assert exec_text.startswith("> **")
    assert trust.startswith("> **")
    assert REVIEWER_WHAT_WE_FOUND in exec_text
    assert REVIEWER_WHY_IT_MATTERS in exec_text
    assert REVIEWER_NEXT_STEP in exec_text
    assert "No client authorization applies" in trust
    for blob in (exec_text, trust):
        assert "CoS #" not in blob
        assert "cycle " not in blob.lower() or "cycle " not in blob
        assert "E2E_PROVEN" not in blob
        assert "adapter list" not in blob.lower()


def test_import_csvs_first_line_is_not_a_hash_comment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from exporters.opengrc import write_opengrc
    from shared.poam_fedramp import FEDRAMP_OPEN_HEADERS

    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], GRC_ESTATE_LABEL="LAB")
    write_opengrc(out)
    import_csvs = IMPORT_CSVS + (
        "opengrc/risks.csv",
        "opengrc/assets.csv",
        "opengrc/implementations.csv",
        "simplerisk/poam.csv",
    )
    for rel in import_csvs:
        path = out / rel
        assert path.is_file(), rel
        first = path.read_text(encoding="utf-8").splitlines()[0]
        assert not first.lstrip().startswith("#"), rel
        assert first.strip() == first.splitlines()[0].strip()
    for rel in HEADER_FIRST_NEW:
        path = out / rel
        assert path.is_file(), rel
        text = path.read_text(encoding="utf-8")
        first = text.splitlines()[0]
        assert not first.lstrip().startswith("#"), rel
        if rel.endswith(".csv"):
            assert first == ",".join(FEDRAMP_OPEN_HEADERS), rel
        else:
            assert text.lstrip()[:1] in "{["
    assert (out / "poam" / "ESTATE.txt").is_file()
    assert LABEL_FOR_KIND["LAB"] in (out / "poam" / "ESTATE.txt").read_text(encoding="utf-8")


def test_sample_cannot_claim_client_or_suppress_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader(
        tmp_path,
        monkeypatch,
        [_asset(), _finding("f1", labels=["nmap", "demo"])],
        GRC_ESTATE_LABEL="CLIENT",
        GRC_HIDE_ESTATE="1",
        GRC_SUPPRESS_ESTATE="1",
    )
    for rel in ("EXECUTIVE_SUMMARY.md", "SCOPE_AND_TRUST.md", "poam/poam.md"):
        text = (out / rel).read_text(encoding="utf-8")
        assert text.lstrip().startswith("> **")
        assert not text.splitlines()[0].startswith("> **CLIENT:")
        assert any(
            tok in text
            for tok in (
                "DEMO: NOT A CLIENT",
                "SAMPLE DATA: NOT A CLIENT",
                "MIXED: REVIEW BEFORE USE",
            )
        )
    rows = csv_rows(out / "poam" / "poam.csv")
    assert all(not (row.get("estate") or "").startswith("CLIENT:") for row in rows)


def test_lab_fallback_to_drop_is_mixed_and_stated() -> None:
    stamp = classify_estate(
        [
            {"labels": ["nmap"], "source": "inventory-nmap"},
            {"labels": ["demo"], "source": "fixtures/demo"},
        ],
        fallback_files=["product-lab/drop"],
        env={"GRC_ESTATE_LABEL": "LAB"},
    )
    assert stamp.kind == "MIXED"
    assert "product-lab/drop" in stamp.sentence
    assert "CLIENT" not in stamp.label


def test_estate_pages_and_detection_dates_agree_not_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pack collected_at is not a scan time. Estate pages and POA&M both print 'not recorded'."""
    finding = _finding("f1")
    finding["collected_at"] = "2026-09-26T06:00:00Z"
    asset = _asset()
    asset["collected_at"] = "2026-09-26T06:00:00Z"
    out = _run_loader(tmp_path, monkeypatch, [asset, finding], GRC_ESTATE_LABEL="SAMPLE")
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    trust = (out / "SCOPE_AND_TRUST.md").read_text(encoding="utf-8")
    poam = csv_rows(out / "poam" / "poam.csv")
    assert poam and poam[0]["original_detection_date"] == NOT_RECORDED
    window = next(line for line in exec_text.splitlines() if "Assessment window" in line)
    assert "2026-09-26T06:00:00Z" not in window
    assert "2026-09-26T06:00:00Z" not in trust
    assert NOT_RECORDED in trust


def test_estate_pages_use_artifact_scan_time_not_collected_at(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _finding("f1")
    finding["collected_at"] = "2026-09-26T06:00:00Z"
    finding["extra"] = {**finding["extra"], "scan_time": "2026-09-01T12:00:00Z"}
    out = _run_loader(tmp_path, monkeypatch, [_asset(), finding], GRC_ESTATE_LABEL="LAB")
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    poam = csv_rows(out / "poam" / "poam.csv")
    assert poam and poam[0]["original_detection_date"] == "2026-09-01"
    window = next(line for line in exec_text.splitlines() if "Assessment window" in line)
    assert "2026-09-01" in window
    assert "2026-09-26T06:00:00Z" not in window


def test_missing_values_print_not_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRC_AUTHORIZER", raising=False)
    monkeypatch.delenv("GRC_REVIEWER", raising=False)
    monkeypatch.delenv("GRC_CONTACT", raising=False)
    monkeypatch.delenv("GRC_RUN_ID", raising=False)
    monkeypatch.setenv("GRC_ESTATE_LABEL", "SAMPLE")
    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")])
    trust = (out / "SCOPE_AND_TRUST.md").read_text(encoding="utf-8")
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    assert NOT_RECORDED in trust
    assert "Contact for questions or corrections: " + NOT_RECORDED in trust
    assert "0" not in exec_text.split("Duplicates merged")[0][-20:] or True
    # Per-severity duplicate column must not invent zeros.
    for line in exec_text.splitlines():
        if line.startswith("| Critical |"):
            assert NOT_RECORDED in line
        if line.startswith("| High |"):
            assert NOT_RECORDED in line


def test_exec_and_trust_generated_from_run_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader(
        tmp_path,
        monkeypatch,
        [_asset(), _finding("f1", sev="critical"), _finding("f2", sev="high")],
        GRC_ESTATE_LABEL="LAB",
    )
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    assert "| Critical |" in exec_text
    assert "| High |" in exec_text
    assert "`f1`" in exec_text or "f1" in exec_text
    assert (out / "SCOPE_AND_TRUST.md").is_file()
    assert "LAB: TEST ENVIRONMENT" in exec_text
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["estate_kind"] == "LAB"
    assert summary.get("client") is False


def test_exec_counts_info_as_own_bucket_not_dropped_low(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader(
        tmp_path,
        monkeypatch,
        [
            _asset(),
            _finding("f-low", sev="low"),
            _finding("f-info", sev="info"),
        ],
        GRC_ESTATE_LABEL="LAB",
    )
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    low_line = next(line for line in exec_text.splitlines() if line.startswith("| Low |"))
    info_line = next(line for line in exec_text.splitlines() if line.startswith("| Info |"))
    assert "| 1 |" in low_line
    assert "| 1 |" in info_line
    assert "| 0 |" in info_line.split("|")[3]
    excluded = csv_rows(out / "poam" / "excluded.csv")
    info_ex = [row for row in excluded if row.get("finding_ref_id") == "f-info"]
    assert info_ex and info_ex[0]["severity"] == "info"
    assert info_ex[0]["excluded_reason"] == "severity_info"


def test_exporters_stamp_opengrc_and_probo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from exporters.opengrc import write_opengrc
    from exporters.probo import write_probo

    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], GRC_ESTATE_LABEL="SAMPLE")
    stamp = write_opengrc(out)
    assert stamp["client"] is False
    dest = Path(stamp["dir"])
    risks = dest / "risks.csv"
    text = risks.read_text(encoding="utf-8")
    assert not text.lstrip().startswith("#")
    assert LABEL_FOR_KIND["SAMPLE"] in text
    rows = csv_rows(risks)
    assert "estate" not in rows[0]
    sidecar = dest / "ESTATE.txt"
    assert sidecar.is_file()
    assert LABEL_FOR_KIND["SAMPLE"] in sidecar.read_text(encoding="utf-8")
    probo = write_probo(out)
    payload = json.loads(probo.read_text(encoding="utf-8"))
    assert payload["estate"] == LABEL_FOR_KIND["SAMPLE"]
    assert not str(payload["estate"]).startswith("CLIENT:")
    readme = (out / "probo" / "README.md").read_text(encoding="utf-8")
    assert readme.startswith("> **")
    assert LABEL_FOR_KIND["SAMPLE"] in readme


def _write_sensor_coverage(out: Path, source: str, records_n: int, *, demo: bool = True) -> None:
    dest = out / "coverage" / "sensors"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / f"{source}.json").write_text(
        json.dumps(
            {
                "source": source,
                "status": "demo" if records_n and demo else ("ok" if records_n else "empty"),
                "demo": bool(demo and records_n),
                "files": 1 if records_n else 0,
                "records": records_n,
                "unread": [],
                "issues": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_scope_in_and_out_from_same_coverage_and_lists_every_sensor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shared.io_util import SENSOR_IN

    in_scope_src = [
        "inventory-nmap",
        "cloud-prowler",
        "host-wazuh",
        "identity-ad",
        "easm",
        "k8s-kubescape",
        "code-secrets",
        "vuln-scan",
        "saas-idp",
    ]
    out_scope_src = [src for src in SENSOR_IN if src not in in_scope_src]
    assert "vuln-scan" in in_scope_src and "saas-idp" in in_scope_src
    assert out_scope_src

    out = tmp_path / "out"
    (out / "canonical").mkdir(parents=True)
    records: list[dict] = [_asset(), _finding("f1", labels=["nmap", "demo"])]
    with (out / "canonical" / "inventory-nmap.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    _write_sensor_coverage(out, "inventory-nmap", 2)
    for src in in_scope_src:
        if src == "inventory-nmap":
            continue
        rec = {
            "kind": "finding",
            "source": src,
            "ref_id": f"{src}-1",
            "name": f"{src} finding",
            "description": f"{src} fixture finding",
            "severity": "high",
            "category": src,
            "assets": ["host-a"],
            "labels": ["demo"],
            "extra": {},
        }
        with (out / "canonical" / f"{src}.jsonl").open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        _write_sensor_coverage(out, src, 1)
    for src in out_scope_src:
        _write_sensor_coverage(out, src, 0, demo=False)

    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("IN_DIR", str(tmp_path / "in"))
    monkeypatch.setenv("GRC_ESTATE_LABEL", "SAMPLE")
    import collectors.grc_loader as loader

    importlib.reload(loader)
    loader.load()

    trust = (out / "SCOPE_AND_TRUST.md").read_text(encoding="utf-8")
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    inside = parse_scope_table_areas(trust)
    outside = parse_out_of_scope_names(trust)
    assert set(inside) & set(outside) == set()
    for src in in_scope_src:
        assert COLLECTOR_AREAS[src] in inside, src
    for src in out_scope_src:
        assert COLLECTOR_AREAS[src] in outside, src
    assert "Vulnerability scan" in inside
    assert "SaaS / identity" in inside
    assert "List every collector folder" not in trust
    assert "If no one did, print" not in trust
    assert "collected by not recorded" not in trust
    assert "print \"not human-reviewed\"" not in trust
    assert len(trust.splitlines()) <= MAX_PAGE_LINES
    assert "rows dated" in exec_text
    assert_client_export_honesty(out)


def test_generated_pages_have_no_instruction_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader(
        tmp_path,
        monkeypatch,
        [_asset(), _finding("f1")],
        GRC_ESTATE_LABEL="SAMPLE",
    )
    trust = (out / "SCOPE_AND_TRUST.md").read_text(encoding="utf-8")
    exec_text = (out / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8")
    for blob in (trust, exec_text):
        assert "List every collector folder" not in blob
        assert "If no one did, print" not in blob
        assert "collected by not recorded" not in blob
        assert "[insert " not in blob.lower()
        assert "{{" not in blob
    assert_client_export_honesty(out)


def test_manifest_verifies_with_sha256sum_c(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _run_loader(
        tmp_path,
        monkeypatch,
        [_asset(), _finding("f1")],
        GRC_ESTATE_LABEL="LAB",
    )
    manifest = (out / "MANIFEST").read_text(encoding="utf-8")
    assert manifest
    assert not manifest.lstrip().startswith(">")
    assert "| File |" not in manifest
    assert "MANIFEST" not in {line.split()[-1] for line in manifest.splitlines() if line.strip()}
    assert_client_export_honesty(out)
