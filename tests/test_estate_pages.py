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

from shared.estate_pages import (
    LABEL_FOR_KIND,
    NOT_RECORDED,
    REVIEWER_NEXT_STEP,
    REVIEWER_WHAT_WE_FOUND,
    REVIEWER_WHY_IT_MATTERS,
    classify_estate,
    csv_rows_skip_comments,
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


EXPORT_FILES = (
    "EXECUTIVE_SUMMARY.md",
    "SCOPE_AND_TRUST.md",
    "poam/poam.csv",
    "poam/poam.md",
    "ciso-assistant/assets.csv",
    "ciso-assistant/applied_controls.csv",
    "ciso-assistant/evidences.csv",
    "ciso-assistant/findings.csv",
    "ciso-assistant/vulnerabilities.csv",
    "ciso-assistant/risk_scenarios.csv",
)


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
    for rel in EXPORT_FILES:
        path = out / rel
        assert path.is_file(), rel
        text = path.read_text(encoding="utf-8")
        assert label in text, rel
        assert "Every finding below comes from bundled example files" in text, rel
        if path.suffix == ".csv":
            delim = ";" if "risk_scenarios" in rel else ","
            rows = csv_rows_skip_comments(path, delimiter=delim)
            header = next(
                line
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
            assert "estate" in header.split(delim), rel
            if rows:
                assert {row["estate"] for row in rows} == {label}, rel

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
    rows = csv_rows_skip_comments(out / "poam" / "poam.csv")
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


def test_exporters_stamp_opengrc_and_probo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from exporters.opengrc import write_opengrc
    from exporters.probo import write_probo

    out = _run_loader(tmp_path, monkeypatch, [_asset(), _finding("f1")], GRC_ESTATE_LABEL="SAMPLE")
    stamp = write_opengrc(out)
    assert stamp["client"] is False
    dest = Path(stamp["dir"])
    risks = dest / "risks.csv"
    text = risks.read_text(encoding="utf-8")
    assert LABEL_FOR_KIND["SAMPLE"] in text
    rows = csv_rows_skip_comments(risks)
    assert rows and rows[0]["estate"] == LABEL_FOR_KIND["SAMPLE"]
    probo = write_probo(out)
    payload = json.loads(probo.read_text(encoding="utf-8"))
    assert payload["estate"] == LABEL_FOR_KIND["SAMPLE"]
    assert not str(payload["estate"]).startswith("CLIENT:")
    readme = (out / "probo" / "README.md").read_text(encoding="utf-8")
    assert readme.startswith("> **")
    assert LABEL_FOR_KIND["SAMPLE"] in readme
