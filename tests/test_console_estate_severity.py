"""Console estate_kind honesty + POA&M severity strip (cold-review-5).

SAMPLE/CLIENT banners come from summary.estate_kind / estate, not the
lab/sample/demo flags. Severity KPIs count open poam.csv rows, not
findings.csv. LAB/SAMPLE/DEMO is never client KEEP. Never POST /api/risks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from product.server import derive_honesty, estate, severity_from_open_poam
from shared.estate_pages import LABEL_FOR_KIND

POAM_HEADER = "weakness,asset,severity,framework_refs,recommended_fix,owner,due,status"
FINDINGS_H = "ref_id,name,description,severity,status,filtering_labels"


def _write_summary(out: Path, **fields) -> None:
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "canonical": 4,
        "assets": 4,
        "findings": 2,
        "poam": 4,
        "demo": False,
        "lab": False,
        "sample": False,
        "client": False,
    }
    payload.update(fields)
    (out / "summary.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_csvs(out: Path, *, findings: list[str], poam: list[str]) -> None:
    ciso = out / "ciso-assistant"
    ciso.mkdir(parents=True, exist_ok=True)
    (ciso / "findings.csv").write_text(
        FINDINGS_H + "\n" + "\n".join(findings) + "\n", encoding="utf-8"
    )
    dest = out / "poam"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "poam.csv").write_text(
        POAM_HEADER + "\n" + "\n".join(poam) + "\n", encoding="utf-8"
    )


@pytest.mark.parametrize(
    ("kind", "banner"),
    [
        ("SAMPLE", LABEL_FOR_KIND["SAMPLE"]),
        ("DEMO", LABEL_FOR_KIND["DEMO"]),
        ("LAB", LABEL_FOR_KIND["LAB"]),
        ("CLIENT", "CLIENT: Acme Corp"),
    ],
)
def test_honesty_uses_estate_kind_and_banner_verbatim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    banner: str,
) -> None:
    out = tmp_path / "out"
    _write_summary(out, estate_kind=kind, estate=banner)
    monkeypatch.setenv("OUT_DIR", str(out))
    honesty = derive_honesty(out, json.loads((out / "summary.json").read_text()))
    data = estate()
    assert honesty["honesty_label"] == banner
    assert honesty["estate_kind"] == kind
    assert data["honesty_label"] == banner
    assert data["estate_kind"] == kind
    assert data["client"] is False
    if kind == "SAMPLE":
        assert data["sample"] is True
        assert data["lab"] is False
    elif kind == "LAB":
        assert data["lab"] is True
        assert data["sample"] is False
    elif kind == "DEMO":
        assert data["demo"] is True
        assert data["lab"] is False
        assert data["sample"] is False
    elif kind == "CLIENT":
        assert data["lab"] is False
        assert data["sample"] is False
        assert data["demo"] is False
        assert "not a client estate" not in data["honesty_label"]


def test_sample_banner_without_sample_flag_is_sample_not_generic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    banner = LABEL_FOR_KIND["SAMPLE"]
    _write_summary(
        out,
        estate_kind="SAMPLE",
        estate=banner,
        sample=False,
        demo=False,
        lab=False,
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["sample"] is True
    assert data["estate_kind"] == "SAMPLE"
    assert data["honesty_label"] == banner
    assert data["honesty_label"] != "not a client estate"
    assert data["client"] is False


def test_client_kind_without_flags_shows_client_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    banner = "CLIENT: Acme Corp"
    _write_summary(out, estate_kind="CLIENT", estate=banner)
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["honesty_label"] == banner
    assert data["estate_kind"] == "CLIENT"
    assert data["client"] is False
    assert data["sample"] is False
    assert data["lab"] is False


def test_lab_sample_demo_cannot_become_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _write_summary(
        out,
        estate_kind="CLIENT",
        estate="CLIENT: Acme Corp",
        demo=True,
        lab=True,
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    assert data["client"] is False
    assert data["estate_kind"] != "CLIENT"
    assert not data["honesty_label"].startswith("CLIENT:")


def test_severity_strip_counts_open_poam_not_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    _write_summary(
        out,
        estate_kind="SAMPLE",
        estate=LABEL_FOR_KIND["SAMPLE"],
        findings=2,
        poam=5,
    )
    _write_csvs(
        out,
        findings=[
            "F-1,one,d,critical,identified,cpg_2_W",
            "F-2,two,d,high,identified,cpg_2_W",
        ],
        poam=[
            "Weak A,host-a,critical,csf_PR,fix,,,open",
            "Weak B,host-b,critical,csf_PR,fix,,,open",
            "Weak C,host-c,high,csf_PR,fix,,,open",
            "Weak D,host-d,medium,csf_PR,fix,,,open",
            "Weak E,host-e,high,csf_PR,already,soc,2026-09-01,closed",
        ],
    )
    monkeypatch.setenv("OUT_DIR", str(out))
    data = estate()
    # findings.csv would be 1 critical / 1 high. Open POA&M is 2/1/1/0.
    assert data["severity"] == {"critical": 2, "high": 1, "medium": 1, "low": 0}
    assert sum(data["severity"].values()) == 4
    assert data["poam"]["open"] == 4
    assert data["summary"]["findings"] == 2
    assert data["client"] is False
    assert data["honesty_label"] == LABEL_FOR_KIND["SAMPLE"]


def test_severity_from_open_poam_ignores_closed() -> None:
    rows = [
        {"severity": "critical", "status": "open", "open": True},
        {"severity": "critical", "status": "closed", "open": False},
        {"severity": "high", "status": "open", "open": True},
    ]
    assert severity_from_open_poam(rows) == {
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 0,
    }
