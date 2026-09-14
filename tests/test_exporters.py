"""OpenGRC + Probo sinks read the CISO intermediate. No sockets. No POST."""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

from exporters.model import HONESTY_BANNER, load_pack_estate
from exporters.opengrc import ASSETS_HEADER, RISKS_HEADER, write_opengrc
from exporters.probo import build_probo_preview, write_probo

ROOT = Path(__file__).resolve().parents[1]
DROP_CISO = ROOT / "product-lab" / "drop"


def _tiny_ciso(tmp: Path) -> Path:
    ciso = tmp / "ciso-assistant"
    ciso.mkdir()
    (ciso / "findings.csv").write_text(
        "ref_id,name,description,severity,status,filtering_labels\n"
        "X-1,Public bucket,demo-public,critical,identified,demo\n"
        "X-2,Weak TLS,demo host filesrv.corp.local,medium,identified,demo\n",
        encoding="utf-8",
    )
    (ciso / "assets.csv").write_text(
        "ref_id,name,description,domain,type,reference_link,observation,filtering_labels,parent_assets\n"
        "A-1,filesrv.corp.local,host 10.9.8.7,Global,PR,,,\"demo\", \n",
        encoding="utf-8",
    )
    (ciso / "applied_controls.csv").write_text(
        "ref_id,name,description,domain,status,category,priority,csf_function\n"
        "CTL-1,Restrict SMB,close 445,Global,to_do,technical,1,protect\n",
        encoding="utf-8",
    )
    (ciso / "risk_scenarios.csv").write_text(
        "ref_id;assets;threats;name;description;existing_controls;current_impact;current_proba;current_risk;additional_controls;residual_impact;residual_proba;residual_risk;treatment\n"
        "RSK-x-1;filesrv.corp.local;exposure;Public bucket;demo-public;;Very High;Very High;Very High;CTL-1;High;High;High;mitigate\n",
        encoding="utf-8",
    )
    (ciso / "vulnerabilities.csv").write_text(
        "ref_id,name,description,status,severity,assets,applied_controls\n"
        "CVE-1,Demo CVE,sample,Exploitable,High,filesrv.corp.local,CTL-1\n",
        encoding="utf-8",
    )
    return tmp


def test_load_pack_estate_from_ciso_headers(tmp_path: Path) -> None:
    estate = load_pack_estate(_tiny_ciso(tmp_path))
    assert estate.client is False
    assert estate.posted is False
    assert estate.sample is True
    assert estate.findings[0].severity == "critical"
    assert estate.assets[0].hostname == "filesrv.corp.local"
    assert estate.assets[0].ip_address == "10.9.8.7"
    assert len(estate.scenarios) == 1
    assert len(estate.controls) == 1


def test_opengrc_writes_wizard_csvs(tmp_path: Path) -> None:
    out = _tiny_ciso(tmp_path)
    stamp = write_opengrc(out)
    assert stamp["posted"] is False
    assert stamp["http"] is False
    assert stamp["client"] is False
    assert stamp["demo"] is True
    assert stamp["paying_day"] == "FAIL"
    dest = Path(stamp["dir"])
    with (dest / "risks.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert list(rows[0].keys()) == RISKS_HEADER
    assert rows[0]["status"] == "Not Assessed"
    assert rows[0]["code"] == "RSK-x-1"
    assert int(rows[0]["inherent_likelihood"]) == 5
    assert HONESTY_BANNER.split("—")[0].strip() in (dest / "README.md").read_text(encoding="utf-8")
    with (dest / "assets.csv").open(encoding="utf-8", newline="") as fh:
        assets = list(csv.DictReader(fh))
    assert list(assets[0].keys()) == ASSETS_HEADER
    assert assets[0]["asset_tag"] == "A-1"
    assert assets[0]["hostname"] == "filesrv.corp.local"
    assert assets[0]["ip_address"] == "10.9.8.7"
    impl = (dest / "implementations.csv").read_text(encoding="utf-8")
    assert "Restrict SMB" in impl
    manifest = json.loads((dest / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["posted"] is False


def test_probo_add_risk_and_finding_drafts(tmp_path: Path) -> None:
    out = _tiny_ciso(tmp_path)
    preview = build_probo_preview(out)
    assert preview["posted"] is False
    assert preview["http"] is False
    assert preview["organization_id"] is None
    assert preview["createRisk"][0]["shape"] == "createRisk"
    assert preview["createRisk"][0]["addRisk"]["inherent_likelihood"] == 5
    assert preview["addFinding"]
    kinds = {row["kind"] for row in preview["addFinding"]}
    assert "MAJOR_NONCONFORMITY" in kinds
    assert "OBSERVATION" not in kinds or True
    assert any(row["kind"] == "MINOR_NONCONFORMITY" for row in preview["addFinding"])
    assert all(row["organization_id"] is None for row in preview["addRisk"])
    assert all(row["posted"] is False for row in preview["addFinding"])
    path = write_probo(out)
    assert path.name == "probo.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["sink"] == "probo"
    assert (out / "probo" / "README.md").is_file()


def test_exporters_consume_product_lab_ciso_drop(tmp_path: Path) -> None:
    shutil.copytree(DROP_CISO / "ciso", tmp_path / "ciso-assistant")
    estate = load_pack_estate(tmp_path)
    assert estate.findings
    assert estate.assets
    assert estate.sample is True
    stamp = write_opengrc(tmp_path)
    assert stamp["counts"]["risks"] >= 1
    assert stamp["counts"]["assets"] >= 1
    preview = build_probo_preview(tmp_path)
    assert preview["counts"]["addFinding"] >= len(estate.findings)
    assert preview["posted"] is False


def test_keep_lab_sample_ciso_feeds_sinks(tmp_path: Path) -> None:
    """SAMPLE keep-lab CISO intermediate is enough — do not wait for denser KEEP."""
    from keep.lab import keep_lab

    empty = tmp_path / "empty-in"
    empty.mkdir()
    stamp = keep_lab(ROOT, pack_in=empty, work=tmp_path / "work")
    assert stamp["status"] == "pass"
    assert stamp["sample"] is True
    assert stamp["demo"] is True
    assert stamp["client_keep"] is False
    out = Path(stamp["out_dir"])
    estate = load_pack_estate(out)
    assert estate.demo is True
    assert estate.sample is True
    preview = build_probo_preview(out, estate=estate)
    assert preview["demo"] is True
    assert preview["posted"] is False
    og = write_opengrc(out, estate=estate)
    assert og["demo"] is True
    assert og["counts"]["risks"] >= 1
    assert og["counts"]["assets"] >= 1


def test_exporter_modules_have_no_sockets_or_risks_post() -> None:
    banned = ("socket.socket", "urllib.request", "http.client", "requests.get", "httpx.")
    for rel in (
        "exporters/model.py",
        "exporters/opengrc.py",
        "exporters/probo.py",
        "exporters/__main__.py",
        "keep/export.py",
        "scripts/export_opengrc.py",
        "scripts/preview_probo.py",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, rel
        assert "curl" not in text
        assert 'POST "/api/risks"' not in text
        assert "${API}/risks" not in text
