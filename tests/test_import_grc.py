from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_import_grc_help_exits_0() -> None:
    from dropbox.import_grc import main

    with pytest.raises(SystemExit) as ei:
        main(["--help"])
    assert ei.value.code == 0


def test_import_grc_dry_run_no_http(monkeypatch) -> None:
    import dropbox.import_grc as ig

    called: list[str] = []
    monkeypatch.setattr(
        "push.ciso_import.urlopen",
        lambda *a, **k: called.append("http") or (_ for _ in ()).throw(AssertionError("no HTTP")),
    )
    rec = ig.run("all", live=False)
    assert rec["dry_run"] is True
    assert rec.get("http") is False
    assert rec["ciso"]["http"] is False
    assert rec["opengrc"]["http"] is False
    assert rec["probo"]["http"] is False
    assert rec["client_facing_ready"] is False
    assert rec["riskready"]["WRAP_DEAD"] is True
    assert "/api/risks" not in rec["opengrc"]["endpoint"]
    assert not rec["probo"]["endpoint"].startswith("http://192.168.10.130")
    assert rec["probo"]["endpoint"].startswith("(set PROBO_URL") or rec["probo"]["endpoint"].endswith("/graphql")
    assert called == []
    og = ROOT / "out" / "opengrc" / "assets.csv"
    assert og.is_file()
    text = og.read_text(encoding="utf-8")
    assert "name,description,asset_tag" in text
    assert (ROOT / "out" / "opengrc" / "risks.csv").is_file()
    assert "title,description,mitigation" in (ROOT / "out" / "opengrc" / "risks.csv").read_text(encoding="utf-8")
    assert (ROOT / "out" / "opengrc" / "MAPPING.md").is_file()
    assert (ROOT / "out" / "probo" / "findings_plan.json").is_file()
    plan = (ROOT / "out" / "probo" / "findings_plan.json").read_text(encoding="utf-8")
    assert "addFinding" in plan
    assert "No createRisk" in plan


def test_import_grc_live_and_dry_run_together_exit_2() -> None:
    from dropbox.import_grc import main

    assert main(["--target", "ciso", "--live", "--dry-run"]) == 2


def test_import_grc_live_without_gate_exit_2() -> None:
    from dropbox.import_grc import main

    assert main(["--target", "ciso", "--live"]) == 2
    assert main(["--target", "opengrc", "--live"]) == 2
    assert main(["--target", "probo", "--live"]) == 2


def test_import_grc_riskready_wrap_dead() -> None:
    from dropbox.import_grc import main

    assert main(["--target", "riskready"]) == 2
    assert main(["--target", "riskready", "--dry-run"]) == 2


def test_import_grc_source_has_no_api_risks_post() -> None:
    ciso = (ROOT / "push" / "ciso_import.py").read_text(encoding="utf-8")
    ig = (ROOT / "dropbox" / "import_grc.py").read_text(encoding="utf-8")
    og = (ROOT / "push" / "opengrc_import.py").read_text(encoding="utf-8")
    probo = (ROOT / "push" / "probo_import.py").read_text(encoding="utf-8")
    assert "/api/risks" not in ciso
    assert "/api/importer/" in ciso
    assert "urlopen" not in ig
    assert "urlopen" not in og
    assert "urlopen" not in probo
    assert "createRisk" not in probo or "No createRisk" in probo
    assert "no_post" in og.lower() or "skipped" in og.lower()


def test_ciso_live_posts_assets_evidences_only(tmp_path, monkeypatch) -> None:
    from push import ciso_import

    gate = ROOT / "push" / "GATE_CISO"
    posted: list[str] = []

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

    def _urlopen(req, timeout=20):
        posted.append(req.full_url)
        assert "/api/risks" not in req.full_url
        assert "/api/importer/" in req.full_url
        return _Resp()

    gate.write_text("lab-gate\n", encoding="utf-8")
    monkeypatch.setenv("CISO_TOKEN", "lab-not-a-secret")
    monkeypatch.setenv("CISO_URL", "http://127.0.0.1:8000")
    monkeypatch.setattr(ciso_import, "urlopen", _urlopen)
    try:
        rec = ciso_import.live()
    finally:
        if gate.is_file():
            gate.unlink()
    assert rec["posted"] == ["assets.csv", "evidences.csv"]
    assert rec["http"] is True
    assert all("/api/importer/" in u for u in posted)
    assert not any("/api/risks" in u for u in posted)


def test_realish_infeed_not_demo_fallback(tmp_path, monkeypatch) -> None:
    """Files in in/nmap win over fixtures/demo; unique host is from realish fixture."""
    from collectors.inventory_nmap import parse_files
    from shared.io_util import discover_input_files

    src = ROOT / "tests" / "fixtures_realish" / "nmap" / "realish.xml"
    pack = tmp_path / "pack"
    (pack / "in" / "nmap").mkdir(parents=True)
    (pack / "fixtures" / "demo" / "nmap").mkdir(parents=True)
    (pack / "in" / "nmap" / "realish.xml").write_bytes(src.read_bytes())
    (pack / "fixtures" / "demo" / "nmap" / "scan.xml").write_text(
        '<?xml version="1.0"?><nmaprun></nmaprun>\n', encoding="utf-8"
    )
    monkeypatch.setenv("PACK_ROOT", str(pack))
    files = discover_input_files("nmap")
    assert [p.name for p in files] == ["realish.xml"]
    recs = parse_files(files)
    names = " ".join(r.name for r in recs)
    assert "realish-only.lab" in names
    assert "dc01.corp.local" not in names


def test_opengrc_writer_from_rows() -> None:
    from push import opengrc_import

    rows = [
        {"kind": "asset", "name": "realish-web", "description": "lab asset", "ref_id": "A-REALISH"},
        {
            "kind": "finding",
            "name": "Cleartext HTTP",
            "description": "http on 80",
            "ref_id": "F-1",
            "recommended_action": "Serve TLS",
        },
    ]
    written = opengrc_import.write_files(rows)
    assets = Path(written["assets_csv"]).read_text(encoding="utf-8")
    risks = Path(written["risks_csv"]).read_text(encoding="utf-8")
    assert "realish-web" in assets
    assert "A-REALISH" in assets
    assert "Cleartext HTTP" in risks
    assert "Serve TLS" in risks
    assert written["asset_rows"] == 1
    assert written["risk_rows"] == 1


def test_opengrc_live_with_gate_still_no_post(monkeypatch) -> None:
    from push import opengrc_import

    gate = ROOT / "push" / "GATE_OPENGRC"
    monkeypatch.setenv("OPENGRC_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("OPENGRC_TOKEN", "lab-not-a-secret")
    monkeypatch.setattr(
        "push.opengrc_import.urlopen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no HTTP")),
        raising=False,
    )
    gate.write_text("lab-gate\n", encoding="utf-8")
    try:
        rec = opengrc_import.live()
    finally:
        if gate.is_file():
            gate.unlink()
    assert rec["http"] is False
    assert rec["live_skipped"] == "opengrc_schema_unconfirmed_no_post"
    assert "/api/risks" not in rec["endpoint"]


def test_probo_live_with_gate_still_no_http(monkeypatch) -> None:
    from push import probo_import

    gate = ROOT / "push" / "GATE_PROBO"
    monkeypatch.setenv("PROBO_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("PROBO_TOKEN", "lab-not-a-secret")
    gate.write_text("lab-gate\n", encoding="utf-8")
    try:
        rec = probo_import.live()
    finally:
        if gate.is_file():
            gate.unlink()
    assert rec["http"] is False
    assert rec["live_skipped"] == "no_probo_on_this_lab_no_createrisk"
    assert not rec["endpoint"].startswith("http://192.168.10.130")


def test_probo_live_refuses_office_lan_url(monkeypatch) -> None:
    from dropbox.import_grc import main

    gate = ROOT / "push" / "GATE_PROBO"
    monkeypatch.setenv("PROBO_URL", "http://192.168.10.130:8080")
    monkeypatch.setenv("PROBO_TOKEN", "lab-not-a-secret")
    gate.write_text("lab-gate\n", encoding="utf-8")
    try:
        assert main(["--target", "probo", "--live"]) == 2
    finally:
        if gate.is_file():
            gate.unlink()


def test_gate_examples_and_gitignore() -> None:
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for name in ("CISO", "OPENGRC", "PROBO"):
        assert (ROOT / "push" / f"GATE_{name}.example").is_file()
        assert f"push/GATE_{name}" in gi


def test_import_opengrc_doc() -> None:
    text = (ROOT / "docs" / "IMPORT_OPENGRC.md").read_text(encoding="utf-8")
    assert "assets.csv" in text
    assert "risks.csv" in text
    assert "GATE_OPENGRC" in text
    assert "Data Manager" in text


def test_real_scan_drop_doc() -> None:
    text = (ROOT / "docs" / "REAL_SCAN_DROP.md").read_text(encoding="utf-8")
    assert "in/nmap" in text
    assert "grc_loader.py" in text
    assert "import_grc" in text
    assert "192.168.10.0/24" in text
