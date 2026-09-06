from __future__ import annotations

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_factory_creates_slug_not_client_facing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    from dropbox.new_engagement import new_engagement

    manifest = new_engagement("litware-lab", ROOT / "dropbox" / "SCOPE.example.yaml")
    dest = tmp_path / "litware-lab"
    assert dest.is_dir()
    assert (dest / "SCOPE.yaml").is_file()
    assert (dest / "MANIFEST.json").is_file()
    assert (dest / "out" / "ciso-assistant" / "assets.csv").is_file()
    assert (dest / "out" / "poam" / "poam.csv").is_file()
    assert (dest / "out" / "quote" / "quote.csv").is_file()
    quote = (dest / "out" / "quote" / "quote.csv").read_text(encoding="utf-8")
    assert "draft" in quote
    assert "$" not in quote
    assert manifest["client_facing_ready"] is False
    assert manifest["blocked_by"]
    data = json.loads((dest / "MANIFEST.json").read_text(encoding="utf-8"))
    assert data["client_facing_ready"] is False
    exec_md = (dest / "EXECUTIVE.md").read_text(encoding="utf-8")
    assert "evidence_files:" in exec_md
    assert "findings:" in exec_md
    assert "not a customer" in exec_md.lower() or "fixture" in exec_md.lower()


def test_other_client_discover_not_packaged_as_slug(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    orch = ROOT / "dropbox" / "out"
    orch.mkdir(parents=True, exist_ok=True)
    leftover = orch / "discover.json"
    prior = leftover.read_text(encoding="utf-8") if leftover.is_file() else None
    leftover.write_text(
        json.dumps({"client": "Other Corp LLC", "label": "live-byo", "hosts": [{"host": "evil.example", "live": True}]}),
        encoding="utf-8",
    )
    try:
        from dropbox.new_engagement import new_engagement

        manifest = new_engagement("litware-lab", ROOT / "dropbox" / "SCOPE.example.yaml")
        dest = tmp_path / "litware-lab"
        assert manifest["leftover_discover_brake"] == "discover_client_mismatch"
        assert manifest["client_facing_ready"] is False
        assert not (dest / "out" / "orchestrator" / "discover.json").is_file()
    finally:
        if prior is None:
            leftover.unlink(missing_ok=True)
        else:
            leftover.write_text(prior, encoding="utf-8")


def test_zip_excludes_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    from dropbox.new_engagement import new_engagement
    from dropbox.package_engagement import package_slug

    new_engagement("litware-lab", ROOT / "dropbox" / "SCOPE.example.yaml")
    dest = tmp_path / "litware-lab"
    (dest / ".env").write_text("CISO_TOKEN=super-secret\n", encoding="utf-8")
    (dest / "notes.env").write_text("x=1\n", encoding="utf-8")
    zpath = package_slug("litware-lab")
    assert zpath.is_file()
    names = zipfile.ZipFile(zpath).namelist()
    assert not any(n.endswith(".env") or n.endswith("/.env") or n.split("/")[-1] == ".env" for n in names)
    assert not any("notes.env" in n for n in names)
    assert any(n.endswith("MANIFEST.json") for n in names)


def test_riskready_push_still_wrap_dead() -> None:
    text = (ROOT / "push_riskready.ps1").read_text(encoding="utf-8")
    assert "WRAP_DEAD" in text
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#")).lower()
    assert "/api/itsm" not in code
    assert "curl" not in code


def test_engagement_no_api_risks_post() -> None:
    for path in ROOT.glob("dropbox/*.py"):
        blob = path.read_text(encoding="utf-8")
        assert "POST /api/risks" not in blob


def test_archive_out_copies_other_client_skips_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    dest = tmp_path / "dropbox-out"
    dest.mkdir()
    (dest / "discover.json").write_text(
        json.dumps({"client": "Other Corp LLC", "label": "fixture", "hosts": []}),
        encoding="utf-8",
    )
    (dest / ".env").write_text("CISO_TOKEN=super-secret\n", encoding="utf-8")
    from dropbox.archive_out import archive_dropbox_out

    rec = archive_dropbox_out(dest, current_client="Litware Lab LLC")
    assert rec["archived"] is True
    assert rec["leftover_client"] == "Other Corp LLC"
    assert rec["client_facing_ready"] is False
    archive = Path(rec["path"])
    assert (archive / "discover.json").is_file()
    assert not (archive / ".env").is_file()
    leftover = json.loads((archive / "discover.json").read_text(encoding="utf-8"))
    assert leftover["client"] == "Other Corp LLC"
    same = archive_dropbox_out(dest, current_client="Other Corp LLC")
    assert same["archived"] is False
    assert same["reason"] == "same_client"



