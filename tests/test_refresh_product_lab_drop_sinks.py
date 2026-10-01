"""refresh_product_lab_drop_sinks sync_from_out / --from-out copies host-lab out/.

An ignore --from-out mutant used to pass the suite because nothing asserted
the CLI dispatch. These tests write a temp drop only — they do not touch
product-lab/drop. DEMO/SAMPLE fixtures. Never POST /api/risks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.refresh_product_lab_drop_sinks import (
    CISO_CSVS,
    MANIFEST_ROWS,
    main,
    sync_from_out,
)


def _seed_out(src_out: Path) -> None:
    ciso = src_out / "ciso-assistant"
    poam = src_out / "poam"
    ciso.mkdir(parents=True)
    poam.mkdir(parents=True)
    for name in CISO_CSVS:
        body = "ref_id,name\nFIND-1,one\n" if name == "findings.csv" else "ref_id,name\n"
        (ciso / name).write_text(body, encoding="utf-8")
    (ciso / "ESTATE.txt").write_text("DEMO: NOT A CLIENT\n", encoding="utf-8")
    (poam / "poam.csv").write_text("poam_id\nEGP-1\n", encoding="utf-8")
    (poam / "excluded.csv").write_text(
        "id,excluded_reason\nNMAP-filesrv-corp-local-445-tcp,superseded_by_specific\n",
        encoding="utf-8",
    )
    (poam / "poam_fedramp.csv").write_text("POAM ID\nEGP-1\n", encoding="utf-8")
    (poam / "poam-ledger.json").write_text('{"version": 1, "items": {}}\n', encoding="utf-8")
    (poam / "poam.md").write_text("# POA&M\n", encoding="utf-8")
    (poam / "ESTATE.txt").write_text("DEMO: NOT A CLIENT\n", encoding="utf-8")
    (src_out / "EXECUTIVE_SUMMARY.md").write_text("# exec\n", encoding="utf-8")
    (src_out / "SCOPE_AND_TRUST.md").write_text("# scope\n", encoding="utf-8")


def _stub_sinks(monkeypatch: pytest.MonkeyPatch, dest: Path) -> Path:
    """Keep main() off the real drop and off live exporters."""
    import scripts.refresh_product_lab_drop_sinks as mod

    def fake_opengrc(drop: Path, estate=None):
        og = Path(drop) / "opengrc"
        og.mkdir(parents=True, exist_ok=True)
        for name in ("risks.csv", "assets.csv", "implementations.csv"):
            (og / name).write_text("code,name\n", encoding="utf-8")
        return {"counts": {"risks": 0, "assets": 0, "implementations": 0}}

    probo = dest / "import_preview" / "probo.json"
    probo.parent.mkdir(parents=True, exist_ok=True)
    probo.write_text(json.dumps({"counts": {"addFinding": 1}}), encoding="utf-8")

    monkeypatch.setattr(mod, "DROP", dest)
    monkeypatch.setattr(mod, "load_pack_estate", lambda drop: object())
    monkeypatch.setattr(mod, "write_opengrc", fake_opengrc)
    monkeypatch.setattr(mod, "write_probo", lambda drop, estate=None: probo)
    monkeypatch.setattr(mod, "_write_manifest", lambda *args, **kwargs: None)
    monkeypatch.setattr(mod, "_write_readme", lambda *args, **kwargs: None)
    return probo


def test_sync_from_out_copies_ciso_poam_and_estate_pages(tmp_path: Path) -> None:
    src_out = tmp_path / "out"
    dest = tmp_path / "drop"
    _seed_out(src_out)

    sync_from_out(src_out, dest)

    assert (dest / "ciso" / "findings.csv").read_text(encoding="utf-8").startswith("ref_id")
    assert "FIND-1" in (dest / "ciso" / "findings.csv").read_text(encoding="utf-8")
    assert (dest / "ciso" / "ESTATE.txt").read_text(encoding="utf-8").startswith("DEMO")
    assert (dest / "poam" / "poam.csv").read_text(encoding="utf-8") == "poam_id\nEGP-1\n"
    assert "superseded_by_specific" in (dest / "poam" / "excluded.csv").read_text(encoding="utf-8")
    assert (dest / "poam" / "poam_fedramp.csv").is_file()
    assert (dest / "poam" / "poam-ledger.json").is_file()
    assert (dest / "EXECUTIVE_SUMMARY.md").read_text(encoding="utf-8") == "# exec\n"
    assert (dest / "SCOPE_AND_TRUST.md").read_text(encoding="utf-8") == "# scope\n"


def test_main_from_out_dispatches_sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI --from-out must call sync_from_out. Ignore --from-out mutants fail here."""
    src_out = tmp_path / "out"
    dest = tmp_path / "drop"
    dest.mkdir()
    _seed_out(src_out)

    _stub_sinks(monkeypatch, dest)

    assert main(["--from-out", str(src_out)]) == 0
    assert (dest / "ciso" / "findings.csv").is_file()
    assert "FIND-1" in (dest / "ciso" / "findings.csv").read_text(encoding="utf-8")
    assert (dest / "poam" / "excluded.csv").is_file()
    assert (dest / "poam" / "poam_fedramp.csv").is_file()
    assert (dest / "poam" / "poam-ledger.json").is_file()
    assert (dest / "EXECUTIVE_SUMMARY.md").is_file()


def test_main_sync_alias_dispatches_sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src_out = tmp_path / "out"
    dest = tmp_path / "drop"
    dest.mkdir()
    _seed_out(src_out)

    import scripts.refresh_product_lab_drop_sinks as mod

    called: dict[str, Path] = {}

    def fake_sync(src: Path, drop: Path = dest) -> None:
        called["src"] = Path(src)
        called["drop"] = Path(drop)

    _stub_sinks(monkeypatch, dest)
    monkeypatch.setattr(mod, "sync_from_out", fake_sync)
    monkeypatch.setattr(mod, "_sha256", lambda path: "0" * 64)
    monkeypatch.setattr(mod, "_csv_rows", lambda path: 0)

    assert main(["sync", str(src_out)]) == 0
    assert called["src"] == src_out


def test_sync_from_out_refuses_missing_findings_csv(tmp_path: Path) -> None:
    """S5: missing-CSV guard must refuse. An empty ciso-assistant is not a sync."""
    src_out = tmp_path / "out"
    (src_out / "ciso-assistant").mkdir(parents=True)
    dest = tmp_path / "drop"
    with pytest.raises((SystemExit, FileNotFoundError), match="CISO|findings"):
        sync_from_out(src_out, dest)
    assert not (dest / "ciso" / "findings.csv").is_file()


def test_manifest_writer_keeps_estate_and_ledger_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """S6/S7: ciso/ESTATE.txt and poam-ledger.json stay in the MANIFEST writer."""
    import scripts.refresh_product_lab_drop_sinks as mod

    rels = [rel for rel, _key in MANIFEST_ROWS]
    assert "ciso/ESTATE.txt" in rels
    assert "poam/ESTATE.txt" in rels
    assert "poam/poam-ledger.json" in rels
    assert "poam/excluded.csv" in rels
    assert "poam/poam_fedramp.csv" in rels
    assert all("poam_members.csv" not in rel for rel in rels)

    dest = tmp_path / "drop"
    dest.mkdir()
    monkeypatch.setattr(mod, "DROP", dest)
    hashes = {rel: "0" * 64 for rel, _key in MANIFEST_ROWS}
    counts = {rel: 1 for rel, key in MANIFEST_ROWS if key != "draft"}
    mod._write_manifest(counts, hashes)
    text = (dest / "MANIFEST").read_text(encoding="utf-8")
    assert "| ciso/ESTATE.txt |" in text
    assert "| poam/poam-ledger.json |" in text
    assert "| poam/ESTATE.txt |" in text
    assert "poam_members.csv" not in text


def test_main_from_out_uses_outdir_env_when_path_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S9: `--from-out` with no path must honor OUT_DIR."""
    src_out = tmp_path / "out"
    dest = tmp_path / "drop"
    dest.mkdir()
    _seed_out(src_out)

    import scripts.refresh_product_lab_drop_sinks as mod

    called: dict[str, Path] = {}

    def fake_sync(src: Path, drop: Path = dest) -> None:
        called["src"] = Path(src)

    _stub_sinks(monkeypatch, dest)
    monkeypatch.setattr(mod, "sync_from_out", fake_sync)
    monkeypatch.setattr(mod, "_sha256", lambda path: "0" * 64)
    monkeypatch.setattr(mod, "_csv_rows", lambda path: 0)
    monkeypatch.setenv("OUT_DIR", str(src_out))

    assert main(["--from-out"]) == 0
    assert called["src"] == src_out
