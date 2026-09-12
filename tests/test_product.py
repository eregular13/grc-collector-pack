from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Folded onto main estate (R04–R09) plus live web/TLS. Zip contract for R12.
ESTATE_MAPPED_CLASSES = (
    "Cleartext HTTP",
    "Missing HSTS",
    "Missing web security headers",
    "Server banner disclosure",
    "Git metadata exposed",
    "Directory listing enabled",
    "Environment file exposed",
    "Insecure session cookie",
    "Permissive CORS policy",
    "Untrusted TLS certificate",
)


def test_hitl_doc_and_lab_file() -> None:
    text = (ROOT / "docs" / "HITL.md").read_text(encoding="utf-8")
    for key in ("attested", "client", "timestamp", "slug", "evidence_label"):
        assert key in text
    assert "lab-sim" in text
    assert "client_facing_ready" in text
    blob = json.loads((ROOT / "dropbox" / "HITL.docker-estate.json").read_text(encoding="utf-8"))
    assert blob["attested"] is True
    assert blob["evidence_label"] == "lab-sim"
    assert blob["client"] == "Evergreen Docker Estate LLC"
    assert blob["slug"] == "docker-estate-product"


def test_attested_hitl_fixture_still_not_ready() -> None:
    from dropbox.orchestrator.run import run

    dest = ROOT / "dropbox" / "out"
    dest.mkdir(parents=True, exist_ok=True)
    hitl = dest / "HITL.json"
    (dest / "normalized").mkdir(exist_ok=True)
    (dest / "deepen.json").write_text(
        json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    (dest / "normalized" / "findings.json").write_text(
        json.dumps({"label": "fixture", "client": "Litware Lab LLC", "findings": []}),
        encoding="utf-8",
    )
    hitl.write_text(
        json.dumps(
            {
                "attested": True,
                "client": "Litware Lab LLC",
                "slug": "docker-estate-product",
                "evidence_label": "lab-sim",
                "timestamp": "2026-09-05T21:50:00-07:00",
            }
        ),
        encoding="utf-8",
    )
    try:
        payload = run(ROOT / "dropbox" / "SCOPE.lab.yaml", "grc_export")
        assert payload["grc_export"]["client_facing_ready"] is False
        assert payload["grc_export"]["hitl"].get("blocked_by") in {
            "fixture_not_client_estate",
            "lab_sim_not_client_estate",
        }
    finally:
        if hitl.exists():
            hitl.unlink()


def test_product_demo_estate_down(monkeypatch, tmp_path) -> None:
    import dropbox.product_demo as demo

    monkeypatch.setattr(demo, "estate_up", lambda: False)
    with pytest.raises(demo.EstateDown):
        demo.run_demo()
    assert demo.main(["run"]) == 2


def test_product_demo_estate_down_does_not_package_litware(monkeypatch, capsys) -> None:
    """R15: estate-down exits 2; no orchestrator, no Litware kit, no sink POST."""
    import dropbox.product_demo as demo

    called: list[str] = []
    monkeypatch.setattr(demo, "estate_up", lambda: False)
    monkeypatch.setattr(demo, "new_engagement", lambda *_a, **_k: called.append("eng") or {})
    monkeypatch.setattr(demo, "package_slug", lambda *_a, **_k: called.append("zip"))
    monkeypatch.setattr(demo, "_post_importer", lambda _p: called.append("post") or 200)
    monkeypatch.setattr(demo, "_write_hitl", lambda _d: called.append("hitl") or {})
    monkeypatch.setattr(demo, "run", lambda *_a, **_k: called.append("run") or {})
    monkeypatch.setattr(demo, "_export_estate_out", lambda _p: called.append("export") or Path("x"))
    assert demo.main(["run"]) == 2
    out = capsys.readouterr().out
    assert "estate_down" in out
    assert called == []
    assert "132" not in out
    assert "Litware" not in out


def test_mapped_classes_from_poam(tmp_path) -> None:
    from dropbox.product_demo import mapped_classes_from_poam

    path = tmp_path / "poam.csv"
    path.write_text(
        "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
        "Cleartext HTTP,127.0.0.1,medium,CPG 2.W;PR.DS-02,Enforce TLS,,,open\n"
        "Git metadata exposed,127.0.0.1,medium,CPG 2.T;PR.AA-05;PR.DS-01,Do not publish .git,,,open\n"
        "Lab widget,127.0.0.1,low,UNMAPPED,Triage,,,open\n"
        "Cleartext HTTP,127.0.0.1,medium,CPG 2.W;PR.DS-02,Enforce TLS,,,open\n",
        encoding="utf-8",
    )
    names = mapped_classes_from_poam(path)
    assert names == ["Cleartext HTTP", "Git metadata exposed"]
    assert mapped_classes_from_poam(tmp_path / "missing.csv") == []


def test_product_demo_help_does_not_hit_sink(monkeypatch) -> None:
    import dropbox.product_demo as demo

    called: list[str] = []
    monkeypatch.setattr(demo, "_health", lambda: called.append("health") or '{"ok": true}')
    monkeypatch.setattr(demo, "_post_importer", lambda _p: called.append("post") or 200)
    monkeypatch.setattr(demo, "run_demo", lambda: called.append("run") or {})
    monkeypatch.setattr(demo, "plan_only", lambda: called.append("plan") or {})
    with pytest.raises(SystemExit) as exc:
        demo.main(["--help"])
    assert exc.value.code == 0
    assert called == []


def _sink_received() -> int | None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:18080/health", timeout=2) as resp:
            blob = json.loads(resp.read().decode("utf-8"))
        return int(blob.get("received") or 0)
    except Exception:  # noqa: BLE001
        return None


@pytest.mark.skipif(_sink_received() is None, reason="mock_sink :18080 down")
def test_product_demo_help_sink_delta_zero() -> None:
    """R11: --help does not increment mock_sink received. No POST /api/risks."""
    before = _sink_received()
    assert before is not None
    proc = subprocess.run(
        [sys.executable, "-m", "dropbox.product_demo", "--help"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    assert proc.returncode == 0
    assert "usage:" in (proc.stdout or "").lower() or "Isolated Docker estate demo" in (proc.stdout or "")
    after = _sink_received()
    assert after == before


def test_product_demo_dry_run_is_plan(monkeypatch) -> None:
    import dropbox.product_demo as demo

    monkeypatch.setattr(demo, "run_demo", lambda: (_ for _ in ()).throw(AssertionError("run must not execute")))
    monkeypatch.setattr(demo, "plan_only", lambda: {"ok": True, "dry_run": True})
    assert demo.main(["--dry-run"]) == 0
    assert demo.main(["plan"]) == 0


def test_product_demo_scope_ok_refuses_lan_drift(tmp_path, monkeypatch) -> None:
    """R16: poisoned docker-estate SCOPE (CIDR or host) fails closed. No orchestrator. No scan."""
    import dropbox.product_demo as demo

    base = (ROOT / "dropbox" / "SCOPE.docker-estate.yaml").read_text(encoding="utf-8")
    cidr_path = tmp_path / "SCOPE.cidr.yaml"
    cidr_path.write_text(
        base.replace('- "172.28.90.0/24"', '- "172.28.90.0/24"\n    - "192.168.10.0/24"', 1),
        encoding="utf-8",
    )
    host_path = tmp_path / "SCOPE.host.yaml"
    host_path.write_text(base.replace('- "172.28.90.10"', '- "192.168.10.50"', 1), encoding="utf-8")
    called: list[str] = []
    monkeypatch.setattr(demo, "run", lambda *_a, **_k: called.append("run") or {})
    monkeypatch.setattr(demo, "estate_up", lambda: True)
    monkeypatch.setattr(demo, "SCOPE", cidr_path)
    with pytest.raises(SystemExit) as exc:
        demo._scope_ok()
    assert "office LAN" in str(exc.value)
    with pytest.raises(SystemExit):
        demo.plan_only()
    with pytest.raises(SystemExit):
        demo.run_demo()
    monkeypatch.setattr(demo, "SCOPE", host_path)
    with pytest.raises(SystemExit) as host_exc:
        demo._scope_ok()
    assert "office LAN" in str(host_exc.value)
    assert called == []


def test_estate_slug_poam_is_cleartext_not_litware(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    from dropbox.new_engagement import new_engagement

    src = tmp_path / "estate-out"
    (src / "poam").mkdir(parents=True)
    (src / "poam" / "poam.csv").write_text(
        "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
        "Cleartext HTTP,127.0.0.1,medium,CPG 2.W;PR.DS-02,Enforce TLS,,,open\n",
        encoding="utf-8",
    )
    rec = new_engagement(
        "docker-estate-product",
        ROOT / "dropbox" / "SCOPE.docker-estate.yaml",
        evidence_label="lab-sim",
        artifact_src=src,
        counts={"pack_mapped": 4, "poam_rows": 4, "findings": 4},
    )
    dest = tmp_path / "docker-estate-product"
    poam = (dest / "out" / "poam" / "poam.csv").read_text(encoding="utf-8")
    assert "Cleartext HTTP" in poam
    assert rec["client_facing_ready"] is False
    assert rec["evidence_label"] == "lab-sim"
    assert rec["counts"].get("pack_mapped") == 4
    assert not (dest / "out" / "ciso-assistant" / "assets.csv").is_file()
    assert "132" not in json.dumps(rec["counts"])


def test_two_slugs_do_not_steal_poam(tmp_path, monkeypatch) -> None:
    """T07: docker-estate-product vs 24h-cold keep separate POA&M."""
    import zipfile

    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    from dropbox.new_engagement import new_engagement
    from dropbox.package_engagement import package_slug

    header = "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
    src_a = tmp_path / "estate-out"
    (src_a / "poam").mkdir(parents=True)
    (src_a / "poam" / "poam.csv").write_text(
        header + "Cleartext HTTP,127.0.0.1,medium,CPG 2.W;PR.DS-02,Enforce TLS,,,open\n",
        encoding="utf-8",
    )
    src_b = tmp_path / "cold-out"
    (src_b / "poam").mkdir(parents=True)
    (src_b / "poam" / "poam.csv").write_text(
        header + "Untrusted TLS certificate,127.0.0.1,medium,CPG 2.W;PR.DS-02;PR.DS-10,Replace cert,,,open\n",
        encoding="utf-8",
    )
    scope = ROOT / "dropbox" / "SCOPE.docker-estate.yaml"
    new_engagement("docker-estate-product", scope, evidence_label="lab-sim", artifact_src=src_a, counts={"pack_mapped": 1, "poam_rows": 1})
    new_engagement("24h-cold", scope, evidence_label="lab-sim", artifact_src=src_b, counts={"pack_mapped": 1, "poam_rows": 1})
    a = (tmp_path / "docker-estate-product" / "out" / "poam" / "poam.csv").read_text(encoding="utf-8")
    b = (tmp_path / "24h-cold" / "out" / "poam" / "poam.csv").read_text(encoding="utf-8")
    assert "Cleartext HTTP" in a
    assert "Untrusted TLS certificate" not in a
    assert "Untrusted TLS certificate" in b
    assert "Cleartext HTTP" not in b
    assert not (tmp_path / "docker-estate-product" / "out" / "orchestrator" / "discover.json").is_file()
    assert not (tmp_path / "24h-cold" / "out" / "orchestrator" / "discover.json").is_file()
    new_engagement("docker-estate-product", scope, evidence_label="lab-sim", artifact_src=src_a, counts={"pack_mapped": 1})
    b2 = (tmp_path / "24h-cold" / "out" / "poam" / "poam.csv").read_text(encoding="utf-8")
    assert b2 == b
    (tmp_path / "24h-cold" / ".env").write_text("CISO_TOKEN=nope\n", encoding="utf-8")
    zpath = package_slug("24h-cold")
    names = zipfile.ZipFile(zpath).namelist()
    assert not any(n.endswith(".env") or n.split("/")[-1] == ".env" for n in names)
    man = json.loads((tmp_path / "24h-cold" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert man["client_facing_ready"] is False


def test_zip_contract_four_mapped_names_facing_false(tmp_path, monkeypatch) -> None:
    """R12: zip has no .env, ten mapped web/TLS names, facing false, not SMBv1."""
    import zipfile

    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    from dropbox.new_engagement import new_engagement
    from dropbox.package_engagement import package_slug, slug_zip_poam

    header = "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
    rows = "".join(
        f"{name},127.0.0.1,medium,CPG 2.W;PR.DS-02,fix,,,open\n" for name in ESTATE_MAPPED_CLASSES
    )
    src = tmp_path / "estate-out"
    (src / "poam").mkdir(parents=True)
    (src / "poam" / "poam.csv").write_text(header + rows, encoding="utf-8")
    (tmp_path / "docker-estate-product").mkdir()
    (tmp_path / "docker-estate-product" / ".env").write_text("SECRET=1\n", encoding="utf-8")
    rec = new_engagement(
        "docker-estate-product",
        ROOT / "dropbox" / "SCOPE.docker-estate.yaml",
        evidence_label="lab-sim",
        artifact_src=src,
        counts={"pack_mapped": 10, "poam_rows": 10},
    )
    assert rec["client_facing_ready"] is False
    zpath = package_slug("docker-estate-product")
    ready = tmp_path / "engagement-docker-estate-product-ready.zip"
    assert ready.is_file()
    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
        assert not any(n.split("/")[-1].endswith(".env") or n.split("/")[-1] == ".env" for n in names)
        man = json.loads(zf.read("docker-estate-product/MANIFEST.json"))
    poam = slug_zip_poam(zpath, "docker-estate-product")
    poam_ready = slug_zip_poam(ready, "docker-estate-product")
    for name in ESTATE_MAPPED_CLASSES:
        assert name in poam
        assert name in poam_ready
    assert "SMBv1" not in poam
    assert "SMBv1" not in poam_ready
    assert man["client_facing_ready"] is False


def test_slug_zip_poam_survives_pack_overwrite(tmp_path, monkeypatch) -> None:
    """R12: pack out/poam SMBv1 overwrite must not change slug dir or zip POA&M."""
    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    from dropbox.new_engagement import new_engagement
    from dropbox.package_engagement import package_slug, slug_zip_poam

    header = "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
    rows = "".join(
        f"{name},127.0.0.1,medium,CPG 2.W;PR.DS-02,fix,,,open\n" for name in ESTATE_MAPPED_CLASSES
    )
    src = tmp_path / "estate-out"
    (src / "poam").mkdir(parents=True)
    (src / "poam" / "poam.csv").write_text(header + rows, encoding="utf-8")
    new_engagement(
        "docker-estate-product",
        ROOT / "dropbox" / "SCOPE.docker-estate.yaml",
        evidence_label="lab-sim",
        artifact_src=src,
        counts={"pack_mapped": 10, "poam_rows": 10},
    )
    zpath = package_slug("docker-estate-product")
    ready = tmp_path / "engagement-docker-estate-product-ready.zip"
    before = slug_zip_poam(zpath, "docker-estate-product")
    ready_bytes = ready.read_bytes()
    zip_bytes = zpath.read_bytes()
    slug_poam = tmp_path / "docker-estate-product" / "out" / "poam" / "poam.csv"
    slug_before = slug_poam.read_text(encoding="utf-8")

    pack_poam = ROOT / "out" / "poam" / "poam.csv"
    pack_poam.parent.mkdir(parents=True, exist_ok=True)
    prior_pack = pack_poam.read_text(encoding="utf-8") if pack_poam.is_file() else None
    try:
        pack_poam.write_text(
            header + "SMBv1 / TCP 445 exposed,10.0.0.9,high,CPG 2.H,Disable SMBv1,,,open\n",
            encoding="utf-8",
        )
        assert slug_poam.read_text(encoding="utf-8") == slug_before
        assert zpath.read_bytes() == zip_bytes
        assert ready.read_bytes() == ready_bytes
        after = slug_zip_poam(zpath, "docker-estate-product")
        assert after == before
        for name in ESTATE_MAPPED_CLASSES:
            assert name in after
            assert name in slug_before
        assert "SMBv1" not in after
        assert "SMBv1" not in slug_before
        assert "SMBv1" in pack_poam.read_text(encoding="utf-8")
    finally:
        if prior_pack is None:
            if pack_poam.is_file():
                pack_poam.unlink()
        else:
            pack_poam.write_text(prior_pack, encoding="utf-8")


def _assert_simplerisk_estate_rows(text: str) -> None:
    assert "SMBv1" not in text
    assert "No API wrap" in text
    for name in ESTATE_MAPPED_CLASSES:
        assert name in text


def test_estate_simplerisk_is_not_only_smbv1(tmp_path) -> None:
    """R13: leave-behind CSV is folded estate web/TLS classes, not fixture SMBv1."""
    from dropbox.orchestrator.poam import export_simplerisk, map_finding

    rows = []
    for name in ESTATE_MAPPED_CLASSES:
        rec = map_finding(name, "127.0.0.1", "medium")
        rec["asset"] = "127.0.0.1"
        rec["weakness"] = rec.get("weakness") or name
        assert rec.get("mapped") is True, name
        assert "UNMAPPED" not in (rec.get("control_refs") or [])
        rows.append(rec)
    dest = tmp_path / "risks_import.csv"
    export_simplerisk(rows, dest)
    _assert_simplerisk_estate_rows(dest.read_text(encoding="utf-8"))
    live = ROOT / "out-estate" / "simplerisk" / "risks_import.csv"
    if live.is_file():
        _assert_simplerisk_estate_rows(live.read_text(encoding="utf-8"))
    slug_sr = ROOT / "engagements" / "docker-estate-product" / "out" / "simplerisk" / "risks_import.csv"
    if slug_sr.is_file():
        _assert_simplerisk_estate_rows(slug_sr.read_text(encoding="utf-8"))


def test_estate_simplerisk_copied_into_slug_zip(tmp_path, monkeypatch) -> None:
    """R13: estate artifact_src simplerisk lands in slug dir + dated/ready zip."""
    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    from dropbox.new_engagement import new_engagement
    from dropbox.orchestrator.poam import export_simplerisk, map_finding
    from dropbox.package_engagement import package_slug, slug_zip_simplerisk

    header = "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
    rows = "".join(
        f"{name},127.0.0.1,medium,CPG 2.W;PR.DS-02,fix,,,open\n" for name in ESTATE_MAPPED_CLASSES
    )
    src = tmp_path / "estate-out"
    (src / "poam").mkdir(parents=True)
    (src / "poam" / "poam.csv").write_text(header + rows, encoding="utf-8")
    sr_rows = []
    for name in ESTATE_MAPPED_CLASSES:
        rec = map_finding(name, "127.0.0.1", "medium")
        rec["asset"] = "127.0.0.1"
        rec["weakness"] = rec.get("weakness") or name
        sr_rows.append(rec)
    (src / "simplerisk").mkdir(parents=True)
    export_simplerisk(sr_rows, src / "simplerisk" / "risks_import.csv")
    new_engagement(
        "docker-estate-product",
        ROOT / "dropbox" / "SCOPE.docker-estate.yaml",
        evidence_label="lab-sim",
        artifact_src=src,
        counts={"pack_mapped": 10, "poam_rows": 10},
    )
    slug_sr = tmp_path / "docker-estate-product" / "out" / "simplerisk" / "risks_import.csv"
    _assert_simplerisk_estate_rows(slug_sr.read_text(encoding="utf-8"))
    zpath = package_slug("docker-estate-product")
    ready = tmp_path / "engagement-docker-estate-product-ready.zip"
    _assert_simplerisk_estate_rows(slug_zip_simplerisk(zpath, "docker-estate-product"))
    _assert_simplerisk_estate_rows(slug_zip_simplerisk(ready, "docker-estate-product"))


def test_slug_simplerisk_survives_pack_overwrite(tmp_path, monkeypatch) -> None:
    """R13: pack out/simplerisk SMBv1 overwrite must not change slug dir or zip CSV."""
    monkeypatch.setenv("ENGAGEMENT_ROOT", str(tmp_path))
    from dropbox.new_engagement import new_engagement
    from dropbox.orchestrator.poam import export_simplerisk, map_finding
    from dropbox.package_engagement import package_slug, slug_zip_simplerisk

    header = "weakness,asset,severity,control_refs,recommended_action,owner,milestone,status\n"
    rows = "".join(
        f"{name},127.0.0.1,medium,CPG 2.W;PR.DS-02,fix,,,open\n" for name in ESTATE_MAPPED_CLASSES
    )
    src = tmp_path / "estate-out"
    (src / "poam").mkdir(parents=True)
    (src / "poam" / "poam.csv").write_text(header + rows, encoding="utf-8")
    sr_rows = []
    for name in ESTATE_MAPPED_CLASSES:
        rec = map_finding(name, "127.0.0.1", "medium")
        rec["asset"] = "127.0.0.1"
        rec["weakness"] = rec.get("weakness") or name
        sr_rows.append(rec)
    (src / "simplerisk").mkdir(parents=True)
    export_simplerisk(sr_rows, src / "simplerisk" / "risks_import.csv")
    new_engagement(
        "docker-estate-product",
        ROOT / "dropbox" / "SCOPE.docker-estate.yaml",
        evidence_label="lab-sim",
        artifact_src=src,
        counts={"pack_mapped": 10, "poam_rows": 10},
    )
    zpath = package_slug("docker-estate-product")
    ready = tmp_path / "engagement-docker-estate-product-ready.zip"
    slug_sr = tmp_path / "docker-estate-product" / "out" / "simplerisk" / "risks_import.csv"
    slug_before = slug_sr.read_text(encoding="utf-8")
    zip_before = slug_zip_simplerisk(zpath, "docker-estate-product")
    zip_bytes = zpath.read_bytes()
    ready_bytes = ready.read_bytes()
    _assert_simplerisk_estate_rows(slug_before)
    _assert_simplerisk_estate_rows(zip_before)

    pack_sr = ROOT / "out" / "simplerisk" / "risks_import.csv"
    pack_sr.parent.mkdir(parents=True, exist_ok=True)
    prior_pack = pack_sr.read_text(encoding="utf-8") if pack_sr.is_file() else None
    try:
        pack_sr.write_text(
            "Subject,Status,Category,Scoring,Mitigation,Regulation,Notes\n"
            "SMBv1 / TCP 445 exposed on 10.0.0.9,New,Vulnerability,high,Disable SMBv1,CPG 2.H,fixture\n",
            encoding="utf-8",
        )
        assert slug_sr.read_text(encoding="utf-8") == slug_before
        assert zpath.read_bytes() == zip_bytes
        assert ready.read_bytes() == ready_bytes
        after = slug_zip_simplerisk(zpath, "docker-estate-product")
        assert after == zip_before
        _assert_simplerisk_estate_rows(after)
        assert "SMBv1" in pack_sr.read_text(encoding="utf-8")
    finally:
        if prior_pack is None:
            if pack_sr.is_file():
                pack_sr.unlink()
        else:
            pack_sr.write_text(prior_pack, encoding="utf-8")


def test_client_assess_doc_is_checklist_only() -> None:
    text = (ROOT / "docs" / "CLIENT_ASSESS.md").read_text(encoding="utf-8")
    assert "EVERGREEN_ORCH_LIVE" in text
    assert "WRAP_DEAD" in text
    assert "assets.csv" in text
    assert "/api/risks" in text
    assert "192.168.10.0/24" in text
    assert "do not" in text.lower() or "not a scan" in text.lower()
    qs = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
    prod = (ROOT / "PRODUCT.md").read_text(encoding="utf-8")
    assert "dropbox.product_demo --help" in qs
    assert "CLIENT_ASSESS.md" in qs
    assert "not Litware" in prod
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "0.5.0-rc.2"
    ready = (ROOT / "CLIENT_READY.md").read_text(encoding="utf-8")
    assert "version: 0.5.0-rc.2" in ready
    assert "client_facing_ready: false" in ready
    assert "paying_day: NO" in ready
    assert "0.5.0-rc.2" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "version: 0.5.0-rc.2" in prod


def test_product_md_has_github_sha_line() -> None:
    """G15: PRODUCT.md stamps pack_mapped 10 and a ship-0.4.0 sha."""
    import re

    prod = (ROOT / "PRODUCT.md").read_text(encoding="utf-8")
    assert "pack_mapped: 10" in prod
    assert "github_branch: ship-0.4.0" in prod
    assert re.search(r"github_sha: [0-9a-f]{40}", prod)


def test_client_docs_match_pack_mapped_live() -> None:
    """R14: CLIENT_ASSESS + CLIENT_READY + PRODUCT.md match live pack_mapped 10."""
    prod = (ROOT / "PRODUCT.md").read_text(encoding="utf-8")
    ready = (ROOT / "CLIENT_READY.md").read_text(encoding="utf-8")
    assess = (ROOT / "docs" / "CLIENT_ASSESS.md").read_text(encoding="utf-8")
    for blob in (prod, ready, assess):
        assert "pack_mapped: 10" in blob
        assert "client_facing_ready: false" in blob
    assert "paying_day: NO" in ready
    assert "`5` on docker-estate" not in ready
    assert "pack_mapped: 5" not in ready
    assert "pack_mapped: 5" not in prod
    for name in ESTATE_MAPPED_CLASSES:
        assert name in ready
        assert name in prod or (
            name == "Missing web security headers" and "Missing X-Frame-Options/CSP" in prod
        )


def test_from_gh_ready_scorecard() -> None:
    """G23: FROM_GH_READY.md records origin sha, docker, pytest, pack_mapped, eval-24h quarantined."""
    text = (ROOT / "FROM_GH_READY.md").read_text(encoding="utf-8")
    assert "pack_mapped: 10" in text
    assert "eval24h: quarantined" in text
    assert "client_facing_ready: false" in text
    assert "ship-0.4.0" in text
    assert "0.5.0-rc.2" in text
    assert "DO NOT UP" in text or "quarantined" in text
    assert "/api/risks" in text
    assert "G24" in text
    assert "client_facing_ready: true" not in text


def test_refine_ready_scorecard() -> None:
    """R23/G03: REFINE_READY.md records folds; refine scheduler cancelled; facing false."""
    text = (ROOT / "REFINE_READY.md").read_text(encoding="utf-8")
    assert "pack_mapped: 10" in text
    assert "extras_down: yes" in text
    assert "client_facing_ready: false" in text
    assert "paying_day: NO" in text
    assert "ship-0.4.0" in text
    assert "ab121a4f6bdae0cd18c5a4b540692c023bed9abb" in text
    assert "192.168.10.0/24" in text
    assert "/api/risks" in text
    assert "172.28.110" in text
    assert "grc-estate" in text
    assert "R09" in text
    assert "client_facing_ready: true" not in text
    assert "armed until R24" not in text
    assert "scheduler: cancelled" in text
    assert "window closed 2026-09-08" in text
    status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
    assert "scheduler: cancelled" in status
    assert "pack_mapped: 10" in status
    assert "0.5.0-rc.2" in status
    assert "armed until R24" not in status
    for name in ESTATE_MAPPED_CLASSES:
        assert name in text


def test_readme_leads_with_assessment() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Authorized assessment" in text
    assert "dropbox.product_demo --help" in text
    assert "Not a GRC UI" in text
    assert "0.0.0.0" not in text
    assert "127.0.0.1" in text
    assert "Lab-sim" in text or "lab-sim" in text
    assert "docs/QUICKSTART.md" in text


def test_product_demo_module_exists() -> None:
    assert (ROOT / "dropbox" / "product_demo.py").is_file()
    assert (ROOT / "scripts" / "product_demo.ps1").is_file()
    text = (ROOT / "dropbox" / "product_demo.py").read_text(encoding="utf-8")
    assert "POST /api/risks" not in text
    console = (ROOT / "dropbox" / "orchestrator" / "console.py").read_text(encoding="utf-8")
    assert 'HOST = "127.0.0.1"' in console
    assert "0.0.0.0" not in console
    assert "18765" in console
    assert "405" in console
    assert "WRAP_DEAD" in text or "lab-sim" in text
    assert "192.168.10.0/24" in text
    assert "estate_down" in text
    assert "lab-sim" in text
    ps1 = (ROOT / "scripts" / "product_demo.ps1").read_text(encoding="utf-8")
    assert "python -m dropbox.product_demo" in ps1
    assert "@args" in ps1
    assert "RISKREADY_PUSH" in ps1


def test_dockerfile_still_no_nmap() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8").lower()
    assert "nmap" not in text
