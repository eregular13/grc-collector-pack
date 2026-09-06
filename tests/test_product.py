from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


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


def test_product_demo_dry_run_is_plan(monkeypatch) -> None:
    import dropbox.product_demo as demo

    monkeypatch.setattr(demo, "run_demo", lambda: (_ for _ in ()).throw(AssertionError("run must not execute")))
    monkeypatch.setattr(demo, "plan_only", lambda: {"ok": True, "dry_run": True})
    assert demo.main(["--dry-run"]) == 0
    assert demo.main(["plan"]) == 0


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
