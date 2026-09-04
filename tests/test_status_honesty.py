"""Themis honesty: DEMO ≠ client; compose ABSENT ≠ PASS; paying-day stays FAIL."""

from __future__ import annotations

from pathlib import Path

from dropbox.scanner_free import compose_lab, docker_available

ROOT = Path(__file__).resolve().parents[1]


def _status() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (ROOT / "STATUS.md").read_text(encoding="utf-8").splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def test_status_paying_day_fail_and_compose_absent_until_proven() -> None:
    status = _status()
    assert status.get("paying_day") == "FAIL"
    assert status.get("demo") == "true"
    assert "DEMO" in status.get("estate", "")
    assert "client estate" in status.get("estate", "").lower()
    assert status.get("wrap") == "review-only"
    assert status.get("license_lock_will_run") == "never"
    ok, reason = docker_available()
    if not ok:
        assert status.get("compose_lab") == "absent"
        assert status.get("compose_lab") != "pass"
        assert status.get("compose_lab_reason")
        assert "docker" in status["compose_lab_reason"].lower() or "PATH" in status["compose_lab_reason"]
        assert "docker" in reason.lower() or "PATH" in reason
    else:
        assert status.get("paying_day") == "FAIL"
        assert status.get("compose_lab") in {"absent", "pass", "skip"}


def test_compose_lab_absent_is_not_a_pass_on_this_vm() -> None:
    ok, _reason = docker_available()
    stamp = compose_lab()
    if not ok:
        assert stamp.get("status") == "absent"
        assert stamp.get("status") != "pass"
        assert stamp.get("profiles_run") == []
        note = str(stamp.get("note") or "")
        assert "not a compose" in note.lower() or "runtime compose not run" in note.lower()


def test_executive_does_not_stamp_paying_day_or_assessment_ready() -> None:
    for rel in (
        "STATUS.md",
        "product-lab/EXECUTIVE.md",
        "dropbox/EXECUTIVE.md",
        "farm/QUICKSTART.md",
        "CRITIC.md",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "assessment-ready" not in text.lower()
        for line in text.splitlines():
            low = line.lower()
            if "paying-day pass" in low or "paying_day: pass" in low:
                assert any(tok in low for tok in ("not", "never", "do not", "fail", "≠"))


def test_scanner_free_and_wrap_dead_require_hephaestus_rails() -> None:
    """Rail 4: scanner-free + wrap-dead only count if wrap/toolbin/MCP rails hold."""
    from dropbox.orchestrator.byo import farm_which
    from dropbox.scope import LICENSE_LOCK_SPAWN

    status = _status()
    assert status.get("wrap") == "review-only"
    assert status.get("paying_day") == "FAIL"
    assert status.get("license_lock_will_run") == "never"
    assert status.get("scanner_free") == "true"
    for name in ("nuclei", "openvas", "wazuh", "osquery", "bloodhound", "pingcastle"):
        assert name in LICENSE_LOCK_SPAWN
        assert farm_which(name) is None
    hexstrike = (ROOT / "dropbox" / "HEXSTRIKE.md").read_text(encoding="utf-8")
    assert "evergreen_assessment_mcp" in hexstrike
    assert "check_scope" in hexstrike
    assert "license_guard" in hexstrike
    assert "TypeScript refuse" in hexstrike
    farm_op = (ROOT / "farm" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "evergreen_assessment_mcp" in farm_op
    assert "check_scope" in farm_op
    assert "license_guard" in farm_op
    assert "TypeScript refuse" in farm_op
    for rel in ("product-lab/EXECUTIVE.md", "dropbox/EXECUTIVE.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "wrap" in text.lower() and ("dead" in text.lower() or "review-only" in text.lower())
        assert "evergreen_assessment_mcp" in text or "not pack truth" in text.lower()
    for folder in (ROOT, ROOT / "dropbox", ROOT / "farm", ROOT / "scripts"):
        assert not list(folder.glob("*.ts"))
        assert not list(folder.glob("*refuse*matrix*"))


def test_operator_compose_proof_path_is_documented() -> None:
    op = (ROOT / "farm" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "docker compose config --services" in op
    assert "docker compose up --build --exit-code-from grc-loader" in op
    assert "docker compose -f docker-compose.dropbox.yml --profile internal" in op
    assert "docker compose -f farm/docker-compose.yml --profile orchestrate" in op
    assert "paying-day PASS" in op
    assert "not" in op.lower() and "paying-day" in op.lower()
    assert "ABSENT" in op
    pl = (ROOT / "product-lab" / "OPERATOR.md").read_text(encoding="utf-8")
    assert "docker compose up --build --exit-code-from grc-loader" in pl
    assert "ABSENT" in pl
    assert "paying-day" in pl.lower()
