"""Eval ↔ pack handoff honesty. Eval day-of ≠ pack paying_day PASS."""

from __future__ import annotations

from pathlib import Path

from tests.test_status_honesty import (
    COVEY_E2E_HEAD,
    EVAL_HEAD,
    STALE_E2E_HEAD,
    STALE_EVAL_HEAD,
    _assert_status_compose_lab_desktop,
    _status,
)

ROOT = Path(__file__).resolve().parents[1]


def test_eval_pack_handoff_doc_names_operator_path() -> None:
    doc = (ROOT / "docs" / "EVAL_PACK_HANDOFF.md").read_text(encoding="utf-8")
    low = doc.lower()
    assert "DESKTOP-DAY-OF.md" in doc
    assert "DESKTOP_DRY_RUN.md" in doc
    assert "loopback" in low or "127.0.0.1" in doc
    assert "HITL" in doc
    assert "eval day-of ≠ pack paying_day pass" in low or (
        "eval day-of" in low and "paying_day" in low and "pass" in low and "≠" in doc
    )
    assert "sample keep cannot stamp client-ready" in low
    assert "SAMPLE ≠ client" in doc or "sample ≠ client" in low
    assert "paying_day" in doc and "FAIL" in doc
    assert "0/4" in doc
    assert "/api/risks" in doc
    assert "stay-out" in low
    assert "DRY_RUN=1" in doc
    assert "CISO_PUSH=0" in doc
    assert "python3 -m keep lab" in doc
    assert "no usb" in low or "no usb copy" in low
    assert "no new collectors" in low
    assert "invent" in low and "keep" in low
    assert "client-ready" in low
    assert "ASSESSMENT-READY" in doc or "assessment-ready" in low


def test_eval_pack_handoff_fail_closed_flags() -> None:
    status = _status()
    assert status.get("paying_day") == "FAIL"
    assert status.get("argus_keep_real") == "0/4"
    assert status.get("demo") == "true"
    assert status.get("wrap") == "review-only"
    _assert_status_compose_lab_desktop(status)
    doc = (ROOT / "docs" / "EVAL_PACK_HANDOFF.md").read_text(encoding="utf-8")
    for needle in (
        "`paying_day`",
        "`argus_keep_real`",
        "`client_keep`",
        "`posted`",
        "FAIL",
        "0/4",
        "false",
        "review-only",
    ):
        assert needle in doc, f"handoff doc missing fail-closed flag {needle}"


def test_desktop_dry_run_points_at_eval_handoff() -> None:
    dry = (ROOT / "docs" / "DESKTOP_DRY_RUN.md").read_text(encoding="utf-8")
    keep = (ROOT / "docs" / "KEEP_EVAL_HANDOFF.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "EVAL_PACK_HANDOFF.md" in dry
    assert "EVAL_PACK_HANDOFF.md" in keep
    assert "EVAL_PACK_HANDOFF.md" in readme
    assert "Eval day-of" in dry or "eval day-of" in dry.lower()
    assert "paying_day" in dry and "FAIL" in dry
    assert "client-ready" in dry.lower()
    action = _status().get("next_action", "")
    assert "EVAL_PACK_HANDOFF" in action or "eval_pack_handoff" in action.lower()
    assert COVEY_E2E_HEAD in action
    assert EVAL_HEAD in action
    assert STALE_E2E_HEAD not in action
    assert STALE_EVAL_HEAD not in action
    assert "pr #23" in action.lower()
    assert "pr #24" in action.lower()
    assert "unit" in action.lower()
