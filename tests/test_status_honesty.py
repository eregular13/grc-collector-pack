"""Themis honesty: DEMO ≠ client; compose ABSENT ≠ PASS; paying-day stays FAIL."""

from __future__ import annotations

import re
from pathlib import Path

from dropbox.scanner_free import compose_lab, docker_available
from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_ADAPTERS

ROOT = Path(__file__).resolve().parents[1]

# Shared all-16 set (prove_ciso seed + fixtures/pack_drop/). STATUS
# next_action + PLAN this-window must name every tool so the pack
# cannot lag a later Covey brick again.
COVEY_E2E_PROVEN = E2E_PROVEN_PACK_DROP_ADAPTERS
COVEY_E2E_HEAD = "c012dd24"
STALE_E2E_HEAD = "3cf8bb86"
COVEY_PACK_HEAD = "a3a3651b"
STALE_PACK_HEAD = "9a872ef5"
STALE_PACK_PRIOR = "899e44c8"
STALE_PACK_OLDER = "b77cfc0e"
STALE_PACK_HONESTY = "a89145f4"
EVAL_HEAD = "ebaa9f50"
STALE_EVAL_HEAD = "5f40f9ff"
# DESKTOP-222GHQV compose proof (operator snapshot; not this agent/CI VM).
LIVE_PACK_HEAD = "2680a5b2"
COMPOSE_LAB_DESKTOP = "pass_desktop"
COMPOSE_LAB_HOST = "DESKTOP-222GHQV"
COVEY_E2E_UNPROVEN = (
    "masscan",
    "arp-scan",
    "netdiscover",
    "zmap",
)


def _status() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (ROOT / "STATUS.md").read_text(encoding="utf-8").splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def _compose_lab_yaml_value(text: str) -> str | None:
    """Exact STATUS/docs `compose_lab:` field — not compose_lab_host/head/reason."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("compose_lab:") and not stripped.lower().startswith(
            "compose_lab_"
        ):
            return stripped.split(":", 1)[1].strip().lower()
    return None


def _has_bare_compose_pass(text: str) -> bool:
    """True only for exact compose_lab pass — pass_desktop is DESKTOP-only, not a VM pass."""
    if re.search(r'"compose_lab":\s*"pass"', text):
        return True
    value = _compose_lab_yaml_value(text)
    return value == "pass"


def _assert_status_compose_lab_desktop(status: dict[str, str]) -> None:
    """STATUS compose_lab is DESKTOP proof, never a bare pass on this agent/CI VM."""
    assert status.get("compose_lab") == COMPOSE_LAB_DESKTOP
    assert status.get("compose_lab") != "pass"
    assert status.get("compose_lab_host") == COMPOSE_LAB_HOST
    assert status.get("compose_lab_head") == LIVE_PACK_HEAD
    assert "2026-09-18" in status.get("compose_lab_at", "")
    reason = status.get("compose_lab_reason", "")
    assert reason
    assert "docker" in reason.lower() or "PATH" in reason
    assert "ABSENT" in reason or "absent" in reason.lower()
    assert "DESKTOP" in reason


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
        _assert_status_compose_lab_desktop(status)
        assert "docker" in reason.lower() or "PATH" in reason
    else:
        assert status.get("paying_day") == "FAIL"
        assert status.get("compose_lab") in {"absent", "pass", "skip", "pass_desktop"}


def _has_bare_cos(text: str, n: int) -> bool:
    """True when `CoS #N` is a cycle stamp, not a prefix of CoS #N0."""
    return re.search(rf"cos #{n}(?!\d)", text.lower()) is not None


def _next_brick(text: str) -> str:
    """Clause after 'next brick' — DONE pack_drop vanity must not live here.

    Split on a sentence boundary ('.' + whitespace), not the '.' in meta.json.
    """
    low = text.lower()
    idx = low.find("next brick")
    if idx < 0:
        return ""
    return re.split(r"\.\s", low[idx:], maxsplit=1)[0]


def _live_reid_only_blockers(text: str) -> str:
    """Current-truth blocker list, not historical cycle-74 notes."""
    for needle in (
        "**Still open (Reid-only blockers",
        "**Reid-only blockers (no fake greens):**",
    ):
        if needle in text:
            idx = text.index(needle)
            return text[idx:].split("\n\n", 1)[0]
    return ""


def test_status_next_action_is_reid_only_blockers() -> None:
    status = _status()
    action = status.get("next_action", "")
    low = action.lower()
    assert "cos #48" in low
    assert "honesty sync" in low
    assert "farm_drop_to_sor" in low
    assert "farm-drop-to-sor" in low
    assert "cos45-pack-drop-source-lock" in low
    assert "cos46-honesty" in low
    assert "cos47-honesty" in low
    assert "done" in low
    assert status.get("item") == "COS48-FARM-DROP-TO-SOR"
    assert "cos #47" not in low, "bare CoS #47 is not the current cycle stamp"
    assert "cos #46" not in low, "bare CoS #46 is not the current cycle stamp"
    assert "cos #45" not in low, "bare CoS #45 is not the current cycle stamp"
    assert "cos #44" not in low, "bare CoS #44 is not the current cycle stamp"
    assert "cos #43" not in low, "bare CoS #43 is not the current cycle stamp"
    assert "next brick" in low
    brick = _next_brick(action)
    assert "keep" in brick, "next brick must name Reid-only real KEEP in/ (0/4)"
    assert "0/4" in brick, "next brick must name real KEEP 0/4"
    assert "vanity" in brick, "next brick must refuse pack_drop vanity"
    assert "in/" in action, "next brick path is real KEEP in/"
    assert "source" not in brick or "identity" not in brick, "source identity lock is DONE, not the next brick"
    assert "evergreen-covey" not in brick, "pack_drop source lock is DONE, not the next brick"
    assert "port→service" not in brick and "port->service" not in brick, "port→service is DONE, not the next brick"
    assert not ("port" in brick and "service" in brick), "port→service is DONE, not the next brick"
    assert "observation" not in brick or "finding" not in brick, "observation/finding port→service is DONE, not the next brick"
    assert "service→host" not in brick and "service->host" not in brick, "service→host is DONE, not the next brick"
    assert "kind-partition" not in brick, "kind-partition lock is DONE, not the next brick"
    assert "16 e2e_proven pack_drop void closed" in low
    assert "schema seam" in low, "pack_drop schema seam must be named CLOSED"
    assert "parked" in low, "integrity PARKED must be current truth"
    assert "covey head still" not in low, "Covey HEAD is live c012dd24, not stuck"
    assert "sample_banner" in low
    assert "unicornscan" in low
    assert "after cos #1" not in low
    assert "after cos #2/#3" not in low
    for n in range(4, 48):
        assert not _has_bare_cos(low, n), f"STATUS next_action still stamps CoS #{n}"
    assert "covey" in low
    assert "e2e_proven" in low
    assert "closed" in low
    assert "20-adapter" in low
    assert "pack_drop" in low
    assert len(COVEY_E2E_PROVEN) == 16
    for name in COVEY_E2E_PROVEN:
        assert name in low, f"STATUS next_action lags Covey E2E set; missing {name}"
    for name in COVEY_E2E_UNPROVEN:
        assert name in low, f"STATUS next_action dropped UNPROVEN fail-closed {name}"
    assert "17th" in low
    assert COVEY_E2E_HEAD in low
    assert COVEY_PACK_HEAD in low
    assert STALE_E2E_HEAD not in low
    assert STALE_PACK_HEAD not in low
    assert STALE_PACK_PRIOR not in low
    assert STALE_PACK_OLDER not in low
    assert STALE_PACK_HONESTY not in low
    assert STALE_EVAL_HEAD not in low
    assert "no pack" in low and "adapter" in low
    # Pack HEAD a3a3651b (this PR farm_drop_to_sor). Covey HEAD c012dd24
    # (farm PR #23 unit CI). Eval HEAD ebaa9f50 (PR #4). Docs must
    # not name 9a872ef5 / 899e44c8 / b77cfc0e / 5f40f9ff / 3cf8bb86
    # as current.
    assert "held" not in low
    assert "missing" not in low
    assert "not in flight" not in low
    assert "reid-only" in low
    assert "cta" in low
    assert "eval" in low and "npm start" in low
    assert "keep" in low and "in/" in action
    assert "compose" in low and "docker" in low
    assert "no fake greens" in low
    assert "absent" in low and "not a pass" in low
    assert LIVE_PACK_HEAD in action
    assert COVEY_E2E_HEAD in action
    assert EVAL_HEAD in action
    assert STALE_EVAL_HEAD not in action
    assert "sample_to_sor" in low
    assert "sample-to-sor" in low
    assert "0.697" in action
    assert "0.231" in action
    assert "node" in low and "22" in action
    assert "better-sqlite3" in low
    assert COMPOSE_LAB_HOST in action or COMPOSE_LAB_DESKTOP in low
    assert "demo" in low and "client" in low
    assert "sample" in low
    assert "fail" in low
    # Durable blockers only — a frozen PR number is not a Reid-only blocker.
    # PR #4 (SCOPE hash / gate) is already on master; do not instruct merge.
    assert "merge pr #" not in low
    assert "gate" in low or "hash" in low
    assert "already" in low or "on master" in low
    if "pr #" in low:
        assert any(tok in low for tok in ("merged", "already", "on master"))
    assert status.get("paying_day") == "FAIL"
    _assert_status_compose_lab_desktop(status)
    assert status.get("scope_gap") == "none"
    assert status.get("farm_tool_bin_refuse") == "LICENSE_LOCK_SPAWN"
    for rel in ("product-lab/EXECUTIVE.md", "dropbox/EXECUTIVE.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "Reid-only" in text
        assert "CTA" in text
        assert "npm start" in text
        assert "ABSENT" in text
        assert "KEEP" in text
        live = _live_reid_only_blockers(text)
        assert live, f"{rel} missing live Reid-only blocker list"
        live_low = live.lower()
        assert "cta" in live_low
        assert "npm start" in live_low
        assert "keep" in live_low
        assert "in/" in live
        assert "absent" in live_low
        assert "merge pr #" not in live_low
        assert "gate" in live_low or "hash" in live_low
        assert "already" in live_low or "on master" in live_low


def _live_this_window(text: str) -> str:
    """Current-cycle window / newest delta — not historical cycle-153 notes."""
    for needle in (
        "**This window",
        "**Delta (cycle 174):",
        "**Delta (cycle 173):",
        "**Delta (cycle 172):",
        "**Delta (cycle 171):",
        "**Delta (cycle 170):",
        "**Delta (cycle 169):",
        "**Delta (cycle 168):",
        "**Delta (cycle 167):",
        "**Delta (cycle 166):",
        "**Delta (cycle 165):",
        "**Delta (cycle 164):",
        "**Delta (cycle 163):",
        "**Delta (cycle 162):",
        "**Delta (cycle 161):",
        "**Delta (cycle 160):",
        "**Delta (cycle 159):",
        "**Delta (cycle 158):",
        "**Delta (cycle 157):",
        "**Delta (cycle 156):",
        "**Delta (cycle 155):",
        "**Delta (cycle 154):",
        "**Delta (cycle 153):",
        "**Delta (cycle 152):",
        "**Delta (cycle 151):",
        "**Delta (cycle 150):",
        "**Delta (cycle 149):",
        "**Delta (cycle 148):",
        "**Delta (cycle 147):",
        "**Delta (cycle 146):",
        "**Delta (cycle 145):",
        "**Delta (cycle 144):",
        "**Delta (cycle 143):",
        "**Delta (cycle 142):",
        "**Delta (cycle 141):",
        "**Delta (cycle 140):",
        "**Delta (cycle 139):",
        "**Delta (cycle 138):",
        "**Delta (cycle 137):",
    ):
        if needle in text:
            idx = text.index(needle)
            return text[idx:].split("\n\n", 1)[0]
    return ""


def _plan_this_window() -> str:
    text = (ROOT / "PLAN.md").read_text(encoding="utf-8")
    idx = text.find("## This window")
    return text[idx:].split("## STOP", 1)[0] if idx >= 0 else ""


def test_status_and_plan_cannot_lag_covey_e2e_set() -> None:
    """STATUS next_action and PLAN this-window must name every Covey E2E tool."""
    action = _status().get("next_action", "")
    window = _plan_this_window()
    assert action and window
    for where, text in (("STATUS next_action", action), ("PLAN this-window", window)):
        low = text.lower()
        assert len(COVEY_E2E_PROVEN) == 16, f"{where} honesty lock is not the sixteen-name set"
        missing = [name for name in COVEY_E2E_PROVEN if name not in low]
        assert not missing, f"{where} lags Covey E2E set; missing {missing}"
        assert "e2e_proven" in low, f"{where} missing E2E_PROVEN"
        assert "cos #48" in low, f"{where} missing CoS #48 stamp"
        assert "farm_drop_to_sor" in low, f"{where} missing farm_drop_to_sor"
        assert "cos #47" not in low, f"{where} still stamps CoS #47 as the current cycle"
        assert "cos #46" not in low, f"{where} still stamps CoS #46 as the current cycle"
        assert "cos #45" not in low, f"{where} still stamps CoS #45 as the current cycle"
        assert "cos #44" not in low, f"{where} still stamps CoS #44 as the current cycle"
        assert "cos #43" not in low, f"{where} still stamps CoS #43 as the current cycle"
        assert "cos #42" not in low, f"{where} still stamps CoS #42 as the current cycle"
        assert "cos #41" not in low, f"{where} still stamps CoS #41 as the current cycle"
        assert "cos #40" not in low, f"{where} still stamps CoS #40 as the current cycle"
        assert "cos #39" not in low, f"{where} still stamps CoS #39 as the current cycle"
        assert "cos #38" not in low, f"{where} still stamps CoS #38 as the current cycle"
        assert "cos #37" not in low, f"{where} still stamps CoS #37 as the current cycle"
        assert "cos #36" not in low, f"{where} still stamps CoS #36 as the current cycle"
        assert "cos #35" not in low, f"{where} still stamps CoS #35 as the current cycle"
        assert "cos #34" not in low, f"{where} still stamps CoS #34 as the current cycle"
        assert "next brick" in low, f"{where} missing next brick = Reid-only real KEEP in/ (0/4)"
        brick = _next_brick(text)
        assert "keep" in brick, f"{where} next brick missing real KEEP"
        assert "0/4" in brick, f"{where} next brick missing 0/4"
        assert "vanity" in brick, f"{where} next brick missing no pack_drop vanity"
        assert "source" not in brick or "identity" not in brick, f"{where} still names source identity as next brick"
        assert "evergreen-covey" not in brick, f"{where} still names pack_drop source lock as next brick"
        assert "port→service" not in brick and "port->service" not in brick, f"{where} still names port→service as next brick"
        assert not ("port" in brick and "service" in brick), f"{where} still names port→service as next brick"
        assert "service→host" not in brick and "service->host" not in brick, f"{where} still names service→host as next brick"
        assert "kind-partition" not in brick, f"{where} still names kind-partition as next brick"
        assert "void" in low and "closed" in low, f"{where} missing 16 E2E_PROVEN pack_drop void CLOSED"
        assert "schema seam" in low, f"{where} missing pack_drop schema seam CLOSED"
        assert "parked" in low, f"{where} missing integrity PARKED"
        assert "covey head still" not in low, f"{where} still implies Covey is stuck"
        assert "cos45-pack-drop-source-lock" in low, f"{where} missing COS45-PACK-DROP-SOURCE-LOCK DONE"
        assert "cos46-honesty" in low, f"{where} missing COS46-HONESTY DONE"
        assert "cos47-honesty" in low, f"{where} missing COS47-HONESTY DONE"
        assert "stop for cos #49" in low, f"{where} missing Stop for CoS #49"
        assert "pr #23" in low, f"{where} missing farm PR #23 unit CI"
        assert "unit" in low, f"{where} missing farm PR #23 unit CI"
        assert EVAL_HEAD in low, f"{where} missing Eval HEAD {EVAL_HEAD}"
        assert "eval_pack_handoff" in low, f"{where} missing EVAL_PACK_HANDOFF"
        assert COVEY_E2E_HEAD in low, f"{where} missing Covey HEAD {COVEY_E2E_HEAD}"
        assert COVEY_PACK_HEAD in low, f"{where} missing pack HEAD {COVEY_PACK_HEAD}"
        assert STALE_E2E_HEAD not in low, f"{where} still stamps stale HEAD {STALE_E2E_HEAD}"
        assert STALE_PACK_HEAD not in low, f"{where} still stamps stale pack HEAD {STALE_PACK_HEAD}"
        assert STALE_PACK_PRIOR not in low, f"{where} still stamps prior pack HEAD {STALE_PACK_PRIOR}"
        assert STALE_PACK_OLDER not in low, f"{where} still stamps older pack HEAD {STALE_PACK_OLDER}"
        assert STALE_PACK_HONESTY not in low, f"{where} still stamps stale honesty lock {STALE_PACK_HONESTY}"
        assert STALE_EVAL_HEAD not in low, f"{where} still stamps stale Eval HEAD {STALE_EVAL_HEAD}"
        assert "pack_drop" in low, f"{where} missing pack_drop export stamp"
        assert "closed" in low, f"{where} missing CLOSED lane"
        unproven = [name for name in COVEY_E2E_UNPROVEN if name not in low]
        assert not unproven, f"{where} dropped UNPROVEN fail-closed {unproven}"
        assert "17th" in low, f"{where} dropped no-17th-live lock"


def test_status_and_live_docs_match_cos47_covey_e2e_proven() -> None:
    """Pack next_action / this-window docs follow CoS #48 live farm HEAD E2E_PROVEN."""
    from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_NAMED, SAMPLE_BANNER

    status = _status()
    action = status.get("next_action", "")
    low = action.lower()
    assert status.get("paying_day") == "FAIL"
    _assert_status_compose_lab_desktop(status)
    assert status.get("demo") == "true"
    assert status.get("argus_keep_real") == "0/4"
    assert status.get("argus_pack_truth") == "evergreen_assessment_mcp only"
    assert "e2e_proven" in low
    assert "pack_drop" in low
    for name in COVEY_E2E_PROVEN:
        assert name in low, f"STATUS next_action lags Covey E2E set; missing {name}"
    assert COVEY_E2E_HEAD in low
    assert COVEY_PACK_HEAD in low
    assert STALE_E2E_HEAD not in low
    assert STALE_PACK_HEAD not in low
    assert STALE_PACK_PRIOR not in low
    assert STALE_PACK_OLDER not in low
    assert STALE_PACK_HONESTY not in low
    assert STALE_EVAL_HEAD not in low
    assert "cos #20" not in low
    assert "cos #21" not in low
    assert "cos #22" not in low
    assert "cos #23" not in low
    assert "cos #24" not in low
    assert "cos #25" not in low
    assert "cos #26" not in low
    assert "cos #27" not in low
    assert "cos #28" not in low
    assert "cos #29" not in low
    assert "cos #30" not in low
    assert "cos #31" not in low
    assert "cos #32" not in low
    assert "cos #33" not in low
    assert "cos #34" not in low
    assert "cos #35" not in low
    assert "cos #36" not in low
    assert "cos #37" not in low
    assert "cos #38" not in low
    assert "cos #39" not in low
    assert "cos #40" not in low
    assert "cos #41" not in low
    assert "cos #42" not in low
    assert "cos #43" not in low
    assert "cos #44" not in low
    assert "cos #45" not in low
    assert "cos #46" not in low
    assert "cos #47" not in low
    assert "closed" in low
    assert "held" not in low
    assert "missing" not in low
    assert "not in flight" not in low
    joined = " + ".join(COVEY_E2E_PROVEN)
    assert joined == E2E_PROVEN_PACK_DROP_NAMED
    assert joined.endswith("unicornscan")
    assert "unicornscan" in SAMPLE_BANNER
    assert E2E_PROVEN_PACK_DROP_NAMED in SAMPLE_BANNER
    prove_src = (ROOT / "scripts" / "prove_ciso.py").read_text(encoding="utf-8")
    assert "join(E2E_PROVEN_PACK_DROP_ADAPTERS)" in prove_src
    assert "unicornscan" in prove_src
    assert "E2E_PROVEN_PACK_DROP_NAMED" in prove_src
    live = (
        ROOT / "CRITIC.md",
        ROOT / "DONE.md",
        ROOT / "PLAN.md",
        ROOT / "product-lab" / "EXECUTIVE.md",
        ROOT / "dropbox" / "EXECUTIVE.md",
        ROOT / "docs" / "PROVE_CISO.md",
    )
    for path in live:
        text = path.read_text(encoding="utf-8")
        window = _live_this_window(text)
        if not window:
            # CRITIC / PLAN / DONE / PROVE_CISO current-truth is the lead copy.
            if path.name == "PLAN.md":
                window = _plan_this_window() or text
            else:
                idx = text.find("CoS #48")
                window = text[idx : idx + 1800] if idx >= 0 else ""
        assert window, f"{path} missing CoS #48 this-window copy"
        win_low = window.lower()
        assert "cos #48" in win_low, f"{path} this-window is not CoS #48"
        assert "farm_drop_to_sor" in win_low, f"{path} this-window missing farm_drop_to_sor"
        assert "cos #47" not in win_low, f"{path} this-window still stamps CoS #47 as the current cycle"
        assert "cos #46" not in win_low, f"{path} this-window still stamps CoS #46 as the current cycle"
        assert "cos #45" not in win_low, f"{path} this-window still stamps CoS #45 as the current cycle"
        assert "cos #44" not in win_low, f"{path} this-window still stamps CoS #44 as the current cycle"
        assert "cos #43" not in win_low, f"{path} this-window still stamps CoS #43 as the current cycle"
        assert "cos #42" not in win_low, f"{path} this-window still stamps CoS #42 as the current cycle"
        assert "cos #41" not in win_low, f"{path} this-window still stamps CoS #41 as the current cycle"
        assert "cos #40" not in win_low, f"{path} this-window still stamps CoS #40 as the current cycle"
        assert "cos #39" not in win_low, f"{path} this-window still stamps CoS #39 as the current cycle"
        assert "cos #38" not in win_low, f"{path} this-window still stamps CoS #38 as the current cycle"
        assert "cos #37" not in win_low, f"{path} this-window still stamps CoS #37 as the current cycle"
        assert "cos #36" not in win_low, f"{path} this-window still stamps CoS #36 as the current cycle"
        assert "cos45-pack-drop-source-lock" in win_low, f"{path} this-window missing COS45-PACK-DROP-SOURCE-LOCK DONE"
        assert "cos46-honesty" in win_low, f"{path} this-window missing COS46-HONESTY DONE"
        assert "cos47-honesty" in win_low, f"{path} this-window missing COS47-HONESTY DONE"
        assert "eval_pack_handoff" in win_low, f"{path} this-window missing EVAL_PACK_HANDOFF"
        assert "c012dd24" in win_low, f"{path} this-window missing farm HEAD c012dd24"
        assert "pr #23" in win_low, f"{path} this-window missing farm PR #23"
        assert EVAL_HEAD in win_low, f"{path} this-window missing Eval HEAD {EVAL_HEAD}"
        assert "next brick" in win_low, f"{path} this-window missing next brick = Reid-only real KEEP in/ (0/4)"
        brick = _next_brick(window)
        assert "keep" in brick, f"{path} this-window next brick missing real KEEP"
        assert "0/4" in brick, f"{path} this-window next brick missing 0/4"
        assert "vanity" in brick, f"{path} this-window next brick missing no pack_drop vanity"
        assert "source" not in brick or "identity" not in brick, f"{path} this-window still names source identity as next brick"
        assert "evergreen-covey" not in brick, f"{path} this-window still names pack_drop source lock as next brick"
        assert "port→service" not in brick and "port->service" not in brick, f"{path} this-window still names port→service as next brick"
        assert not ("port" in brick and "service" in brick), f"{path} this-window still names port→service as next brick"
        assert "service→host" not in brick and "service->host" not in brick, f"{path} this-window still names service→host as next brick"
        assert "kind-partition" not in brick, f"{path} this-window still names kind-partition as next brick"
        assert "void" in win_low, f"{path} this-window missing void CLOSED"
        assert "schema seam" in win_low, f"{path} this-window missing pack_drop schema seam CLOSED"
        assert "parked" in win_low, f"{path} this-window missing integrity PARKED"
        assert "covey head still" not in win_low, f"{path} this-window still implies Covey is stuck"
        assert "e2e_proven" in win_low, f"{path} this-window missing E2E_PROVEN"
        assert "closed" in win_low, f"{path} this-window missing CLOSED lane"
        assert "pack_drop" in win_low, f"{path} this-window missing pack_drop export"
        missing = [name for name in COVEY_E2E_PROVEN if name not in win_low]
        assert not missing, f"{path} this-window lags Covey E2E set; missing {missing}"
        assert COVEY_E2E_HEAD in win_low, f"{path} this-window missing HEAD {COVEY_E2E_HEAD}"
        assert COVEY_PACK_HEAD in win_low, f"{path} this-window missing pack HEAD {COVEY_PACK_HEAD}"
        assert STALE_E2E_HEAD not in win_low, f"{path} this-window still stamps stale HEAD"
        assert STALE_PACK_HEAD not in win_low, f"{path} this-window still stamps stale pack HEAD"
        assert STALE_PACK_PRIOR not in win_low, f"{path} this-window still stamps prior pack HEAD"
        assert STALE_PACK_OLDER not in win_low, f"{path} this-window still stamps older pack HEAD"
        assert STALE_PACK_HONESTY not in win_low, f"{path} this-window still stamps stale honesty lock"
        assert STALE_EVAL_HEAD not in win_low, f"{path} this-window still stamps stale Eval HEAD"
        assert "held" not in win_low, f"{path} this-window still claims brick held"
        assert "not in flight" not in win_low, f"{path} this-window still claims not in flight"


def test_argus_fail_closed_bar_is_stamped() -> None:
    status = _status()
    assert status.get("argus_bar") == "fail-closed"
    assert "DEMO" in status.get("argus_demo_e2e", "") and "client" in status.get("argus_demo_e2e", "")
    assert status.get("argus_live_ready_stubs") == "fail-closed"
    assert "SAMPLE" in status.get("argus_keep", "") and "client KEEP" in status.get("argus_keep", "")
    assert status.get("argus_keep_real") == "0/4"
    assert status.get("argus_pack_truth") == "evergreen_assessment_mcp only"
    assert status.get("argus_farm_mcp") == "never pack truth"
    assert "DESKTOP" in status.get("argus_compose", "")
    vm = status.get("argus_compose_vm", "")
    assert "ABSENT" in vm
    assert "pass" in vm.lower() and ("≠" in vm or "not" in vm.lower())
    assert "HITL" in status.get("argus_invoke", "") and "SCOPE" in status.get("argus_invoke", "")
    assert status.get("argus_file_drop") == "default"
    assert "stay-out" in status.get("argus_wrap", "")
    assert status.get("argus_hexstrike") == "pattern-only"
    assert status.get("paying_day") == "FAIL"
    _assert_status_compose_lab_desktop(status)
    for rel in ("farm/OPERATOR.md", "dropbox/OPERATOR.md", "farm/INTEGRITY.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "Argus" in text or "argus" in text.lower()
        assert "DEMO e2e" in text
        assert "0/4" in text
        assert "evergreen_assessment_mcp" in text
        assert "never pack truth" in text
        assert "DESKTOP" in text
        assert "HITL" in text
        assert "stay-out" in text or "review-only" in text.lower()
        assert "pattern-only" in text.lower() or "Hexstrike pattern-only" in text


def test_status_scope_inventory_no_remaining_entrypoint_gap() -> None:
    status = _status()
    assert status.get("scope_gap") == "none"
    inv = status.get("scope_inventory", "").lower()
    assert "load_scope" in inv
    assert "run_slot" in inv
    assert "cli" in inv and "conductor" in inv
    assert status.get("farm_tool_bin_refuse") == "LICENSE_LOCK_SPAWN"
    assert status.get("paying_day") == "FAIL"
    _assert_status_compose_lab_desktop(status)
    assert status.get("catalog_total") == "111"


def test_compose_lab_absent_is_not_a_pass_on_this_vm() -> None:
    """Runtime stamp on this VM stays absent; STATUS pass_desktop is DESKTOP-only."""
    stamp = compose_lab()
    status = _status()
    _assert_status_compose_lab_desktop(status)
    if stamp.get("status") == "absent":
        assert stamp.get("status") != "pass"
        assert stamp.get("profiles_run") == []
        note = str(stamp.get("note") or "")
        assert "not a compose" in note.lower() or "runtime compose not run" in note.lower()
    else:
        assert stamp.get("status") in {"pass", "fail"}


def test_docs_and_status_cannot_flip_compose_lab_absent_to_pass() -> None:
    """Bare compose_lab pass is forbidden; pass_desktop is DESKTOP-only, not this VM."""
    ok, reason = docker_available()
    status = _status()
    status_text = (ROOT / "STATUS.md").read_text(encoding="utf-8")
    assert not _has_bare_compose_pass(status_text)
    if not ok:
        _assert_status_compose_lab_desktop(status)
        assert "docker" in reason.lower() or "PATH" in reason
        action = status.get("next_action", "")
        assert "absent" in action.lower()
        assert "not a pass" in action.lower() or "≠" in action
        assert "DESKTOP" in action or COMPOSE_LAB_DESKTOP in action.lower()
        yaml_value = _compose_lab_yaml_value(status_text)
        assert yaml_value == COMPOSE_LAB_DESKTOP
        assert yaml_value != "pass"
    live = (
        ROOT / "STATUS.md",
        ROOT / "CRITIC.md",
        ROOT / "DONE.md",
        ROOT / "PLAN.md",
        ROOT / "product-lab" / "EXECUTIVE.md",
        ROOT / "dropbox" / "EXECUTIVE.md",
    )
    for path in live:
        text = path.read_text(encoding="utf-8")
        assert not _has_bare_compose_pass(text), f"{path} flipped compose_lab to bare pass"
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("compose_lab:") and not stripped.lower().startswith(
                "compose_lab_"
            ):
                value = stripped.split(":", 1)[1].strip().lower()
                assert value in {"absent", "pass_desktop"}, (
                    f"{path} compose_lab={value} (bare pass forbidden; this VM stays absent)"
                )
                assert value != "pass"


def test_executive_does_not_stamp_paying_day_or_assessment_ready() -> None:
    for rel in (
        "README.md",
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


def test_executive_and_status_share_honesty_rails() -> None:
    status = _status()
    assert status.get("paying_day") == "FAIL"
    assert status.get("wrap") == "review-only"
    assert status.get("catalog_total") == "111"
    assert status.get("catalog_wired") == "32"
    assert status.get("catalog_invoke") == "30"
    assert status.get("catalog_file_drop") == "81"
    assert "DEMO" in status.get("estate", "")
    for rel in ("product-lab/EXECUTIVE.md", "dropbox/EXECUTIVE.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "111" in text and "32" in text and "30 invoke" in text and "81 file_drop" in text
        assert "evergreen_assessment_mcp" in text
        assert "FAIL" in text and "ABSENT" in text
        assert "DEMO" in text and "client" in text.lower()
        assert "review-only" in text.lower() or "wrap stays dead" in text.lower()


def test_root_readme_honesty_rails() -> None:
    """Top-level README must match STATUS: DEMO≠client, FAIL, ABSENT, catalog, pack truth."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    low = text.lower()
    assert "demo ≠ client" in low or "demo != client" in low
    assert "paying-day **fail**" in low or "paying-day fail" in low
    assert "compose **absent**" in low or "compose absent" in low
    assert "review-only" in low
    assert "111" in text and "32 wired" in text
    assert "30 invoke" in text and "81 file_drop" in text
    assert "evergreen_assessment_mcp" in text
    assert "check_scope" in text and "license_guard" in text
    assert "dropbox.mcp_stub" in text
    assert "not" in low and "allowlist nmap" in low
    assert "exit-code-from grc-loader" in text
    assert "exactly 11" in text
    assert "this vm stamps compose absent" in low


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
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docker compose config --services" in readme
    assert "docker compose up --build --exit-code-from grc-loader" in readme
    assert "this VM stamps compose ABSENT" in readme
    assert "not" in readme.lower() and "paying-day pass" in readme.lower()
