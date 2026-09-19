"""Themis honesty: DEMO ≠ client; compose ABSENT ≠ PASS; paying-day stays FAIL."""

from __future__ import annotations

import re
from pathlib import Path

from dropbox.scanner_free import compose_lab, docker_available
from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_ADAPTERS

ROOT = Path(__file__).resolve().parents[1]

# Shared all-16 set (prove_ciso seed + fixtures/pack_drop/). Inventory
# locks still use this tuple; live STATUS next_action is the
# CLIENT-READY product path, not an integrity-city brick list.
COVEY_E2E_PROVEN = E2E_PROVEN_PACK_DROP_ADAPTERS
COVEY_E2E_HEAD = "f1432918"
STALE_E2E_HEAD = "30d2197f"
COVEY_PACK_HEAD = "34a32a84"
STALE_PACK_HEAD = "62b52d41"
STALE_PACK_HONESTY = "8c442a33"
STALE_META_LOCK_HEAD = "7f6fd90d"
CLIENT_READY_ITEM = "CLIENT-READY-HONESTY"
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


def _has_bare_cos(text: str, n: int) -> bool:
    """True when `CoS #N` is a cycle stamp, not a prefix of CoS #N0."""
    return re.search(rf"cos #{n}(?!\d)", text.lower()) is not None


def _fold(text: str) -> str:
    """Collapse wrapped markdown so 'does\\nnot own' still matches."""
    return re.sub(r"\s+", " ", text.lower())


def _assert_not_integrity_city(where: str, text: str) -> None:
    """Live copy must not restamp pack_drop integrity as current work."""
    low = _fold(text)
    assert STALE_PACK_HEAD not in low, (
        f"{where} still claims stale pack HEAD {STALE_PACK_HEAD}"
    )
    assert STALE_E2E_HEAD not in low, (
        f"{where} still claims stale Covey HEAD {STALE_E2E_HEAD}"
    )
    assert "next brick" not in low, f"{where} still names an integrity next brick"
    assert "stop for cos #46" not in low, f"{where} still stops for CoS #46"
    assert "stop for cos #47" not in low, f"{where} still stops for CoS #47"
    assert not _has_bare_cos(low, 46), f"{where} still names CoS #46 integrity"
    assert not _has_bare_cos(low, 47), f"{where} still names CoS #47 integrity"
    assert "source identity lock" not in low, (
        f"{where} still names meta source identity as current work"
    )
    assert "cos45-honesty" not in low, (
        f"{where} still stamps COS45-HONESTY as the current item"
    )


def _assert_client_ready_live(where: str, text: str) -> None:
    """Current-truth product slice: SAMPLE keep → CISO → OpenGRC/Probo + MCP."""
    low = _fold(text)
    _assert_not_integrity_city(where, text)
    assert COVEY_PACK_HEAD in low, f"{where} missing pack HEAD {COVEY_PACK_HEAD}"
    assert COVEY_E2E_HEAD in low, f"{where} missing Covey HEAD {COVEY_E2E_HEAD}"
    assert "client-ready" in low, f"{where} missing CLIENT-READY path"
    assert "sample" in low and "keep" in low, f"{where} missing SAMPLE keep path"
    assert "ciso" in low, f"{where} missing CISO"
    assert "opengrc" in low, f"{where} missing OpenGRC"
    assert "probo" in low, f"{where} missing Probo"
    assert "keep_status" in low, f"{where} missing keep_status"
    assert "keep_ciso" in low, f"{where} missing keep_ciso"
    assert "pr #85" in low, f"{where} missing PR #85 SAMPLE keep→CISO DONE"
    assert "pr #83" in low, f"{where} missing PR #83 MCP keep tools DONE"
    assert "pr #84" in low, f"{where} missing PR #84 OpenGRC+Probo DONE"
    assert "done" in low, f"{where} missing DONE stamp for product items"
    assert "parked" in low and "integrity" in low, f"{where} missing integrity PARKED"
    assert STALE_META_LOCK_HEAD in low or "#81" in text, (
        f"{where} missing meta source lock history (#81 / {STALE_META_LOCK_HEAD})"
    )
    assert "do not own" in low or "does not own" in low or "no pack" in low, (
        f"{where} must not claim pack owns Covey adapters"
    )
    assert "adapter" in low, f"{where} missing Covey adapter stay-out"


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
    assert status.get("item") == CLIENT_READY_ITEM
    _assert_client_ready_live("STATUS next_action", action)
    assert "operator path" in low
    assert "live" in low
    assert "0/4" in action
    assert "desktop" in low
    assert "riskready" in low and "stay-out" in low
    assert "after cos #1" not in low
    assert "after cos #2/#3" not in low
    for n in range(4, 48):
        assert not _has_bare_cos(low, n), f"STATUS next_action still stamps CoS #{n}"
    assert STALE_PACK_HONESTY not in low
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
    assert "demo" in low and "client" in low
    assert "sample" in low
    assert "fail" in low
    # Durable blockers only — a frozen PR number is not a Reid-only blocker.
    # PR #4 (SCOPE hash / gate) is already on master; do not instruct merge.
    assert "merge pr #" not in low
    assert "gate" in low or "hash" in low
    assert "already" in low or "on master" in low
    if "pr #" in low:
        assert any(tok in low for tok in ("merged", "already", "on master", "done"))
    assert status.get("paying_day") == "FAIL"
    assert status.get("compose_lab") == "absent"
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


def test_status_and_plan_cannot_lag_client_ready_slice() -> None:
    """STATUS next_action and PLAN this-window lock the product-slice HEADs."""
    action = _status().get("next_action", "")
    window = _plan_this_window()
    assert action and window
    assert _status().get("item") == CLIENT_READY_ITEM
    for where, text in (("STATUS next_action", action), ("PLAN this-window", window)):
        _assert_client_ready_live(where, text)
        low = text.lower()
        assert STALE_PACK_HONESTY not in low, f"{where} still stamps stale honesty lock"
        assert "reid-only" in low or "cta" in low, f"{where} missing Reid-only blockers"
        assert "npm start" in low, f"{where} missing Eval npm start"
        assert "0/4" in text, f"{where} missing real KEEP 0/4"
        assert "desktop" in low, f"{where} missing DESKTOP Docker compose"
        assert "paying" in low and "fail" in low, f"{where} missing paying-day FAIL"


def test_status_and_live_docs_match_client_ready_honesty() -> None:
    """Pack next_action / this-window docs follow CLIENT-READY product slice."""
    from scripts.prove_ciso import E2E_PROVEN_PACK_DROP_NAMED, SAMPLE_BANNER

    status = _status()
    action = status.get("next_action", "")
    assert status.get("item") == CLIENT_READY_ITEM
    assert status.get("paying_day") == "FAIL"
    assert status.get("compose_lab") == "absent"
    assert status.get("demo") == "true"
    assert status.get("argus_keep_real") == "0/4"
    assert status.get("argus_pack_truth") == "evergreen_assessment_mcp only"
    _assert_client_ready_live("STATUS next_action", action)
    assert "held" not in action.lower()
    assert "missing" not in action.lower()
    assert "not in flight" not in action.lower()
    joined = " + ".join(COVEY_E2E_PROVEN)
    assert len(COVEY_E2E_PROVEN) == 16
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
            if path.name == "PLAN.md":
                window = _plan_this_window() or text
            else:
                idx = text.lower().find("client-ready")
                if idx < 0:
                    idx = text.find(COVEY_PACK_HEAD)
                window = text[idx : idx + 1800] if idx >= 0 else ""
        assert window, f"{path} missing CLIENT-READY this-window copy"
        _assert_client_ready_live(f"{path} this-window", window)
        win_low = window.lower()
        assert STALE_PACK_HONESTY not in win_low, f"{path} this-window still stamps stale honesty lock"
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
    assert status.get("compose_lab") == "absent"
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
    assert status.get("compose_lab") == "absent"
    assert status.get("catalog_total") == "111"


def test_compose_lab_absent_is_not_a_pass_on_this_vm() -> None:
    """STATUS stays absent on this pack; runtime stamp is its own probe (no TOCTOU)."""
    stamp = compose_lab()
    status = _status()
    assert status.get("compose_lab") == "absent"
    assert status.get("compose_lab") != "pass"
    if stamp.get("status") == "absent":
        assert stamp.get("status") != "pass"
        assert stamp.get("profiles_run") == []
        note = str(stamp.get("note") or "")
        assert "not a compose" in note.lower() or "runtime compose not run" in note.lower()
    else:
        assert stamp.get("status") in {"pass", "fail"}


def test_docs_and_status_cannot_flip_compose_lab_absent_to_pass() -> None:
    """STATUS/docs cannot stamp compose_lab pass while Docker is missing."""
    ok, reason = docker_available()
    status = _status()
    if not ok:
        assert status.get("compose_lab") == "absent"
        assert status.get("compose_lab") != "pass"
        lab_reason = status.get("compose_lab_reason", "")
        assert lab_reason
        assert "docker" in lab_reason.lower() or "PATH" in lab_reason
        assert "docker" in reason.lower() or "PATH" in reason
        action = status.get("next_action", "")
        assert "absent" in action.lower()
        assert "not a pass" in action.lower() or "≠" in action
        assert "compose_lab: pass" not in (ROOT / "STATUS.md").read_text(encoding="utf-8").lower()
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
        if not ok:
            assert "compose_lab: pass" not in text.lower(), f"{path} flipped compose_lab absent → pass"
            assert '"compose_lab": "pass"' not in text, f"{path} JSON flipped compose_lab to pass"
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("compose_lab:"):
                    value = stripped.split(":", 1)[1].strip().lower()
                    assert value == "absent", f"{path} compose_lab={value} while Docker is absent"
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
