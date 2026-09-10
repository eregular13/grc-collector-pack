"""Themis honesty: DEMO ≠ client; compose ABSENT ≠ PASS; paying-day stays FAIL."""

from __future__ import annotations

from pathlib import Path

from dropbox.scanner_free import compose_lab, docker_available

ROOT = Path(__file__).resolve().parents[1]

# Covey HEAD E2E_PROVEN set. STATUS next_action + PLAN this-window must
# name every tool so the pack cannot lag a later Covey brick again.
COVEY_E2E_PROVEN = (
    "nmap",
    "rustscan",
    "fping",
    "naabu",
    "nping",
    "httpx",
    "sslscan",
    "tlsx",
    "whatweb",
    "hping3",
    "onesixtyone",
    "nbtscan",
    "braa",
    "ike-scan",
    "svmap",
    "unicornscan",
)
COVEY_E2E_HEAD = "30d2197f"
STALE_E2E_HEAD = "40583459"
COVEY_PACK_HEAD = "cccfa800"
STALE_PACK_HEAD = "5bd77cde"
STALE_PACK_HONESTY = "eedca686"
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
    assert "cos #24" in low
    assert "honesty sync" in low
    assert "cos23-pack-drop-sslscan" in low
    assert status.get("item") == "COS23-PACK-DROP-SSLSCAN"
    assert "after cos #1" not in low
    assert "after cos #2/#3" not in low
    assert "cos #4" not in low
    assert "cos #5" not in low
    assert "cos #6" not in low
    assert "cos #7" not in low
    assert "cos #8" not in low
    assert "cos #9" not in low
    assert "cos #10" not in low
    assert "cos #11" not in low
    assert "cos #12" not in low
    assert "cos #13" not in low
    assert "cos #14" not in low
    assert "cos #15" not in low
    assert "cos #16" not in low
    assert "cos #17" not in low
    assert "cos #18" not in low
    assert "cos #19" not in low
    assert "cos #20" not in low
    assert "cos #21" not in low
    assert "cos #22" not in low
    assert "cos #23" not in low
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
    assert STALE_PACK_HONESTY not in low
    assert "no pack" in low and "adapter" in low
    # Pack HEAD cccfa800 (PR #37). Covey HEAD still 30d2197f pack_drop
    # export. Pack STATUS must not restamp CoS #23 / pack 5bd77cde / eedca686.
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
        assert any(tok in low for tok in ("merged", "already", "on master"))
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
    """Current-cycle window / newest delta — not historical cycle-121 notes."""
    for needle in (
        "**This window",
        "**Delta (cycle 122):",
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
        assert "cos #24" in low, f"{where} missing CoS #24 stamp"
        assert COVEY_E2E_HEAD in low, f"{where} missing Covey HEAD {COVEY_E2E_HEAD}"
        assert COVEY_PACK_HEAD in low, f"{where} missing pack HEAD {COVEY_PACK_HEAD}"
        assert STALE_E2E_HEAD not in low, f"{where} still stamps stale HEAD {STALE_E2E_HEAD}"
        assert STALE_PACK_HEAD not in low, f"{where} still stamps stale pack HEAD {STALE_PACK_HEAD}"
        assert STALE_PACK_HONESTY not in low, f"{where} still stamps stale honesty lock {STALE_PACK_HONESTY}"
        assert "pack_drop" in low, f"{where} missing pack_drop export stamp"
        assert "closed" in low, f"{where} missing CLOSED lane"
        unproven = [name for name in COVEY_E2E_UNPROVEN if name not in low]
        assert not unproven, f"{where} dropped UNPROVEN fail-closed {unproven}"
        assert "17th" in low, f"{where} dropped no-17th-live lock"


def test_status_and_live_docs_match_cos24_covey_e2e_proven() -> None:
    """Pack next_action / this-window docs follow CoS #24 pack HEAD E2E_PROVEN."""
    status = _status()
    action = status.get("next_action", "")
    low = action.lower()
    assert status.get("paying_day") == "FAIL"
    assert status.get("compose_lab") == "absent"
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
    assert STALE_PACK_HONESTY not in low
    assert "cos #20" not in low
    assert "cos #21" not in low
    assert "cos #22" not in low
    assert "cos #23" not in low
    assert "closed" in low
    assert "held" not in low
    assert "missing" not in low
    assert "not in flight" not in low
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
                idx = text.find("CoS #24")
                window = text[idx : idx + 1600] if idx >= 0 else ""
        assert window, f"{path} missing CoS #24 this-window copy"
        win_low = window.lower()
        assert "cos #24" in win_low, f"{path} this-window is not CoS #24"
        assert "e2e_proven" in win_low, f"{path} this-window missing E2E_PROVEN"
        assert "closed" in win_low, f"{path} this-window missing CLOSED lane"
        assert "pack_drop" in win_low, f"{path} this-window missing pack_drop export"
        missing = [name for name in COVEY_E2E_PROVEN if name not in win_low]
        assert not missing, f"{path} this-window lags Covey E2E set; missing {missing}"
        assert COVEY_E2E_HEAD in win_low, f"{path} this-window missing HEAD {COVEY_E2E_HEAD}"
        assert COVEY_PACK_HEAD in win_low, f"{path} this-window missing pack HEAD {COVEY_PACK_HEAD}"
        assert STALE_E2E_HEAD not in win_low, f"{path} this-window still stamps stale HEAD"
        assert STALE_PACK_HEAD not in win_low, f"{path} this-window still stamps stale pack HEAD"
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
