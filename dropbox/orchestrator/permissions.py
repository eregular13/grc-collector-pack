"""Metis permissions ladder: deny > ask > allow. No subprocess here."""

from __future__ import annotations

from dropbox.scope import ALLOWED_RUNNERS, LICENSE_LOCK_SPAWN, ORCH_BYO
from farm.adapters.catalog import FILE_DROP_ONLY, LICENSE_LOCK_LIVE

LIVE_READY_ALLOW = frozenset(ORCH_BYO) | frozenset(ALLOWED_RUNNERS)

from dropbox.orchestrator.keepmin import KEEP_MINIMUM, VANITY_SCHEDULE

# Invoke deny-list. File-drop ingest of KEEP-minimum stays allow (never subprocess).
DENY_INVOKE = (
    frozenset(LICENSE_LOCK_SPAWN)
    | frozenset(LICENSE_LOCK_LIVE)
    | frozenset(FILE_DROP_ONLY)
    | frozenset(VANITY_SCHEDULE)
)


def classify(name: str) -> str:
    """Return deny, ask, or allow. Deny wins."""
    tool = (name or "").strip().lower()
    if not tool:
        return "deny"
    if tool in DENY_INVOKE and tool not in KEEP_MINIMUM and tool not in LIVE_READY_ALLOW:
        return "deny"
    if tool in FILE_DROP_ONLY or tool in VANITY_SCHEDULE:
        return "deny"
    if tool in LIVE_READY_ALLOW:
        return "ask"
    if tool in KEEP_MINIMUM:
        return "allow"
    return "deny"


def may_ingest(name: str, *, file_on_disk: bool) -> bool:
    """KEEP-minimum file-drop, or vanity only if the file already landed."""
    tool = (name or "").strip().lower()
    if tool in KEEP_MINIMUM:
        return True
    if tool in VANITY_SCHEDULE:
        return bool(file_on_disk)
    return False


def may_invoke(name: str, *, hitl: bool, live_ready: bool, demo_scope: bool) -> bool:
    """PATH/live invoke needs signed non-DEMO SCOPE, HITL, and live_ready."""
    if demo_scope or not hitl or not live_ready:
        return False
    return classify(name) == "ask"
