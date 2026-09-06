"""Intelligent orchestrator = the brakes. Quiet discover, gated deepen, ingest."""

STAGES = (
    "plan",
    "shard",
    "discover",
    "destroy_discover_workers",
    "deepen",
    "destroy_deepen_workers",
    "ingest",
    "grc_export",
)

LIVE_STAGES = frozenset({"discover", "deepen", "all"})
