"""Intelligent chaining: discover → deepen → ingest. BYO tools only. Never embed."""

from dropbox.orchestrator.pipeline import orchestrate
from dropbox.orchestrator.shard import batch_hosts, shard_cidrs

__all__ = ["batch_hosts", "orchestrate", "shard_cidrs"]
