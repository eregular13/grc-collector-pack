from __future__ import annotations

DESTROYED: list[str] = []


def spawn_worker(stage: str, shard: list[str]) -> str:
    return f"{stage}:{len(shard)}"


def destroy_workers(stage: str) -> str:
    token = f"destroyed:{stage}"
    DESTROYED.append(token)
    return token
