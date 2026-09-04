"""Short-lived workers. Discover workers are destroyed after the stage."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Worker:
    wid: str
    stage: str
    target: str
    status: str = "planned"
    argv: list[str] = field(default_factory=list)
    note: str = ""

    def destroy(self) -> None:
        self.status = "destroyed"
        self.argv = []


@dataclass
class Farm:
    workers: list[Worker] = field(default_factory=list)

    def spawn(self, stage: str, target: str, argv: list[str] | None = None, note: str = "") -> Worker:
        worker = Worker(
            wid=f"{stage}-{len(self.workers) + 1:04d}",
            stage=stage,
            target=target,
            status="planned",
            argv=list(argv or []),
            note=note,
        )
        self.workers.append(worker)
        return worker

    def destroy_stage(self, stage: str) -> int:
        n = 0
        for worker in self.workers:
            if worker.stage == stage and worker.status != "destroyed":
                worker.destroy()
                n += 1
        return n

    def alive(self, stage: str | None = None) -> list[Worker]:
        rows = [w for w in self.workers if w.status != "destroyed"]
        if stage:
            rows = [w for w in rows if w.stage == stage]
        return rows
