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
    timeout_sec: int = 30

    def destroy(self) -> None:
        self.status = "destroyed"
        self.argv = []


@dataclass
class Farm:
    workers: list[Worker] = field(default_factory=list)
    max_workers: int = 2

    def spawn(
        self,
        stage: str,
        target: str,
        argv: list[str] | None = None,
        note: str = "",
        timeout_sec: int = 30,
    ) -> Worker:
        live_argv = list(argv or [])
        if live_argv and len(self.alive()) >= self.max_workers:
            live_argv = []
            note = (note + " max_workers cap").strip()
        worker = Worker(
            wid=f"{stage}-{len(self.workers) + 1:04d}",
            stage=stage,
            target=target,
            status="planned",
            argv=live_argv,
            note=note,
            timeout_sec=timeout_sec,
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
