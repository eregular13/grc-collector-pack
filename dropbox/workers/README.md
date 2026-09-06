# Workers

Short-lived discover/deepen jobs. The orchestrator writes `dropbox/out/workers/<name>.alive` and deletes it on destroy.

Do **not** ship long-lived scanner containers. Compose snippets here are optional operator notes, not an image that embeds Nmap/Nessus.

`compose.noop.yml` is a tear-down drill (python:3.12-slim print). It does **not** run scanners.

Integrity: one shard per discover worker; deepen batch 2–5; tear down after the stage.
