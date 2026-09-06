# Lab window vs demo consent window

`dropbox/SCOPE.example.yaml` keeps a **historic closed** window (`window_end: 2026-09-05T09:00-07:00`). After that stamp, live is `window_closed`. That is documentation, not a bug. `allow_live_exec` stays **false**. Do not extend the example window to fake a live drop box.

Pytest and fixture quiet→loud use `dropbox/SCOPE.lab.yaml` (and `SCOPE.external.lab.yaml`). Those files are rewritten at session start with `window_start = now−1d` and `window_end = now+30d`. They are **not** a customer pack. `client_facing_ready` stays false.

A dedicated test still proves a **past** window refuses live (`window_closed`) with a relative end (now−1 hour), not another Saturday date.

Fixture `--stage all` on expired example SCOPE still ingests **labeled fixture** and must not stamp a client-facing CISO drop.

See `tests/scope_clock.py`. Do not bake the next calendar bomb.
