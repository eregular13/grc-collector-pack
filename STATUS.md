cycle: REAL_GRC CLOSED
pytest: 320 sequential
assets: 132
findings: 155
evidence: 9
client_facing_ready: false
scheduler: cancelled
refine_window: closed 2026-09-08T21:27:12-07:00
I-069: not started
canonical_on_this_host: C:\GRC Collector\grc-collector-pack
do_not_mix: C:\Users\R\grc-collector-pack

phase: REAL_GRC
version: 0.5.0-rc.3
quickstart: docs/QUICKSTART.md
import_grc: python -m dropbox.import_grc --target all --dry-run
help_is_help: yes
slug_survives_lab: yes
ci: .github/workflows/lab.yml
pack_mapped: 10
host_lab: LAB_GREEN
wrap_dead_exit: 2
pushed: ship-0.4.0
eval24h: HISTORICAL DO NOT UP
next_action: drop real scanner files into in/<sensor>/ then import_grc --dry-run. Extra Import CISO HITL CSVs. No scheduler. No 192.168.10.0/24.
