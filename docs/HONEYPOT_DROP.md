# Honeypot / decoy file_drop

This pack **parses files**. It does not run a honeypot. It does not scan `192.168.10.0/24`.

A decoy session is **honeypot validated**. That is not a surface map and it is not control operating effectiveness. Do **not** file “MFA failed” or “EDR failed” from `in/honeypot/` alone.

## Drop

`in/honeypot/` (preferred) or `fixtures/demo/honeypot/` if `in/honeypot/` is empty.

| File | Schema |
| --- | --- |
| `events.jsonl` | `honeypot_event.v1` |
| `sessions.jsonl` | `session_summary.v1` |
| `*.jsonl` | also accepts Thales `dd-honeypot` JSON lines (`"dd-honeypot": true`). Login dict: **client_ip only**; passwords are not copied. |

Empty `in/honeypot/` **and** empty demo → collector **skips** (no silent Litware-style demo). That keeps fixture lab counts `132/155/9`.

```powershell
python collectors/honeypot_decoy.py
python collectors/grc_loader.py
python -m dropbox.import_grc --target all --dry-run
```

Findings are **info** (`Decoy session observed` / `Decoy auth attempt observed`) so they do not become CISO `findings.csv` “open high” control failures. Assets are decoy sensor + decoy service (`HPOT-` prefix).

Never POST `/api/risks`. `client_facing_ready` stays false on docker-sim.
