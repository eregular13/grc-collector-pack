# Eval ↔ pack operator handoff (honesty)

Operator path is two desks, in this order. Neither desk invents a
client estate. Neither desk stamps `paying_day` PASS.

1. **evergreen-eval** `docs/DESKTOP-DAY-OF.md` — loopback HITL on
   `127.0.0.1`. Reid signs SCOPE, file-drops Shown, brakes refuse
   `run` / `orchestrate`. `/ready` ASSESSMENT-READY is product rails.
2. **This pack** `docs/DESKTOP_DRY_RUN.md` — SAMPLE keep-lab dry-run
   (`DRY_RUN=1` `CISO_PUSH=0`). Writes CISO / OpenGRC / Probo files
   plus `keep/work/out/eval/handoff.json`. No Eval HTTP from this pack.

**Eval day-of ≠ pack paying_day PASS.** A green Eval day-of (HITL
signed, SAMPLE Shown imported, CISO exported) does not flip this pack
to client-ready. **SAMPLE ≠ client.** **SAMPLE keep cannot stamp client-ready.**
Redacted
`fixtures/keep-samples/` stay `demo: true`, `sample: true`,
`client_keep: false`, `paying_day: FAIL`. `argus_keep_real` stays
**0/4** until Reid drops the four real KEEP families into pack `in/`.

File-only. Never POST `/api/risks`. RiskReady stay-out. No USB copy.
No new collectors. No invented KEEP files.

## Fail-closed flags (this pack)

| Flag | Honest value on SAMPLE |
|---|---|
| `paying_day` | `FAIL` — SAMPLE cannot emit PASS |
| `argus_keep_real` | `0/4` — Reid-only real KEEP still open |
| `demo` / `sample` | `true` |
| `client_keep` | `false` |
| `posted` / `http` | `false` |
| `wrap` | `review-only` |
| `compose_lab` | `pass_desktop` on DESKTOP-222GHQV only; `absent` on this agent/CI VM ≠ that DESKTOP stamp and ≠ PASS |

Eval `payingDayPass` is always `false` in that app. Pack STATUS
`paying_day: FAIL` is independent. Crossing the two desks does not
OR them into a paying-day PASS.

## Copy-paste (Eval first, then pack)

On Reid’s Eval tree (loopback only; see Eval `docs/DESKTOP-DAY-OF.md`):

```bash
npx next start -p 4731 -H 127.0.0.1
# HITL mark_signed, then SAMPLE Shown file-drop — not a client KEEP
```

On this pack clone (no Docker, no `make` required):

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
python3 -m keep lab
```

Confirm `keep/work/out/ciso-assistant/IMPORT.json` before any import:
`demo`/`sample` true, `client_keep` false, `paying_day` FAIL,
`posted`/`http` false. Then follow [DESKTOP_DRY_RUN.md](DESKTOP_DRY_RUN.md)
§4–5. Optional max-5 file is `keep/work/out/eval/handoff.json`
([KEEP_EVAL_HANDOFF.md](KEEP_EVAL_HANDOFF.md)).

## What this is not

- Not a pack paying-day PASS
- Not a client KEEP drop
- Not an Eval HTTP client
- Not a Docker compose PASS (DESKTOP-222GHQV `pass_desktop` ≠ this VM; this VM `compose_lab` ABSENT ≠ pass)
- Not LinkedIn / CTA, not a real KEEP invent, not a RiskReady wrap
