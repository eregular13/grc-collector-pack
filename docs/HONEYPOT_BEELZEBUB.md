# Beelzebub vs Palisade — honeypot pack_drop

Both land on the same pack lane: **`in/honeypot/`**. Same collector
(`python collectors/honeypot.py`). Same canonical kinds
(asset / finding / evidence). They are **not** the same sensor.

## Palisade (already wired)

Fleet-sensor export with **stage 1|2**, `trap_id`, `canary`,
`conceal_detected`, `level2_emitted`. Demo fixture:
`fixtures/demo/honeypot/`.

Stage hits are still deception-sensor / agent-behavior — not
“network compromised.” `map_finding` keeps them off POA&M as a
compromise row.

## Beelzebub (this pack_drop)

Low-interaction SSH/HTTP honeypot. Honest events are **login**,
**cmd**, and **session** only. Beelzebub does **not** have Palisade
stage semantics. The parser **fails closed**: `stage` is JSON `null`.
It will not invent `trap_id`, `stage-1`, `stage-2`, `conceal_detected`,
or `level2_emitted` as truth.

Demo fixture (SAMPLE ≠ client): `fixtures/demo/honeypot_beelzebub/`.

## Drop shape

Copy onto the existing honeypot lane (flat or nested). `list_files`
already rglob's `in/honeypot/`.

```
in/honeypot/events.jsonl
in/honeypot/sessions.jsonl
in/honeypot/meta.json
```

or

```
in/honeypot/pack_drop/events.jsonl
in/honeypot/pack_drop/sessions.jsonl
in/honeypot/pack_drop/meta.json
```

| File | Accepted as |
|---|---|
| `events.jsonl` | `honeypot_event.v1` rows: `event` = `login` \| `cmd` \| `session`, plus `session_id` / `cmd` / `user` / `src_ip` / `protocol`. `stage` omitted or `null`. |
| `sessions.jsonl` | Session-closed summaries. Same schema. `stage` null. |
| `meta.json` | Attestation (`honeypot.meta.v1`, `source: beelzebub`). Empty invents nothing. |

Do not stamp Palisade fields onto a Beelzebub export to make the
parser “light up.” If `source` / path is Beelzebub, stuffed
`stage: 1` / `stage: 2` is ignored.

## Rails

- Parse-only. This pack does not run Beelzebub, Palisade, or any trap.
- Not an 11th compose service. Not a farm slot.
- Demo fixture rows carry `demo: true` → canonical `demo` labels.
  SAMPLE ≠ client estate.
- Never POST `/api/risks`. Paying-day is not a PASS stamp.

Lane map: [EVIDENCE_MATRIX.md](EVIDENCE_MATRIX.md).
