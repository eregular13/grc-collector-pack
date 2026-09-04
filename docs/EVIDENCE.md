# Evidence rows

An evidence row in `out/ciso-assistant/evidences.csv` and `out/riskready/evidence.json` is a **sensor-run attestation**, not a screenshot dump.

Each lab emits:

1. One row per collector that produced canonical records (`{source} collector run`).
2. One row per high/critical **family** (`source` + category/service/check) derived from existing findings. Descriptions list `ref_id`s and point at `out/canonical`. No new assets. No fake screenshots. No secrets.
3. One `grc-loader run` row for the normalize pass.

Names are unique. Floor after this pack: **≥ 18** evidence rows. That is still thinner than findings; it is enough to show which sensor and family produced the high/critical set.

Import these as CISO evidences or RiskReady `TECHNICAL` / `SENSOR` / `DRAFT` evidence. A human attaches screenshots later if the GRC requires them.
