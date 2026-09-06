# Farm quickstart (private drop-box)

**DEMO ≠ client estate.** Written consent first. This repo does not install scanners.
Defaults: `DROPBOX_LIVE=0` `GRC_LIVE_SCAN=0` `CISO_PUSH=0` `RISKREADY_PUSH=0`.

Honest stamp (cycle 81 freeze, host lab): pytest **320** + 1 skip. `make lab`
64 / 79 / 19 / 27 poam **82**. Catalog **111 / 32 wired / 30 invoke /
81 file_drop**. compose **ABSENT** (no Docker CLI — hole, not a PASS).
Wrap review-only. DEMO ≠ client. Paying-day **FAIL**. LICENSE-LOCK /
file_drop-only names never `will_run` or `live_ready`. `FARM_TOOL_BIN`
never resolves locked scanners.

1. **Consent** — store the signed memo next to the box; record its sha256.
2. **SCOPE** — copy `dropbox/SCOPE.example.yaml` → `dropbox/SCOPE.yaml`.
   Fill client, attestation hash, window, named CIDRs/hosts.
   Example does **not** allowlist nmap/nessus (not free-day live).
   `python3 -m dropbox gate`
3. **tool-bin** — DEMO: `farm/tool-bin/lab/` stubs. Real: you install;
   set `FARM_TOOL_BIN` or PATH. Never apt from this tree.
4. **DEMO quiet→loud** (`farm/work/e2e`, not pack `in/`):
   `python3 -m dropbox mcp farm_toolbin_status` then `make farm-toolbin-e2e`.
   Stubs may `will_run`; `live_ready_count` stays 0 on DEMO SCOPE.
5. **KEEP → Eval** (optional): `make keep-lab` → `keep/work/out/eval/handoff.json`
   (max-5). **SAMPLE ≠ client KEEP** until pack `in/` has the four exports.
6. **CISO zip** — `bash scripts/start-product.sh` → http://127.0.0.1:18765/
   Owner/due blank. Do not POST `/api/risks`. RiskReady is review-only.
7. **Real `--live`** — consented box, tools you installed, `live_ready_count` > 0:
   `python3 -m dropbox orchestrate --live`

Layers: [ARCHITECTURE.md](../dropbox/ARCHITECTURE.md) A / B / C.
Full runbook: [OPERATOR.md](OPERATOR.md).
