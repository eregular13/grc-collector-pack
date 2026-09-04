# Farm quickstart (private drop-box)

**DEMO ≠ client estate.** Written consent first. This repo does not install scanners.

Honest stamp (cycle 75, host lab): pytest **318** + 1 skip. `make lab`
64 / 79 / 19 / 27 poam **82**. Catalog **111 / 32 wired / 30 invoke /
81 file_drop**. compose **ABSENT** (no Docker CLI — hole, not a PASS).
Wrap review-only. DEMO ≠ client. Paying-day **FAIL**. LICENSE-LOCK /
file_drop-only names never `will_run=true`. `FARM_TOOL_BIN` never
resolves locked scanners.

1. **Consent** — store the signed memo next to the box; record its sha256.
2. **SCOPE** — copy `dropbox/SCOPE.example.yaml` → `dropbox/SCOPE.yaml`.
   Fill client, attestation hash, window, named CIDRs/hosts.
   Example does **not** allowlist nmap/nessus (not free-day live).
   `python3 -m dropbox gate`
3. **tool-bin**
   - DEMO: `farm/tool-bin/lab/` stubs (fixture stdout, no network).
   - Real: you install allowlisted binaries; set `FARM_TOOL_BIN` or PATH.
     Never apt from this tree. Do not commit ELF/deb packages.
4. **DEMO quiet→loud** (isolated `farm/work/e2e`, not pack `in/`):

   `make farm-toolbin-e2e`

   CISO CSVs + `poam.csv` land under `farm/work/e2e/out`. `demo: true`.
5. **CISO zip** — after outputs exist: `bash scripts/start-product.sh`
   → http://127.0.0.1:18765/ → download drop zip.
   Owner/due stay blank. Do not POST `/api/risks`. RiskReady is review-only.
6. **Real `--live`** — only on the consented drop box, after gate,
   with tools **you** installed:

   `python3 -m dropbox orchestrate --live`

Layers: [ARCHITECTURE.md](../dropbox/ARCHITECTURE.md) A / B / C.
Full runbook: [OPERATOR.md](OPERATOR.md).
