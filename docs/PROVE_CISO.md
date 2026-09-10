# CISO Assistant export prove (SAMPLE/DEMO)

One honest file-drop prove: fixture **Covey pack_drop** + **Palisade/Beelzebub
honeypot** → existing collectors → `grc_loader` → **`out/ciso-assistant/*.csv`**.

This is not a client estate. It is not a paying-day PASS. HITL stays required
before any live PATH tool or `CISO_PUSH`. RiskReady wrap stays review-only —
never POST `/api/risks`.

## Exact commands

From the clone root. Desktop has no `make` / `gh` — the `python3` line is enough.

```bash
export PYTHONPATH="$PWD"
export DRY_RUN=1 GRC_LIVE_SCAN=0 CISO_PUSH=0 RISKREADY_PUSH=0 DROPBOX_LIVE=0
python3 scripts/prove_ciso.py
```

or `make prove-ciso`.

What that does (isolated under `prove/work/`, never pack `in/`):

1. Copy `fixtures/pack_drop/nmap/` → `prove/work/in/nmap/pack_drop/`
2. Copy `fixtures/pack_drop/rustscan/` → `prove/work/in/nmap/pack_drop/rustscan/`
   (stdout-class Covey `export_pack`; `evergreen.pack_drop.v1`)
3. Copy `fixtures/pack_drop/httpx/` → `prove/work/in/nmap/pack_drop/httpx/`
   (stdout-class Covey `export_pack`; `evergreen.pack_drop.v1`)
4. Copy `fixtures/pack_drop/unicornscan/` → `prove/work/in/nmap/pack_drop/unicornscan/`
   (stdout-class Covey `export_pack`; `evergreen.pack_drop.v1`)
5. Copy `fixtures/demo/honeypot/` → `prove/work/in/honeypot/` (Palisade stages)
6. Copy `fixtures/demo/honeypot_beelzebub/` → `prove/work/in/honeypot/pack_drop/`
   (Beelzebub login/cmd/session; `stage` null)
7. Stamp `SAMPLE.txt` (`SAMPLE/DEMO — not a client estate`)
8. Run the existing SoR path: `run_ciso_path` (same as `python3 -m dropbox ciso`)
9. Write `prove/work/out/ciso-assistant/*.csv` and `prove/work/prove-ciso.json`

Operator-shaped equivalent after the seed (same SoR, still dry):

```bash
python3 -m dropbox ciso \
  --scope dropbox/SCOPE.yaml \
  --in-dir prove/work/in \
  --out-dir prove/work/out
# Desktop: clica  or  bash push_ciso.sh   (posted:false unless CISO_PUSH=1)
python3 -m dropbox mcp export_ciso_poam
```

Pytest lock: `python3 -m pytest tests/test_prove_ciso.py -q`

## Honesty limits

| Claim | Truth |
|---|---|
| Estate | **SAMPLE/DEMO ≠ client.** Fixtures only. |
| Paying-day | **FAIL.** This prove does not stamp PASS. HITL + real KEEP `in/` + compose-on-Docker still open. |
| SoR | `out/ciso-assistant/*.csv` (here: `prove/work/out/ciso-assistant/`) |
| Posted | `false` unless an operator sets `CISO_PUSH=1` and `DRY_RUN!=1` |
| RiskReady | Review-only. `RISKREADY_PUSH` ignored. No wrap. No `/api/risks`. |
| Pack `in/` | Read-only. Prove never writes it. |
| Live scan | Never. Parse-only. No Covey/Nmap/honeypot spawn. |
| Catalog | Unchanged. No new collector. Honeypot is not an 11th compose service. |
| KEEP-minimum | Unchanged. Pack_drop/honeypot are already-on-disk sensor dirs, not new schedule slots. |

CoS #22 honesty sync. Pack HEAD `eedca686` (PR #33 httpx
pack_drop→CISO already on master). Covey HEAD still `30d2197f`
multi-adapter pack_drop export for all 16 `E2E_PROVEN`. Item
**COS21-PACK-DROP-HTTPX** = DONE. CoS #22 item 2 lifts unicornscan
stdout-class `fixtures/pack_drop/unicornscan/` into CISO prove. Stop for
CoS #23. 20-adapter lane **CLOSED**
stands. Covey `E2E_PROVEN` sixteen-set
remains: nmap + rustscan + fping + naabu + nping + httpx + sslscan +
tlsx + whatweb + hping3 + onesixtyone + nbtscan + braa + ike-scan +
svmap + unicornscan. UNPROVEN fail-closed: masscan, arp-scan,
netdiscover, zmap — do not claim a 17th live. Pack does not start
Covey adapter work. Tests/docs only. Reid-only blockers remain (CTA;
real KEEP `in/`; Eval `npm start`; compose on a Docker host — this VM
`compose_lab` absent ≠ PASS).

Lane map: [COVEY_PACK_DROP.md](COVEY_PACK_DROP.md), [EVIDENCE_MATRIX.md](EVIDENCE_MATRIX.md).
CSV headers: [../schemas/ciso-assistant.md](../schemas/ciso-assistant.md).
