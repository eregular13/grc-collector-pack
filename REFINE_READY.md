# REFINE_READY (24h refine scorecard)

written_at: 2026-09-08T18:30:23-07:00
window: 24h-refine (R01–R23; R24 is hard-stop only)
hard_stop: 2026-09-08T21:18:00-07:00
version: 0.5.0-rc.2
github_repo: eregular13/grc-collector-pack
github_branch: ship-0.4.0
github_sha: ab121a4f6bdae0cd18c5a4b540692c023bed9abb
github_url: https://github.com/eregular13/grc-collector-pack/commit/ab121a4f6bdae0cd18c5a4b540692c023bed9abb
client_facing_ready: false
paying_day: NO
pack_mapped: 10
poam_rows: 10
pytest: 301
extras_down: yes
estate: 127.0.0.1:18081 / :18082 / :18443 (grc-estate, 172.28.90.0/24)
sink: 127.0.0.1:18080 received 0; GET+POST /api/risks 403
posted: []
facing: false
blocked_by: lab_sim_not_client_estate
scheduler: armed until R24 hard stop (do not cancel here)

Software bar only. Docker-sim is not a paying client. HITL remains lab-sim.

## Torn down (R01–R02)

`compose down -v` on 24 extra 24h/eval/xwait/honeypot farms. Host free RAM 8.8 → 14.2 GiB. Main `grc-estate` + `mock_sink` kept.

Projects/classes torn down (not left running): eval, xwait, honeypot, expired, weak, mismatch, dirlist, status, git, cookie, cors, env, bak, phpinfo, metrics, openapi, basic, sourcemap, actuator, graphql, key, kube, tfstate, dockercfg.

No leftover `172.28.110+` containers or nets. Only 172.28 net is `grc-estate` `172.28.90.0/24`. 24h yml files may still sit under `product-lab/24h/` on disk; none running. Did not down aegis / LocalGrokLoop / `C:\Users\R` pack leftovers.

## Folded onto MAIN estate (not new 3GiB farms)

| Tick | Class | Estate path | Notes |
| --- | --- | --- | --- |
| R04 | Git metadata exposed | `/.git/HEAD` (alias `estate/web/git-meta/`) | dummy refs; not a nested git dir |
| R05 | Directory listing enabled | `/listing/` autoindex | root still `index.html` |
| R06 | Insecure session cookie | `/cookie` | `Set-Cookie: session=labonly; Path=/` (no Secure/HttpOnly) |
| R07 | Permissive CORS policy | `/cors` | `Access-Control-Allow-Origin: *` |
| R08 | Environment file exposed | `/.env` | `estate/web/env-meta/lab.env`; values `[REDACTED]` |

Already live on the same estate (pre-refine): Cleartext HTTP; Missing HSTS; Missing web security headers; Server banner disclosure; Untrusted TLS certificate.

`pack_mapped` 5 → 10. Live mapped_classes (product_demo stdout): Cleartext HTTP; Missing HSTS; Missing web security headers; Server banner disclosure; Git metadata exposed; Directory listing enabled; Environment file exposed; Insecure session cookie; Permissive CORS policy; Untrusted TLS certificate.

## Not folded

- **R09 skip:** expired / hostname-mismatch cert not installed on `:18443`. Host curl (Windows schannel) reports `SEC_E_UNTRUSTED_ROOT` first even with a 2020-expired cert; `parse_curl_tls` is if/elif so one TLS class per URL. Untrusted TLS already mapped. Restored original `-days 2` CN=localhost. No second 172.28.140/170 farm.
- 24h zoo leftovers not folded: bak, phpinfo, metrics, openapi, basic-auth, sourcemap, actuator, graphql, private key, kubeconfig, tfstate, dockercfg, honeypot, weak ciphers, Cowrie. No R25 Cowrie on the LAN.

## Product refine (R10–R22)

- R10 UNMAPPED audit: folded + live web/TLS classes have CPG+CSF. Unknown HTTP widget stays UNMAPPED with `unmapped_reason`. HTTP is not SMBv1 / 445.
- R11 `product_demo` lists `mapped_classes`; `--help` sink delta 0.
- R12 slug zip POA&M has all 10 rows; survives `run_lab.ps1` pack `out/poam` SMBv1 overwrite. `package_slug` writes `engagement-<slug>-ready.zip`.
- R13 SimpleRisk leave-behind is estate slug / out-estate / zip member (not pack fixture SMBv1).
- R14 `PRODUCT.md` + `CLIENT_READY.md` + `docs/CLIENT_ASSESS.md` stamp `pack_mapped: 10`.
- R15 estate-down fail-closed (`estate_down` exit 2; no Litware-as-estate). Same containers started back.
- R16 SCOPE + `192.168.10.0/24` (and overlapping hosts/CIDRs) `forbidden_cidr` plan-only. nmap never execs. Live SCOPE stays `172.28.90.0/24`. SCOPE.example untouched.
- R17 WRAP_DEAD; sink `/api/risks` 403; forbidden POSTs do not increment `received`.
- R18 QUICKSTART literal from `_refine/quick` copy; skip compose from a second copy when estate already answers `:18081`.
- R19 CI `.github/workflows/lab.yml` valid; pytest collection ≥ 229.
- R20 VERSION `0.5.0-rc.2` (this github_sha). Historical `DONE_24H.md` stays rc.1 / pack_mapped 5.
- R21 two `run_lab.ps1` LAB_GREEN (pytest 300 ×2). No pack commit.
- R22 full `product_demo` pack_mapped 10, poam_rows 10, facing false, posted []. No pack commit.

## GitHub (`ship-0.4.0`)

Product freeze (R20; R21–R22 docs-only ticks, no pack commit):

`ab121a4f6bdae0cd18c5a4b540692c023bed9abb` — R20: VERSION 0.5.0-rc.2 after refine code landed.

| sha | item |
| --- | --- |
| 6ef0953 | R04 fold dummy .git |
| 5b8af22 | R05 fold autoindex /listing/ |
| 47da86f | R06 fold insecure Set-Cookie /cookie |
| 45cc568 | R07 fold CORS * /cors |
| bff3247 | R08 fold dummy redacted /.env |
| 041d904 | R09 skip expired/mismatch on :18443 |
| 48395ff | R10 UNMAPPED audit |
| b0502a7 | R11 mapped_classes + --help sink delta 0 |
| 03d6998 | R12 slug zip POA&M / ready.zip |
| d97e481 | R13 SimpleRisk estate rows |
| c7de4c2 | R14 docs pack_mapped 10 |
| 3a21953 | R15 estate-down fail-closed |
| e021ed4 | R16 LAN refuse |
| c3480f4 | R17 WRAP_DEAD + /api/risks 403 |
| 3227c56 | R18 QUICKSTART copy-folder |
| 29441ef | R19 CI + collection ≥ 229 |
| ab121a4 | R20 VERSION 0.5.0-rc.2 |

Never master. Never `C:\Users\R\grc-collector-pack`. `PUSH_OK.txt` present; origin/ship-0.4.0 matched this sha at scorecard time.

## Safety (still)

DRY_RUN=1 CISO_PUSH=0 RISKREADY_PUSH=0 GRC_LIVE_SCAN=0. EVERGREEN_ORCH_LIVE unset when idle. No office LAN scan. No POST `/api/risks`. No compose c11. Do not flip `client_facing_ready`. No T25 whoami. No R25 Cowrie.

## Gaps (not paying-day)

No signed live drop box. HITL is lab-sim. Mock sink is not CISO Assistant Community. Office LAN never in SCOPE. Quote hours blank. R24 still owns scheduler cancel + `DONE_24H_REFINE.md`.
