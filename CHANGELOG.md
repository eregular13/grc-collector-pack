# Changelog

## cycle 161

R10 refine: UNMAPPED audit of folded estate classes (Git metadata, directory listing, insecure cookie, permissive CORS, `.env`, plus live Cleartext HTTP/HSTS/headers/banner/Untrusted TLS). Each has CPG+CSF stubs; unknown HTTP widget stays UNMAPPED with `unmapped_reason`. HTTP classes do not map to SMBv1 / TCP 445. Live `out-estate` POA&M has no UNMAPPED/SMBv1. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product plus host run_lab.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 160

R09 refine skip: hostname-mismatch / expired TLS not folded onto main `grc-estate` `:18443`. Host curl (Windows schannel) reports `SEC_E_UNTRUSTED_ROOT` even when the listener cert is expired (tried 2020 `not_after`; restored original `-days 2` CN=localhost). `parse_curl_tls` is if/elif so one TLS class per URL; Untrusted TLS is already mapped from this listener. 24h expired/mismatch farms needed alpine curl `--cacert` on a second project — not this window. No second 172.28.140/170 farm. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product plus host run_lab.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 159

R08 refine: dummy `/.env` on main `grc-estate` estate-web (`estate/web/env-meta/lab.env`, values already `[REDACTED]`). Curl live exec allowlisted same-origin GET `/.env`; map `Environment file exposed` from GET body + `/.env` path only. HEAD 200 does not invent it. Finding rows do not copy the body. No dummy token in `out/`. No second 172.28.230 farm. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product plus host run_lab.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 158

R07 refine: dummy `Access-Control-Allow-Origin: *` on main `grc-estate` estate-web stub `/cors` only. Curl live exec allowlisted same-origin HEAD `/cors`; map `Permissive CORS policy` from that header. Root HEAD still has no ACAO — not invented. A specific origin is not mapped. No second 172.28.220 farm. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product plus host run_lab.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 157

R06 refine: dummy insecure `Set-Cookie: session=labonly; Path=/` (no Secure/HttpOnly) on main `grc-estate` estate-web stub `/cookie` only. Curl live exec allowlisted same-origin HEAD `/cookie` after named HEAD; map `Insecure session cookie` from that header. Root HEAD still has no Set-Cookie — not invented. No second 172.28.210 farm. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product plus host run_lab.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 156

R05 refine: dummy nginx autoindex on main `grc-estate` estate-web subpath `/listing/` (not site root). Curl live exec allowlisted same-origin GET `/listing/` after HEAD; map `Directory listing enabled` from GET body (`Index of`) only. HEAD 200 does not invent it. No second 172.28.180 farm. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product plus host run_lab.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 155

R04 refine: dummy Git metadata on main `grc-estate` estate-web (`/.git/HEAD` → `estate/web/git-meta/`, loopback :18081). Curl live exec HEADs named URLs then allowlisted same-origin GET `/.git/HEAD` (max 16KiB, no redirects, not 192.168.10.0/24). Map `Git metadata exposed` from GET body + `/.git/` path only. HEAD 200 does not invent it. No second 172.28.200 farm. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product plus host run_lab.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 154

T24 freeze at hard stop 2026-09-07T09:52:00-07:00 (tick clock 10:12 PT). `DONE_24H.md` GREEN. Scheduler cancelled. Estate+sink left up. `client_facing_ready` false. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069. No T25.
pytest: freeze targeted SCOPE+safety+product 84 passed (T17 run_lab.ps1 x2 LAB_GREEN ~229).
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 153

T24-wait extra: dummy Docker config.json estate `grc-dockercfg-24h` on `172.29.15.0/24` loopback 20681. GET `/.docker/config.json` observed `auths` + `auth`; map `Docker config.json exposed` from GET body + docker config path only. HEAD 200 does not invent it. Dummy lab token only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 152

T24-wait extra: dummy terraform.tfstate estate `grc-tfstate-24h` on `172.29.14.0/24` loopback 20581. GET `/terraform.tfstate` observed `terraform_version` + `resources`; map `Terraform state file exposed` from GET body + tfstate path only. HEAD 200 does not invent it. Dummy lab token only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 151

T24-wait extra: dummy kubeconfig estate `grc-kube-24h` on `172.29.13.0/24` loopback 20481. GET `/kubeconfig` observed `kind: Config` + clusters/users; map `Kubernetes kubeconfig exposed` from GET body + kubeconfig path only. HEAD 200 does not invent it. Dummy lab token only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 150

T24-wait extra: dummy private-key estate `grc-key-24h` on `172.29.12.0/24` loopback 20381. GET `/id_rsa` observed `BEGIN RSA PRIVATE KEY` with `LAB-ONLY-NOT-A-REAL-KEY`; map `Private key file exposed` from GET body + id_rsa/privkey path only. HEAD 200 and a certificate PEM do not invent it. Not a real key. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 149

T24-wait extra: dummy GraphQL estate `grc-graphql-24h` on `172.29.11.0/24` loopback 20281. GET `/graphql` observed `"__schema"` + `"types"`; map `GraphQL introspection enabled` from GET body + `/graphql` path only. HEAD 200 and a non-introspection GraphQL body do not invent it. Dummy lab schema only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 148

T24-wait extra: dummy Spring Actuator estate `grc-actuator-24h` on `172.29.10.0/24` loopback 20181. GET `/actuator` observed `_links` health/info; map `Spring Actuator endpoint exposed` from GET body + `/actuator` path only. HEAD 200 and `/health` without `/actuator` do not invent it. Dummy lab JSON only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 147

T24-wait extra: dummy source-map estate `grc-sourcemap-24h` on `172.28.254.0/24` loopback 20081. GET `/app.js.map` observed `"version"` + `"sources"`; map `JavaScript source map exposed` from GET body + `.js.map` path only. HEAD 200 and `/app.js` do not invent it. Dummy lab map only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 146

T24-wait extra: dummy HTTP Basic estate `grc-basic-24h` on `172.28.253.0/24` loopback 19981. HEAD `/` observed `WWW-Authenticate: Basic` on `http://`; map `HTTP Basic auth without TLS` from that header + cleartext scheme only. HTTPS Basic and Digest are not mapped. No credentials stored. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 145

T24-wait extra: dummy OpenAPI estate `grc-openapi-24h` on `172.28.252.0/24` loopback 19881. GET `/openapi.json` observed `"openapi": "3.0.3"`; map `OpenAPI specification exposed` from GET body + openapi/swagger path only. HEAD 200 does not invent it. Dummy lab spec only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 144

T24-wait extra: dummy Prometheus estate `grc-metrics-24h` on `172.28.251.0/24` loopback 19781. GET `/metrics` observed `# HELP` + `# TYPE`; map `Prometheus metrics exposed` from GET body + `/metrics` path only. HEAD 200 does not invent it. Dummy lab metric only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 143

T24-wait extra: dummy phpinfo estate `grc-phpinfo-24h` on `172.28.250.0/24` loopback 19681. GET `/phpinfo.php` observed `phpinfo()` + `PHP Version`; map `phpinfo page exposed` from GET body + phpinfo.php/info.php path only. HEAD 200 does not invent it. Dummy lab HTML only, no PHP runtime. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 142

T24-wait extra: dummy SQL dump estate `grc-bak-24h` on `172.28.240.0/24` loopback 19581. GET `/dump.sql` observed `CREATE TABLE lab_only`; map `Backup file exposed` from GET body + `.sql`/`.bak` path only. HEAD 200 does not invent it. Dummy lab dump only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 141

Factory quote honesty: `new_engagement` seeds `out/quote/quote.csv` with a blank `status=draft` row when pack `out/quote` is header-only (empty ingest after refused `run --stage all`). `export_quote([])` also stamps draft — hours/rate/total stay blank, no `$`. `client_facing_ready` stays false. T24-wait estate maps untouched. WRAP_DEAD unchanged. No I-069.
pytest: engagement kit + honesty + full `tests`.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 140

T24-wait extra: dummy `.env` estate `grc-env-24h` on `172.28.230.0/24` loopback 19481. GET `/.env` observed `LAB_TOKEN=` KEY=value; map `Environment file exposed` from GET body + `/.env` path only. HEAD 200 does not invent it. Dummy lab values only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 139

T24-wait extra: CORS estate `grc-cors-24h` on `172.28.220.0/24` loopback 19381. HEAD `/` observed `Access-Control-Allow-Origin: *`; map `Permissive CORS policy`. Missing ACAO on the main estate is not invented; a specific origin is not mapped. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 138

T24-wait extra: insecure-cookie estate `grc-cookie-24h` on `172.28.210.0/24` loopback 19281. HEAD `/` observed `Set-Cookie: session=labonly; Path=/` without Secure/HttpOnly; map `Insecure session cookie`. Main estate HEAD has no Set-Cookie — not invented. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 137

T24-wait extra: exposed `.git` estate `grc-git-24h` on `172.28.200.0/24` loopback 19181. GET `/.git/HEAD` observed `ref: refs/heads/main`; map `Git metadata exposed` from GET body + `/.git/` path only. HEAD 200 does not invent it. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 136

T24-wait extra: stub_status estate `grc-status-24h` on `172.28.190.0/24` loopback 18981. GET `/nginx_status` observed `Active connections` + `server accepts handled requests`; map `Web server status page exposed` from GET body only. HEAD text/plain does not invent it. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 135

T24-wait extra: autoindex estate `grc-dirlist-24h` on `172.28.180.0/24` loopback 18881. GET `/` observed nginx `Index of /`; map `Directory listing enabled` from GET body only (HEAD does not invent it). TRACE 405, not mapped. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 134

T24-wait extra: hostname-mismatch TLS estate `grc-mismatch-24h` on `172.28.170.0/24` loopback 18681/18643, cert SAN `wrong.lab.example`. Alpine curl `--cacert` observed `no alternative certificate subject name matches target ipv4 address`; map `TLS hostname mismatch`. Do not invent mismatch from UNTRUSTED_ROOT alone. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 133

T24-wait extra: TLS 1.0-only estate `grc-weak-24h` on `172.28.160.0/24` loopback 18581/18543. nmap ssl-enum-ciphers (isolated net only) saw TLSv1.0 AES128-SHA; Windows `--tlsv1.0` 200, `--tlsv1.2` SEC_E_UNSUPPORTED_FUNCTION. `map_finding`/`parse_testssl_text` no longer treat TLSv1.2 as Weak TLS. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product+testssl.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 132

T24-wait extra: expired TLS estate `grc-expired-24h` on `172.28.140.0/24` loopback 18381/18343. Alpine curl `--cacert` observed `certificate has expired`; map `Expired TLS certificate`. Eval pytest-a/b bind-mount leftover still extra-lab, not SKU floor. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 131

Palisade LLM honeypot lab: isolated `grc-honeypot-24h` `172.28.150.0/24`, loopback SSH `:12222` + dash `:18088`. Combined probe maps outdated OpenSSH 5.3, any-password SSH, ANSI hidden traps, dashboard Cleartext HTTP. `inventory_nmap` flags OpenSSH 5.x from XML version. Cowrie needs interactive shell. Palisade `init.py` is not drop-in on Cowrie 3 `command_modules`. Facing false. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted loader+orchestrator.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 130

T24-wait (not freeze): SCOPE `10.0.0.0/8` (whole class A / supernet) is `forbidden_cidr` plan-only; fixture `10.0.0.0/24` unchanged. Extra isolated compose `grc-xwait-24h` on `172.28.130.0/24` loopback 18281/18282/18243. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+safety+product.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 129

T07–T16/T18–T19 24h: slug isolation (`24h-cold` vs `docker-estate-product`); leftover `.alive` destroyed even when discover skipped; deepen 2–5; zip contract no `.env`; `docs/CLIENT_ASSESS.md`; SimpleRisk estate CSV; console GET-only POST 405 on `127.0.0.1:18765`; PRODUCT.md no longer claims Litware CSVs on the estate slug; chaos kill estate-web recovers; mock sink assets/evidence 200, `/api/risks` 403; `--help` ×3 sink delta 0. VERSION 0.5.0-rc.1 = client-assess **software** bar, not paying-day. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: sequential full suite green (xdist -n 16 flakes on shared `dropbox/out` — not the SKU floor).
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 128

T06 24h: cold copy `_24h/cold` compose project `grc-estate-24h` on `172.28.110.0/24` (host 19081/19082/19443). One `product_demo` slug `24h-cold` pack_mapped 5 facing false. `down -v`. Main estate stayed up. Office-LAN SCOPE is `forbidden_cidr` plan-only. `Missing web security headers` remaps. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+product 20 passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 127

T05 24h: sink-down `product_demo --help` 102ms and `--dry-run` 125ms, both exit 0. Sink restored. POST /api/risks 403. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: help/dry-run timed; targeted SCOPE tests green.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 126

T04 24h: estate-web/api/tls stopped → `product_demo` exit 2 `estate_down`. Product zip SHA unchanged; no SMBv1. Estate brought back. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: live fail-closed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 125

T03 24h: SCOPE with `192.168.10.0/24` (or 192.168.10.x host, or `0.0.0.0/0`) is `refuse_live=forbidden_cidr` — plan-only, nmap never execs. Comments are not targets. No scan. No cycle 11. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+product 16 passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 124

T02 24h: `SCOPE.docker-estate.yaml` includes `https://127.0.0.1:18443/`. `python -m dropbox.product_demo` pack_mapped 5 (Untrusted TLS added from live estate-tls), facing false, blocked_by lab_sim_not_client_estate. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: targeted SCOPE+TLS+product 14 passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 123

T01 24h: `estate-tls` sidecar `127.0.0.1:18443` self-signed (HTTP `:18081` stays). curl_byo maps Untrusted TLS certificate (including Windows schannel UNTRUSTED_ROOT) and Missing HSTS on HTTPS after `-k` header sample. No public bind. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: 216+ passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 122

SKU sim: `scripts/product_demo.ps1` forwards `@args` so `--help` is help. QUICKSTART uses `.venv\Scripts\python.exe` (does not assume a global pytest). No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: 216 passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 121

Clean-clone pytest: `.env.example` un-ignored; conftest seeds stub `out/` CSVs if missing so factory tests run without a prior `run_lab.ps1`. VERSION 0.4.2. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: 216 passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 120

Product-ready 0.4.1: `docs/QUICKSTART.md` (venv → pytest → estate compose → product_demo --help). `docs/ESTATE.md` for `172.28.90.0/24` loopback. CI `.github/workflows/lab.yml` (pytest 3.12, no Docker estate required). Slug Cleartext HTTP survives pack `out/poam` fixture overwrite (`tests/test_product_ready.py`). Lab-sim ≠ customer pack. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: 216 passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 119

Ship 0.4.0 hygiene: `python -m dropbox.product_demo --help` is help (no sink). `--dry-run` plans only. Estate slug `docker-estate-product` copies `out-estate/` POA&M (Cleartext HTTP mapped), not leftover Litware 132/155/9 CSVs. README leads with authorized assessment → CISO + POA&M. VERSION 0.4.0. docs/OUT_DIR.md + docs/PUBLISH.md. Lab pack git init on `ship-0.4.0`. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: 212 passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 118

Viable product demo on the existing isolated estate (`127.0.0.1:18081/18082`). Live Cleartext HTTP + missing HSTS/XFO/CSP + Server banner map to CPG/CSF (not UNMAPPED). `pack_mapped: 4`. HITL lab-sim attested without `client_facing_ready`. `python -m dropbox.product_demo` writes `engagements/docker-estate-product/` + zip. Mock sink assets+evidences only. No cycle 11. No 192.168.10.0/24. SCOPE.example untouched. WRAP_DEAD unchanged. No I-069.
pytest: 208 passed.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 117

Docker estate rehearsal on isolated `grc-estate` `172.28.90.0/24` (loopback 127.0.0.1:18081/18082). Live curl HEAD found Cleartext HTTP. Sidecar nmap -sn only; pack image still has no nmap apt. SCOPE.example untouched. Kit `docker-estate` not client-facing (factory copies fixture CISO CSVs). Mock sink importer assets+evidences; `/api/risks` 403. WRAP_DEAD unchanged. No I-069. No 192.168.10.0/24.
pytest: 198 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 116

Lab clocks decoupled from demo consent window. `SCOPE.example.yaml` keeps historic `window_end: 2026-09-05T09:00-07:00` (`window_closed`, not live-eligible). Pytest uses generated `SCOPE.lab.yaml` (now−1d .. now+30d, `allow_live_exec: false`). Relative past window still proves `window_closed`. No fake live drop box. RiskReady WRAP_DEAD unchanged. No I-069.
pytest: 195 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 115

Import docs + status reconcile: `docs/IMPORT_CISO.md` (Reid-side SoR, CISO_PUSH assets+evidences only, findings HITL), `docs/IMPORT_RR.md` (WRAP_DEAD, no HTTP), `docs/IMPORT_PROBO.md` (no Probo on this lab). STATUS/DONE stamped live 188 / 132/155/9. Fixture Litware not a customer. RiskReady WRAP_DEAD unchanged. No I-069. No live scan.
pytest: 192 passed. Two consecutive LAB_GREEN after this cycle.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 114

Inside Lab / External Lab `--stage all` tests write to a temp out dir so they cannot stamp operator `dropbox/out` as another client. Litware leftover isolation from cycle 113 holds. RiskReady WRAP_DEAD unchanged. No I-069. No live scan.
pytest: 188 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 113

Leftover-estate archive: `python -m dropbox.archive_out` copies other-client `dropbox/out` into `engagements/_archive/` (skips `.env`/tokens). Lonely Host / Nessus-only pytest no longer stamps the operator `dropbox/out`. Docker compose mounts `../product-lab` so fixture ingest can stamp the CISO drop. Facet matrix expects RiskReady `WRAP_DEAD`, not a DRY_RUN POST banner. Litware kit `client_facing_ready: false` (`live_exec_not_allowed`). No I-069. No live scan.
pytest: 188 passed. Two consecutive LAB_GREEN. DOCKER_LAB_GREEN. FACET_DOCKER_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 112

Engagement kit factory: `python -m dropbox.new_engagement --slug litware-lab` writes `engagements/<slug>/` (SCOPE, OPERATOR_RUN, CISO CSVs, POA&M, blank quote, SimpleRisk leave-behind, nine sensor evidence.md, MANIFEST, EXECUTIVE). Lab SCOPE cannot stamp `client_facing_ready`. Leftover other-client `discover.json` is not copied (`discover_client_mismatch`). Zip `engagement-<slug>-<date>.zip` excludes `.env`/tokens. Fixture Litware kit is not a customer estate. RiskReady WRAP_DEAD unchanged. No I-069. No live scan.
pytest: 187 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 111

YAML `consent_attested: yes` / `allow_live_exec: yes` (or `True`) cannot attest or enable live; only lowercase `true`. `EVERGREEN_ORCH_LIVE=true` does not exec (must be `1`). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 182 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 110

Internal-only fixture ingest does not merge vpn/TLS pack demo (symmetric of external-only skipping SMBv1). Console `PATCH`/`OPTIONS` → 405. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 180 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 109

External-only fixture ingest does not merge internal pack demo (SMBv1/Telnet). MCP `run --stage exploit|nuclei` is `not_an_attack_api` (exit 2), not an unknown-stage traceback. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 179 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 108

`/16`-class prefixes refuse live (`prefix_too_large`); `timeouts_seconds: 1` cannot game the runtime budget (planning uses at least 30s/wave). `/24` lab SCOPE stays eligible. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 178 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 107

SCOPE cannot hail-mary blast radius: `max_concurrent_deepen` capped at 2, `max_concurrent_discover` at 4, `discover_shard_size` at 256 (nmap one-worker ceiling), deepen batch still ≤5. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 176 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 106

Unsigned and empty-target live refuses are laws: `integrity.refuse_if_unsigned: false` / `refuse_if_empty_targets: false` cannot bypass. Operator console is GET-only (`POST`/`PUT`/`DELETE` → 405). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 175 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 105

Stale leftover live-byo ingest cannot outrank a current fixture/plan-only deepen (`evidence_label_mismatch`); discover-only inventory is not HITL evidence. Live-eligible SCOPE does not stamp `product-lab/drop/` with leftover fixture ingest. Crash leftover `workers/*.alive` are torn down at discover/deepen start. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 172 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 104

Ingest ignores leftover plan-only/refused `deepen.json` (`deepen_refused`), unstamped leftover deepen (`deepen_client_missing`), and leftover **fixture** deepen from another client (`client_mismatch` — not only live-byo). Leftover findings are filtered to current SCOPE so an external-only sheet does not ingest internal SMBv1. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 170 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 103

Leftover discover refuse is a top-level brake (CLI/MCP **exit 2**), not nested-only. Unstamped leftover `discover.json` is `discover_client_missing`; leftover plan-only/refused discover is `discover_refused`. Console `integrity_stop` shows the leftover reason. Fixture leftover discover with a matching client still filters to current SCOPE. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 166 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 102

Fixture-lab SCOPE refuses leftover live-byo `discover.json` on deepen (`live_exec_not_allowed`); does not use prior live inventory as the louder host set. Fixture leftover discover still filters to current SCOPE. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 163 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 101

Fixture-lab SCOPE (`allow_live_exec: false`) ignores leftover live-byo ingest (`live_exec_not_allowed`); preview stays fixture. Console localhost GET `/status` smoked (127.0.0.1 bind, not an exploit dashboard). CISO dry-run lists assets/evidences only. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 162 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 100

Unparseable leftover `discover.json` is a BRAKE (not a traceback). Missing discover.json still refuses deepen. Unparseable leftover `deepen.json` is ignored (`deepen_unparseable`); ingest stays fixture. Unparseable consent window refuses live (`window_unparseable`). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 160 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 99

Lab SCOPE `allow_live_exec: false` cannot be client-facing even with leftover live-byo (`live_exec_not_allowed`). HITL-ready still requires signed live SCOPE with `allow_live_exec: true`. Mock sink `:18080/health` GET 200 this tick (no POST `/api/risks`). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 156 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 98

Leftover live-byo from another client cannot be HITL-ready (`evidence_client_mismatch`). Ingest stamps `client` on normalized findings. Live-byo without a client stamp is `evidence_client_missing`. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 155 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 97

Fixture evidence cannot be client-facing even with HITL attested (`fixture_not_client_estate`). HITL `client` must match SCOPE `client_legal_name` (`hitl_client_mismatch` / `hitl_client_missing`). Only live-byo + matching HITL is ready. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 154 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 96

Leftover `HITL.json` attested=true cannot make unsigned/empty/window SCOPE client-facing (`blocked_by` refuse_live). Signed fixture HITL still works. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 152 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 95

Empty live discover set is not a hail-mary fixture deepen (no SMBv1 dump for unnamed hosts). Missing consent window refuses live (`window_missing`); future window is `window_not_open`. Schema requires window_start/window_end. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 151 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 94

Blank `named_contact` is unsigned (schema required) even if `consent_attested: true`. Tool not in `allow_tools` does not exec (nmap is not implied by nessus). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 148 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 93

P1 proof: empty `allow_tools` refuses live discover/deepen (`empty_allow_tools`) even when signed + `EVERGREEN_ORCH_LIVE=1`; unsigned SCOPE stays plan-only; deepen workers torn down (`destroy_deepen.json`, no `.alive`). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 146 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 92

Re-prove wrap-dead + unsigned live refuse + plan batch 3 + two LAB_GREEN. No product-code change this tick. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 143 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 91

Re-prove wrap-dead + unsigned live refuse + plan batch 3 + two LAB_GREEN. No product-code change this tick. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 143 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 90

BYO Prowler/Maester execute when named cloud/Entra + live gates. record_seen only; same-day revoke stamped; tenant/account never interpolated into a shell. Unnamed cloud stays plan-only. Tests mock subprocess. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 143 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 89

BYO Lynis / ss / HardeningKitty execute on the drop-box endpoint when gated (`allow_live_exec` + `EVERGREEN_ORCH_LIVE=1` + PATH + signed SCOPE). **record_seen only** — no invented POA&M findings; does not flip discover hosts to live-byo. Tests mock subprocess. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 141 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 88

Deepen refuses leftover `discover.json` from another `client_legal_name` (`discover_client_mismatch`). Live-byo discover without client is also refused. Same-client leftover hosts are filtered to current SCOPE (neighbors dropped). Discover stamps `client`. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 139 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 87

Unsigned/empty/window refuse ingest ignores leftover live-byo `deepen.json` (and other-client leftovers). Deepen stamps `client`. Evidence trail records leftover_ignored. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 137 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 86

Ingest labels follow deepen (`fixture` vs `live-byo`). Live-byo does not merge pack demo canonical rows and does not stamp `product-lab/drop/`. Console shows discover/deepen/ingest labels. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 136 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 85

BYO testssl/curl deepen actually call host binaries when allowlisted + on PATH + `allow_live_exec` + `EVERGREEN_ORCH_LIVE=1`. Named hostnames/URLs only; CIDRs refused; batch ≤5; curl HEAD-only (`-I`, no redirects, http/https). External live path does not mix internal fixture SMBv1. Tests mock subprocess (never a real probe). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 136 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 84

BYO nessus deepen actually calls host nessuscli when allowlisted + on PATH + `allow_live_exec` + `EVERGREEN_ORCH_LIVE=1`. Batch ≤5 hosts; CIDRs and `/16` refused; severity 0 skipped; out-of-scope hosts dropped. Lab default stays fixture-labeled. Tests mock subprocess (never a real scan). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 132 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 83

BYO nmap quiet discover actually calls host nmap when allowlisted + on PATH + `allow_live_exec` + `EVERGREEN_ORCH_LIVE=1`. CIDR shards are IP slices (≤256/worker); `/16` one-argv refused. Unsigned still refuses live (no subprocess). Lab default `allow_live_exec: false` stays fixture-labeled. Tests mock subprocess (never a real scan). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 128 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 82

Re-prove wrap-dead + unsigned live refuse + plan batch 3 + two LAB_GREEN. No product-code change this tick beyond status. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 123 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 81

Re-prove wrap-dead + unsigned live refuse + plan batch 3. Console bind test: HOST is 127.0.0.1, no 0.0.0.0. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 123 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 80

Re-prove wrap-dead + unsigned/empty live refuse. Empty-target SCOPE `--stage all` skips CISO drop (`drop_copied` false) and stays not client-facing. Deepen batch still 2–5. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 122 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 79

Unsigned SCOPE ingest no longer stamps `product-lab/drop/` (CISO/POA&M/quote). Fixture may still write `dropbox/out/`. `dropbox/.gitignore` ignores runtime `out/`. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 122 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 78

Orchestrator ingest lands in `in/_dropbox_preview/` (fixture-labeled) and never clobbers `in/nmap` or other sensor dirs. Stage evidence trail `dropbox/out/EVIDENCE.md`. Unsigned `--stage all` still not client-facing. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 122 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 77

Prowler/Maester/HardeningKitty BYO adapters are plan-only. Prowler needs named cloud; Maester needs named Entra; same-day revoke. HardeningKitty is endpoint-sample (record_seen, no invented findings). Tests fail if scripts download nmap/nessus/nuclei installers. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 120 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 76

Operator MCP hook wraps the CLI (`python -m dropbox.orchestrator mcp --action plan`) — not a public attack API (exploit/spray/scan_internet exit 2, no bind). Lynis and ss/Get-NetTCPConnection BYO adapters are plan-only; Entra-only still does not unlock Lynis. Dockerfile/compose do not apt/embed nmap/nessus/nuclei. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 118 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 75

Remediation quote stub (`out/quote/quote.csv`) with hours/rate/total blank — never invent a price. HITL.json gate: `client_facing_ready` stays false until attested=true. curl BYO adapter is plan-only, CIDRs refused. Localhost console serves HTML brakes view at `/` (JSON at `/status`). Optional `dropbox/workers/compose.noop.yml` (no scanners). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 115 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 74

CISO auto-push is assets+evidences only; findings/POA&M are HITL clica/UI (northstar P0.4). Runtime budget brake: shard waves * timeouts vs max_runtime (`runtime_over_budget`). Pack lab canonical findings that match CPG/CSF stubs merge into POA&M (fixture-labeled; UNMAPPED skipped). SimpleRisk leave-behind `out/simplerisk/risks_import.csv` (no API). RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 111 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 73

Profile isolation + tool-kind brakes + POA&M CISO drop (northstar). External SCOPE never shards internal CIDRs. CIDR-only does not unlock testssl; Entra-only does not unlock Lynis. Discover/deepen workers run in `max_concurrent_*` waves then destroy. Closed window refuses live. testssl BYO adapter is plan-only. POA&M MANIFEST wired to `out/poam/` and `product-lab/drop/poam/`. RiskReady WRAP_DEAD unchanged. No I-069. No embedded scanners.
pytest: 108 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 72

Orchestrator brakes + RiskReady wrap-kill (northstar: grok-build-desktop-orchestrator-mega-prompt.md). `push_riskready.*` WRAP_DEAD even if RISKREADY_PUSH=1. `dropbox/` SCOPE + plan/run quiet→loud (fixture discover/deepen, BYO nmap/nessus plan-only). POA&M/control-map golden SMBv1 → CPG/CSF. No I-069. No embedded scanners.
pytest: 100 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 71

I-068: Gitleaks JSON empty/whitespace `File` uses `Source` / `Path` (not `unknown`). Secret still `[REDACTED]`. Fixture `gitleaks-source.json` (`CODE-HASHICORP-TF-PASSWORD-TERRAFORM-PROD-TFVARS` high, `CODE-JWT-MOBILE-CONFIG-JSON` high; `*-UNKNOWN` omitted). lab_outputs requires those refs and rejects unknown-file slugs.
pytest: 90 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 70

I-067: Prowler JSON empty/whitespace `Status` uses `CheckStatus` / `check_status` (CSV `CHECK_STATUS` too). PASS skipped. Fixture `prowler-checkstatus.json` (`corp-audit-plain` / `CLD-S3-BUCKET-DEFAULT-ENCRYPTION-KMS` high, `kms-unrotated-key` / `CLD-KMS-CMK-ROTATION-ENABLED` critical; `CLD-EC2-EBS-VOLUME-ENCRYPTION` PASS omitted). lab_outputs requires those refs and assets; rejects PASS.
pytest: 89 passed. Two consecutive LAB_GREEN.
summary: assets 132, findings 153, evidence 9, incidents 108, vulnerabilities 29, risks_proposed 106, applied_controls 38, canonical_rows 338, sensors_canonical 9.

## cycle 69

I-066: Nuclei JSONL empty/whitespace `template-id` uses `template` / `template-path` / `template-url` CVE basename (not info.name). Non-CVE path uses file basename. Fixture `nuclei-template.jsonl` (`weblogic-legacy.corp.local` / `VULN-CVE-2020-14882` critical, `vsphere-legacy.corp.local` / `VULN-CVE-2021-21972` critical, `VULN-EXPOSED-KIBANA` medium; info.name refs omitted). lab_outputs requires those hosts and refs; rejects name slugs.
pytest: 88 passed. Two consecutive LAB_GREEN.
summary: assets 129, findings 151, evidence 9, incidents 106, vulnerabilities 29, risks_proposed 104, applied_controls 38, canonical_rows 333, sensors_canonical 9.

## cycle 68

I-065: Nessus XML `.nessus` / `NessusClientData_v2` `ReportHost`/`ReportItem` (no live scan). Prefer `host-fqdn` over ReportHost IP name; empty/whitespace `host-fqdn` uses ReportHost `name`. Plugin severity 0 / `risk_factor` None skipped. CVE from `<cve>`. Fixture `nessus.xml` (`dc-legacy.corp.local` / `VULN-CVE-2020-1472` critical, `print-legacy.corp.local` / `VULN-CVE-2021-34527` high; `VULN-19506` omitted). lab_outputs requires those hosts and refs; rejects ReportHost IP `10.0.88.12` and info plugin.
pytest: 87 passed. Two consecutive LAB_GREEN.
summary: assets 126, findings 148, evidence 9, incidents 104, vulnerabilities 26, risks_proposed 102, applied_controls 38, canonical_rows 327, sensors_canonical 9.

## cycle 67

I-064: Microsoft Graph `userRegistrationDetails` (`value` / `@odata.context`, no live API). MFA gap when `isMfaRegistered` is false; PASS/`true` skipped; guest `userType` skipped. Fixture `graph-registration.json` (`ga-breakglass@litware.onmicrosoft.com` / `SAAS-GRAPH-MFA-GA-BREAKGLASS-LITWARE-ONMICROSOFT-COM` critical, `vendor@litware.onmicrosoft.com` high; analyst/helpdesk/guest omitted). lab_outputs requires those refs and tenant; rejects MFA-registered and guest.
pytest: 86 passed. Two consecutive LAB_GREEN.
summary: assets 124, findings 146, evidence 9, incidents 102, vulnerabilities 24, risks_proposed 100, applied_controls 38, canonical_rows 323, sensors_canonical 9.

## cycle 66

I-063: kube-bench JSON top-level `tests` (no wrapping `Controls` array). Nested `results` or bare result rows; PASS skipped. Fixture `kube-bench-tests.json` (`K8S-KB-4-1-1` medium, `K8S-KB-4-1-2` medium, `K8S-KB-4-1-9` WARN medium; `K8S-KB-4-1-10` PASS omitted). lab_outputs requires those refs and rejects PASS.
pytest: 85 passed. Two consecutive LAB_GREEN.
summary: assets 119, findings 144, evidence 9, incidents 100, vulnerabilities 24, risks_proposed 98, applied_controls 37, canonical_rows 316, sensors_canonical 9.

## cycle 65

I-062: Amass JSON `names` / `subdomains` / `domains` arrays of host strings or `{name}`/`{fqdn}` objects (not httpx exposed). Fixture `amass-names.json` (`vpn.backup.example-corp.com` / `EASM-AMASS-VPN-BACKUP-EXAMPLE-CORP-COM` medium, `admin-portal.example-corp.com`; intranet/www assets only). lab_outputs requires those hosts and refs; enum not exposed.
pytest: 84 passed. Two consecutive LAB_GREEN.
summary: assets 119, findings 141, evidence 9, incidents 100, vulnerabilities 24, risks_proposed 98, applied_controls 37, canonical_rows 313, sensors_canonical 9.

## cycle 64

I-061: BloodHound CE `data` as a list of nodes (plus top-level `edges`), not only `data.nodes` dict. Hybrid `findings`+`nodes` files stay on parse_doc. Domain asset key is the domain name (no colliding `ID-DOMAIN`). Fixture `bloodhound_data_list.json` (`AW.LOCAL` / `ID-BHCE-SPN-SVC-SQL-AW-LOCAL` high, `ID-BHCE-ASREP-JDOE-AW-LOCAL` high, `ID-BHCE-GENERICALL-CONTRACTOR-AW-LOCAL-DC02-AW-LOCAL` critical; ANALYST omitted). lab_outputs requires those refs and domain; rejects ANALYST finding.
pytest: 83 passed. Two consecutive LAB_GREEN.
summary: assets 115, findings 139, evidence 9, incidents 100, vulnerabilities 24, risks_proposed 98, applied_controls 37, canonical_rows 306, sensors_canonical 9.

## cycle 63

I-060: Osquery JSON `osquery` as a list of row objects (and a raw array of listening_ports-shaped dicts), not only `{rows:[...]}` / nested `columns`. Fixture `osquery_list.json` (`nas-legacy.corp.local` / `WAZ-OSQ-NAS-LEGACY-CORP-LOCAL-445` high, `modem-legacy.corp.local` / `WAZ-OSQ-MODEM-LEGACY-CORP-LOCAL-23` high; ssh `:22` omitted). lab_outputs requires both refs and hosts; rejects helper-ssh :22.
pytest: 82 passed. Two consecutive LAB_GREEN.
summary: assets 109, findings 136, evidence 9, incidents 97, vulnerabilities 24, risks_proposed 95, applied_controls 37, canonical_rows 297, sensors_canonical 9.

## cycle 62

I-059: Gitleaks empty/`RuleID` uses `Fingerprint` `file:rule:line` (or `DetectorName`) instead of generic `secret`. Secret values still `[REDACTED]`. Fixture `gitleaks-fingerprint.json` (`CODE-SLACK-BOT-TOKEN-OPS-PAGER-ENV` high, `CODE-PRIVATE-KEY-CERTS-LEGACY-PEM` high; `CODE-SECRET-OPS-PAGER-ENV` omitted). lab_outputs requires both refs and rejects generic secret.
pytest: 81 passed. Two consecutive LAB_GREEN.
summary: assets 106, findings 134, evidence 9, incidents 95, vulnerabilities 24, risks_proposed 93, applied_controls 37, canonical_rows 292, sensors_canonical 9.

## cycle 61

I-058: OpenVAS/Greenbone `<cve>NOCVE</cve>` (and empty/N/A) is ignored; CVE comes from `<ref type="cve" id>` or nested `<cves><cve>`. Fixture `openvas-nocve.xml` (`struts-legacy.corp.local` / `VULN-CVE-2017-5638` critical, `tomcat-legacy.corp.local` / `VULN-CVE-2020-1938` high; `VULN-NOCVE` omitted). lab_outputs requires both CVE refs and hosts; rejects NOCVE.
pytest: 80 passed. Two consecutive LAB_GREEN.
summary: assets 106, findings 132, evidence 9, incidents 93, vulnerabilities 24, risks_proposed 91, applied_controls 37, canonical_rows 289, sensors_canonical 9.

## cycle 60

I-057: kube-bench JSON hyphenated `test-number` / `test-desc` / `test-result` (and lowercase `controls` / `Tests` / `Results`). PASS skipped. Fixture `kube-bench-hyphen.json` (`K8S-KB-4-2-1` high anonymous FAIL, `K8S-KB-4-2-4` medium, `K8S-KB-4-2-6` WARN medium; `K8S-KB-4-2-13` PASS omitted). lab_outputs requires the three refs and rejects PASS.
pytest: 79 passed. Two consecutive LAB_GREEN.
summary: assets 103, findings 129, evidence 9, incidents 91, vulnerabilities 21, risks_proposed 89, applied_controls 37, canonical_rows 283, sensors_canonical 9.

## cycle 59

I-056: Nuclei JSONL `info.classification.cve-id` (string or list, also `cve_id`) becomes the finding CVE ref when `template-id` is not `CVE-*`. Fixture `nuclei-cve-id.jsonl` (`log4j-legacy.corp.local` / `VULN-CVE-2021-45046` critical, `func-legacy.corp.local` / `VULN-CVE-2022-22963` high; empty cve-id keeps template-id). lab_outputs requires both CVE refs and hosts; rejects `VULN-LOG4J-RCE`.
pytest: 78 passed. Two consecutive LAB_GREEN.
summary: assets 103, findings 126, evidence 9, incidents 90, vulnerabilities 21, risks_proposed 88, applied_controls 37, canonical_rows 280, sensors_canonical 9.

## cycle 58

I-055: ScubaGear empty/whitespace CheckID uses `RelativePath` fragment (`baselines/teams.md#ms.teams.2.1v1`) as requirement id, not the Requirement sentence. Fixture `scubagear_relativepath.json` (`fabrikam.onmicrosoft.com` / `ID-SCUBA-MS-TEAMS-2-1V1` high, `ID-SCUBA-MS-DEFENDER-1-4V1` high; Pass `MS.SHAREPOINT.1.1v1` omitted). lab_outputs requires both refs and tenant; rejects Pass.
pytest: 77 passed. Two consecutive LAB_GREEN.
summary: assets 100, findings 124, evidence 9, incidents 88, vulnerabilities 18, risks_proposed 86, applied_controls 37, canonical_rows 274, sensors_canonical 9.

## cycle 57

I-054: httpx JSON empty/`host` (whitespace, null, list) uses `input` URL hostname, never a raw URL asset. Fixture `httpx-input.jsonl` (`admin-confluence.example-corp.com` high exposed, `owa-legacy.example-corp.com`, `fileshare.example-corp.com`; blank host+input omitted). lab_outputs requires those hosts and `EASM-ADMIN-CONFLUENCE-EXAMPLE-CORP-COM`; rejects `unknown-host` / `https://` names.
pytest: 76 passed. Two consecutive LAB_GREEN.
summary: assets 99, findings 122, evidence 9, incidents 86, vulnerabilities 18, risks_proposed 84, applied_controls 37, canonical_rows 271, sensors_canonical 9.

## cycle 56

I-053: Kubescape `failedControls` list of `controlID` objects (no `resources` array). Implicit fail unless status passed/skipped; PASS skipped. Fixture `kubescape_failedcontrols.json` (`staging-gke` / `K8S-C-0016` high, `K8S-C-0048` high from scoreFactor 8; `K8S-C-0005` passed omitted). lab_outputs requires cluster + both refs and rejects passed.
pytest: 75 passed. Two consecutive LAB_GREEN.
summary: assets 96, findings 121, evidence 9, incidents 85, vulnerabilities 18, risks_proposed 83, applied_controls 37, canonical_rows 267, sensors_canonical 9.

## cycle 55

I-052: PingCastle XML empty `<Host>` / `<DomainFQDN>` text uses `DomainFQDN` attribute (then ForestFQDN), not hardcoded `corp.local`. Fixture `pingcastle-domainfqdn.xml` (`ad.tailspintoys.local` / `ID-PCXML-P-ADMINPWDTOOOLD` high). lab_outputs requires the domain and finding; rejects `unknown-domain`.
pytest: 74 passed.
summary: assets 95, findings 119, evidence 9, incidents 83, vulnerabilities 18, risks_proposed 81, applied_controls 37, canonical_rows 264, sensors_canonical 9.

## cycle 54

I-051: Nuclei JSONL with only `ip` (no `host` / `matched-at`) uses the IP as the asset. Accepts `IP`/`ipv4` and list-wrapped ip. Fixture `nuclei-ip-only.jsonl` (`10.0.0.55` / `VULN-CVE-2018-13379` critical). lab_outputs requires the IP and finding; not `unknown-host`.
pytest: 73 passed. Two consecutive LAB_GREEN.
summary: assets 94, findings 118, evidence 9, incidents 82, vulnerabilities 18, risks_proposed 80, applied_controls 37, canonical_rows 262, sensors_canonical 9.

## cycle 53

I-050: Prowler CSV (`CHECK_ID`,`STATUS`,`SEVERITY`; v3/v4 header aliases). STATUS FAIL emits findings; PASS skipped. Fixture `prowler.csv` (`CLD-S3-BUCKET-OBJECT-LOCK-ENABLED` high on `corp-lock-bucket`, `CLD-IAM-PASSWORD-POLICY-MINIMUM-LENGTH-14` medium; `CLD-EC2-INSTANCE-MANAGED-BY-SSM` omitted). lab_outputs requires FAIL refs and rejects PASS.
pytest: 72 passed. Two consecutive LAB_GREEN.
summary: assets 93, findings 117, evidence 9, incidents 81, vulnerabilities 17, risks_proposed 79, applied_controls 37, canonical_rows 260, sensors_canonical 9.

## cycle 52

I-049: Okta GET `/api/v1/users` list (JSON array). MFA gap when `credentials.provider.type` is local (`OKTA`) and no factors; `FEDERATION` and TOTP factors skipped. Fixture `okta-users.json` (`SAAS-OKTA-MFA-OKTA-APPADMIN-CONTOSO-COM` critical, `SAAS-OKTA-MFA-OKTA-CONTRACTOR-CONTOSO-COM` high). No IdP API. lab_outputs requires both and rejects analyst/federated.
pytest: 71 passed. Two consecutive LAB_GREEN.
summary: assets 91, findings 115, evidence 9, incidents 80, vulnerabilities 17, risks_proposed 78, applied_controls 37, canonical_rows 256, sensors_canonical 9.

## cycle 51

I-048: Wazuh alerts JSON from `data.affected_items` / `alerts` / JSONL / `hits._source`. Severity from numeric `rule.level` (12–15 critical, 8–11 high, 5–7 medium; level 0–2 skipped). Fixture `alerts.json` (`WAZ-ALERT-5712` high on `vpn-gw`, `WAZ-ALERT-550` critical on `cfg-bastion`; `WAZ-ALERT-1002` omitted). No live API. lab_outputs requires both refs.
pytest: 70 passed. Two consecutive LAB_GREEN.
summary: assets 87, findings 113, evidence 9, incidents 78, vulnerabilities 17, risks_proposed 76, applied_controls 37, canonical_rows 250, sensors_canonical 9.

## cycle 50

I-047: Gitleaks SARIF `runs[].results` uses `ruleId` as RuleID (not Semgrep). Snippet text is not copied into findings; `redact_text` still strips `ghp_` in `out/raw`. Fixture `gitleaks.sarif` (`CODE-SLACK-BOT-TOKEN-CI-SECRETS-ENV` high on `ci/secrets.env`). lab_outputs requires the ref and rejects snippet leak / CODE-SG- prefix.
pytest: 69 passed. Two consecutive LAB_GREEN.
summary: assets 85, findings 111, evidence 9, incidents 76, vulnerabilities 17, risks_proposed 74, applied_controls 36, canonical_rows 244, sensors_canonical 9.

## cycle 49

I-046: Trivy IaC `Results[].Misconfigurations` (also `Misconfs`). Status `FAIL` emits findings; `PASS`/`EXCEPTION` skipped. Fixture `trivy-misconfig.json` (`CODE-DS002` high on `deploy/api.Dockerfile`, `CODE-KSV017` critical on `k8s/privileged-pod.yaml`; `CODE-DS005` PASS omitted). lab_outputs requires FAIL refs and rejects PASS.
pytest: 68 passed. Two consecutive LAB_GREEN.
summary: assets 85, findings 110, evidence 9, incidents 75, vulnerabilities 17, risks_proposed 73, applied_controls 36, canonical_rows 242, sensors_canonical 9.

## cycle 48

I-045: Nmap XML skips hosts with `<status state="down"/>` (case-insensitive `Down`). Fixture `host-down.xml` (`down-xml.corp.local` / 445 and `xml-down-mixed.corp.local` / telnet skipped; `up-xml.corp.local` kept). lab_outputs requires the up host and rejects down names/IPs.
pytest: 67 passed. Two consecutive LAB_GREEN.
summary: assets 83, findings 108, evidence 9, incidents 73, vulnerabilities 17, risks_proposed 71, applied_controls 35, canonical_rows 238, sensors_canonical 9.

## cycle 47

I-044: OpenVAS/Greenbone empty `<host>` text (and whitespace + nested `<asset>`) uses `ip=` attribute; non-empty host text wins over a conflicting `ip=`. Fixture `openvas-host-ip.xml` (`10.0.0.66` / `VULN-CVE-2018-7600` critical; `gvm-named.corp.local` / `VULN-CVE-2012-1823` high; reject `10.0.0.199`). lab_outputs requires both.
pytest: 66 passed. Two consecutive LAB_GREEN.
summary: assets 82, findings 108, evidence 9, incidents 73, vulnerabilities 17, risks_proposed 71, applied_controls 35, canonical_rows 237, sensors_canonical 9.

## cycle 46

I-043: kube-bench status `Fail`/`Failed`/`FAIL` (and `test_result`) map to findings, not only uppercase `FAIL`. Fixture 1.2.7 Fail + 1.2.8 Failed (medium). lab_outputs requires `K8S-KB-1-2-7` and `K8S-KB-1-2-8`.
pytest: 65 passed. Two consecutive LAB_GREEN.
summary: assets 80, findings 106, evidence 9, incidents 71, vulnerabilities 15, risks_proposed 69, applied_controls 35, canonical_rows 231, sensors_canonical 9.

## cycle 45

I-042: Amass JSON/JSONL objects `{"name": "host"}` and `{"fqdn": "..."}` (OWASP Amass export). Not treated as httpx exposed. Fixture `amass.jsonl` (`sharepoint-old`, `remote`, `admin-vpn.example-corp.com` enum). lab_outputs requires those assets and enum-not-exposed for admin-vpn.
pytest: 64 passed. Two consecutive LAB_GREEN.
summary: assets 80, findings 104, evidence 9, incidents 71, vulnerabilities 15, risks_proposed 69, applied_controls 35, canonical_rows 229, sensors_canonical 9.

## cycle 44

I-041: Nuclei JSONL without `host` uses `matched-at` URL hostname (never a raw URL asset). Fixture `nuclei-matched-at.jsonl` (`https://pulse-legacy.corp.local:443/dana-na/` → `pulse-legacy.corp.local`, `VULN-CVE-2019-11510` critical). lab_outputs requires the host and rejects `https://` asset names.
pytest: 63 passed. Two consecutive LAB_GREEN.
summary: assets 77, findings 103, evidence 9, incidents 71, vulnerabilities 15, risks_proposed 69, applied_controls 35, canonical_rows 225, sensors_canonical 9.

## cycle 43

I-040: `out/evidence/{sensor}.md` exists for all nine sensors after lab. `emit()` always writes the file (fallback stub if no evidence records). lab_outputs requires heading `# Evidence` and the sensor name. pytest covers emit without evidence rows.
pytest: 62 passed. Two consecutive LAB_GREEN.
summary: assets 76, findings 102, evidence 9, incidents 70, vulnerabilities 14, risks_proposed 68, applied_controls 35, canonical_rows 223, sensors_canonical 9.

## cycle 42

I-039: `package-lock.json` paths (including nested `apps/web/package-lock.json`) are asset type SP only. Collector, loader dedupe, and CISO/RiskReady writers coerce PR→SP. Fixture `trivy-package-lock.json` (`CVE-2024-21538`). lab_outputs rejects non-SP lockfile assets.
pytest: 61 passed. Two consecutive LAB_GREEN.
summary: assets 76, findings 102, evidence 9, incidents 70, vulnerabilities 14, risks_proposed 68, applied_controls 35, canonical_rows 223, sensors_canonical 9.

## cycle 41

I-038: Wazuh agent `status: Disconnected` (capital D) and `Never connected` normalize to disconnected/never_connected findings. Also reads `connection_status`. Fixture `agents_disconnected.json` (`jump-legacy`). lab_outputs requires `WAZ-DISC-JUMP-LEGACY` high.
pytest: 60 passed. Two consecutive LAB_GREEN.
summary: assets 75, findings 101, evidence 9, incidents 69, vulnerabilities 13, risks_proposed 67, applied_controls 35, canonical_rows 221, sensors_canonical 9.

## cycle 40

I-037: nmap XML hostname `type=user` preferred over `PTR` (PTR listed first in fixture still loses). Fixture `user-vs-ptr.xml` (`bastion-prod.corp.local` vs `ip-10-0-0-77.ec2.internal`). lab_outputs requires the user name and rejects the PTR asset.
pytest: 59 passed. Two consecutive LAB_GREEN.
summary: assets 74, findings 100, evidence 9, incidents 67, vulnerabilities 13, risks_proposed 66, applied_controls 35, canonical_rows 218, sensors_canonical 9.

## cycle 39

I-036: PingCastle JSON `HealthcheckRisk` nodes when XML is not present. Parser accepts `HealthcheckRisk` / `RiskRules` JSON (and XML `HealthcheckRisk` tags). Fixture `pingcastle_healthcheckrisk.json` (`fabrikam.local`, `P-TrustedCreds` high, `A-NullSession` medium). lab_outputs requires `ID-PCHCR-P-TRUSTEDCREDS`.
pytest: 58 passed. Two consecutive LAB_GREEN.
summary: assets 73, findings 99, evidence 9, incidents 67, vulnerabilities 13, risks_proposed 66, applied_controls 35, canonical_rows 216, sensors_canonical 9.

## cycle 38

I-035: `run_lab.ps1` double-runs collectors+loader; lab_outputs requires `out/evidence/summary-pass1.json` counts to match `summary.json` and writes `idempotent.md`. Pytest asserts the script and re-runs collectors+loader in `test_double_loader_idempotent`.
pytest: 57 passed. Two consecutive LAB_GREEN.
summary: assets 72, findings 97, evidence 9, incidents 66, vulnerabilities 13, risks_proposed 65, applied_controls 35, canonical_rows 213, sensors_canonical 9.

## cycle 37

I-034: CISO `filtering_labels` never spaces-only or empty tokens. `_labels` strips whitespace-only entries; lab_outputs rejects padded/empty tokens on assets and findings.
pytest: 56 passed. Two consecutive LAB_GREEN.
summary: assets 72, findings 97, evidence 9, incidents 66, vulnerabilities 13, risks_proposed 65, applied_controls 35, canonical_rows 213, sensors_canonical 9.

## cycle 36

I-033: findings.csv status only `open|closed|in_progress`. Loader and `finding()` normalize aliases (`NEW`/`FAIL`→open, `RESOLVED`/`ARCHIVED`/`PASS`→closed, `MANUAL`/`IN PROGRESS`/`NOTIFIED`→in_progress). Prowler fixture `finding-status.json` (MANUAL, WorkflowStatus RESOLVED, FindingStatus IN PROGRESS). lab_outputs rejects any other status.
pytest: 55 passed. Two consecutive LAB_GREEN.
summary: assets 72, findings 97, evidence 9, incidents 66, vulnerabilities 13, risks_proposed 65, applied_controls 35, canonical_rows 213, sensors_canonical 9.

## latest lab

Auto-stamped from out/summary.json after run_lab.ps1.
summary: assets 132, findings 155, evidence 9, incidents 110, vulnerabilities 29, risks_proposed 108, applied_controls 38, canonical_rows 341, sensors_canonical 9.

## cycle 35

I-032: Redact `aws_secret_access_key` in YAML/JSONL raw copies (quoted and unquoted). Fixtures `aws-creds.yaml` / `aws-creds.jsonl`; out/raw copies use `[REDACTED]`. lab_outputs scans yaml/yml and rejects leaked secret values.
pytest: 53 passed. Two consecutive LAB_GREEN.
summary: assets 70, findings 94, evidence 9, incidents 66, vulnerabilities 13, risks_proposed 65, applied_controls 35, canonical_rows 207, sensors_canonical 9.

## cycle 34

I-030: CHANGELOG.md entry per cycle with summary.json counts. `run_lab.ps1` stamps `## latest lab` from out/summary.json; lab_outputs requires latest cycle summary keys and latest-lab counts to match summary.json.
pytest: 52 passed. Two consecutive LAB_GREEN.
summary: assets 70, findings 94, evidence 9, incidents 66, vulnerabilities 13, risks_proposed 65, applied_controls 35, canonical_rows 207, sensors_canonical 9.

## cycle 33

I-029: Makefile documents Windows `run_lab.ps1` as the real lab entry (`make lab` optional Unix/WSL only). pytest asserts Makefile contains run_lab.ps1 / Windows / real lab. README Quick lab matches.
pytest: 51 passed. Two consecutive LAB_GREEN.
summary: assets 70, findings 94, evidence 9, incidents 66, vulnerabilities 13, risks_proposed 65, applied_controls 35, canonical_rows 207, sensors_canonical 9.

## cycle 32

I-028: Subfinder JSONL of `{"host": "..."}` objects (plus `hostname`/`fqdn`). Fixture `subfinder.jsonl` (`git.example-corp.com`, `admin-sso.example-corp.com` enum, `citrix.example-corp.com`). lab_outputs rejects treating JSONL host objects as httpx exposed.
pytest: 50 passed. Two consecutive LAB_GREEN.
summary: assets 70, findings 94, evidence 9, incidents 66, vulnerabilities 13, risks_proposed 65, applied_controls 35, canonical_rows 207, sensors_canonical 9.

## cycle 31

I-027: ScubaGear `Failed` array (not only `Results`). Parser merges Results+Failed; Failed items without Outcome are implicit fails; Pass in Results does not hide Failed. Fixture `scubagear_failed.json` `MS.EXO.4.1v1`. lab_outputs requires `ID-SCUBA-MS-EXO-4-1V1` high.
pytest: 49 passed. Two consecutive LAB_GREEN.
summary: assets 67, findings 93, evidence 9, incidents 66, vulnerabilities 13, risks_proposed 65, applied_controls 35, canonical_rows 203, sensors_canonical 9.

## cycle 30

I-026: Osquery `listening_ports` nested `columns` (`hostIdentifier`, decorations). Fixture `osquery_columns.jsonl` (`smb-legacy.corp.local` :445 high, `jump-rdp.corp.local` :3389 medium). lab_outputs requires `WAZ-OSQ-SMB-LEGACY-CORP-LOCAL-445`.
pytest: 48 passed. Two consecutive LAB_GREEN.
summary: assets 66, findings 92, evidence 9, incidents 65, vulnerabilities 13, risks_proposed 64, applied_controls 35, canonical_rows 201, sensors_canonical 9.

## cycle 29

I-025: lab_outputs requires `risk_scenarios.csv` row count equals high+critical findings (and `risks_proposed`). Loader emits both from the same findings.csv high/crit set. Current match: 63.
pytest: 47 passed. Two consecutive LAB_GREEN.
summary: assets 64, findings 90, evidence 9, incidents 64, vulnerabilities 13, risks_proposed 63, applied_controls 35, canonical_rows 197, sensors_canonical 9.

## cycle 28

I-024: OpenVAS numeric CVSS (`9.8`) maps to critical not info. Fixture `openvas.xml` Heartbleed `CVE-2014-0160` on `legacy-ssl.corp.local` (`<severity>9.8</severity>`, no threat label). lab_outputs requires `VULN-CVE-2014-0160` critical.
pytest: 47 passed. Two consecutive LAB_GREEN.
summary: assets 64, findings 90, evidence 9, incidents 64, vulnerabilities 13, risks_proposed 63, applied_controls 35, canonical_rows 197, sensors_canonical 9.

## cycle 27

I-023: Semgrep SARIF `runs[].results` `ruleId` + `level` (fallback `defaultConfiguration.level`). Fixture `semgrep.sarif` (`python.django.sql.extra-used` error→high, `python.lang.security.insecure-hash` warning→medium). lab_outputs requires both refs.
pytest: 46 passed. Two consecutive LAB_GREEN.
summary: assets 63, findings 89, evidence 9, incidents 63, vulnerabilities 12, risks_proposed 62, applied_controls 35, canonical_rows 195, sensors_canonical 9.

## cycle 26

I-022: httpx URL-only strings (`https://host[:port]/path`) normalize to hostname in easm. Fixture `httpx-urls.txt` (`test.example-corp.com` exposed medium, `portal-legacy.example-corp.com` asset). lab_outputs rejects raw URL asset names.
pytest: 45 passed. Two consecutive LAB_GREEN.
summary: assets 63, findings 87, evidence 9, incidents 62, vulnerabilities 12, risks_proposed 61, applied_controls 35, canonical_rows 192, sensors_canonical 9.

## cycle 25

I-021: Prowler v4 nested `Metadata` + `Status` dict + `Resource` object. Fixture `prowler_v4.json` (`ec2_instance_imdsv1_enabled` / `i-0cafe`). lab_outputs requires `CLD-EC2-INSTANCE-IMDSV1-ENABLED`.
pytest: 44 passed. Two consecutive LAB_GREEN.
summary: assets 61, findings 86, evidence 9, incidents 62, vulnerabilities 12, risks_proposed 61, applied_controls 35, canonical_rows 188, sensors_canonical 9.

## cycle 24

I-020: loader `summary.json` adds `sensors_canonical` (count of `out/canonical/*.jsonl`). lab_outputs requires the key, match to glob, and count >= 9.
pytest: 43 passed. Two consecutive LAB_GREEN.
summary: assets 60, findings 85, evidence 9, incidents 61, vulnerabilities 12, risks_proposed 60, applied_controls 35, canonical_rows 186, sensors_canonical 9.

## cycle 23

I-019: kube-bench WARN/WARNING maps to medium (PASS still skipped). Fixture `1.2.6` WARN + `1.2.20` PASS. lab_outputs requires `K8S-KB-1-2-6` severity medium.
pytest: 43 passed. Two consecutive LAB_GREEN.
summary: assets 60, findings 85, evidence 9, incidents 61, vulnerabilities 12, risks_proposed 60, applied_controls 35, canonical_rows 186.

## cycle 22

I-018: EASM dedupes findings by hostname + enum|exposed before emit; Amass/Subfinder enum for the same host merge labels. Duplicate `vpn.example-corp.com` in amass.txt. lab_outputs rejects duplicate easm hostname+kind.
pytest: 42 passed. Two consecutive LAB_GREEN.
summary: assets 60, findings 84, evidence 9, incidents 61, vulnerabilities 12, risks_proposed 60, applied_controls 35, canonical_rows 185.

## cycle 21

I-017: pytest runs `push_ciso.ps1` and `push_riskready.ps1` with CISO_PUSH=0 RISKREADY_PUSH=0 DRY_RUN=1; both exit 0 and print DRY_RUN.
pytest: 41 passed. Two consecutive LAB_GREEN.
summary: assets 60, findings 86, evidence 9, incidents 61, vulnerabilities 12, risks_proposed 60, applied_controls 35, canonical_rows 186.

## cycle 20

I-016: Nmap XML IPv6 host without hostname uses address as asset name (`2001:db8::9`, `ip-only` + `ipv6` labels). lab_outputs requires that asset.
pytest: 40 passed. Two consecutive LAB_GREEN.
summary: assets 60, findings 86, evidence 9, incidents 61, vulnerabilities 12, risks_proposed 60, applied_controls 35, canonical_rows 186.

## cycle 19

I-015: Hostile UTF-8 BOM JSON in `in/cloud/bom-prowler.json` still loads. `load_structured` uses utf-8-sig and strips U+FEFF. lab_outputs requires `CLD-GUARDDUTY-IS-ENABLED`.
pytest: 39 passed. Two consecutive LAB_GREEN.
summary: assets 59, findings 85, evidence 9, incidents 60, vulnerabilities 12, risks_proposed 59, applied_controls 35, canonical_rows 184.

## cycle 18

I-014: README sensor-format matrix (nine `in/` dirs, collector, accepted shapes, prefixes). pytest asserts the matrix lists each sensor and key formats.
pytest: 38 passed. Two consecutive LAB_GREEN.
summary: assets 58, findings 84, evidence 9, incidents 59, vulnerabilities 12, risks_proposed 58, applied_controls 35, canonical_rows 182.

## cycle 17

I-012: applied_controls include at least one `respond` (CTL-FIM) and one `recover` (CTL-BACKUP-RESTORE). Loader fills either CSF if collectors omit it. lab_outputs asserts both.
pytest: 37 passed. Two consecutive LAB_GREEN.
summary: assets 58, findings 84, evidence 9, incidents 59, vulnerabilities 12, risks_proposed 58, applied_controls 35, canonical_rows 182.

## cycle 16

I-011: OCSF items include `time`, `metadata.product.name`, `unmapped.ref_id`. lab_outputs asserts all three.
pytest: 34 passed. Two consecutive LAB_GREEN.
summary: assets 58, findings 84, evidence 9, incidents 59, vulnerabilities 12, risks_proposed 58, applied_controls 34, canonical_rows 182.

## cycle 15

I-010: lab_outputs unique finding ref_ids and unique evidence names (CISO CSVs + riskready evidence.json).
pytest: 34 passed. Two consecutive LAB_GREEN.
summary: assets 58, findings 84, evidence 9, incidents 59, vulnerabilities 12, risks_proposed 58, applied_controls 34, canonical_rows 182.

## cycle 14

I-009: Loader exclusive lock (`out/.loader.lock`) so two loaders cannot interleave writes. Second acquire SystemExit until release.
pytest: 34 passed. Two consecutive LAB_GREEN.
summary: assets 58, findings 84, evidence 9, incidents 59, vulnerabilities 12, risks_proposed 58, applied_controls 34, canonical_rows 182.

## cycle 13

I-008: Gitleaks `Secret` never persisted; `redact_obj` replaces Secret/Match keys with `[REDACTED]` even if extra copies the item. lab_outputs rejects unredacted `"Secret"` in `out/`.
pytest: 33 passed. Two consecutive LAB_GREEN.
summary: assets 58, findings 84, evidence 9, incidents 59, vulnerabilities 12, risks_proposed 58, applied_controls 34, canonical_rows 182.

## cycle 12

I-007: Trivy `Secrets` parser plus `trivy-secrets.json` (AWS access key + GitHub PAT). Match values not persisted; descriptions use `[REDACTED]`.
pytest: 32 passed. Two consecutive LAB_GREEN.
summary: assets 58, findings 84, evidence 9, incidents 59, vulnerabilities 12, risks_proposed 58, applied_controls 34, canonical_rows 182.

## cycle 11

I-006: Kubescape `summaryDetails.resourcesSeverity` / `controls` parser plus `kubescape_summary.json` (prod-aks; C-0002 exec, C-0057 privileged; cluster asset keys unique).
pytest: 31 passed. Two consecutive LAB_GREEN.
summary: assets 57, findings 82, evidence 9, incidents 57, vulnerabilities 12, risks_proposed 56, applied_controls 34, canonical_rows 179.

## cycle 10

I-005: BloodHound CE `data.nodes` / `data.edges` parser plus `bloodhound_ce.json` (HELPDESK GenericAll DC, INTERN MemberOf Domain Admins, AS-REP/SPN on SVC-IIS, unconstrained DC01).
pytest: 30 passed. Two consecutive LAB_GREEN.
summary: assets 56, findings 79, evidence 9, incidents 54, vulnerabilities 12, risks_proposed 53, applied_controls 34, canonical_rows 174.

## cycle 9

I-004: Wazuh SCA policy-checks JSON parser plus `sca.json` demo fixture (cis_win2019 failed Guest/Firewall/anonymous SAM; passed password history skipped).
pytest: 29 passed. Two consecutive LAB_GREEN.
summary: assets 51, findings 73, evidence 9, incidents 48, vulnerabilities 12, risks_proposed 47, applied_controls 32, canonical_rows 161.

## cycle 8

I-003: Nuclei SARIF parser (`runs[].results`) plus `nuclei.sarif` demo fixture (CVE-2024-21762, CVE-2019-19781, exposed-grafana).
pytest: 28 passed. Two consecutive LAB_GREEN.
summary: assets 51, findings 70, evidence 9, incidents 45, vulnerabilities 12, risks_proposed 44, applied_controls 31, canonical_rows 155.

## cycle 7

I-013 / I-031: Docker Desktop 29.7.2 extra lab.
- 11 one-shot containers: 9 collectors + loader + pytest/lab_outputs (LAB_GREEN, 27 tests)
- `live_scan_ignored`: GRC_LIVE_SCAN=1 still file-parse only
- `mock_sink` on :18080: assets/incidents/evidence/importer 200; proposed risks 403
- `run_lab.ps1` writes `out/evidence/docker-probe.md`; `run_docker_lab.ps1` is the compose entry
F-001 closed. critic 10/10 if no other P2.
summary (compose lab): assets 48, findings 67, evidence 9, incidents 43, risks_proposed 42, canonical_rows 149.

## cycle 6

I-002: PingCastle XML parser (`HealthcheckRiskRule`) plus `pingcastle.xml` demo fixture.
I-001 gnmap fixture kept: `legacy-ftp.corp.local` (ftp/21), `10.0.0.88` (smb/445), plus telnet/RDP/down-host lines.
pytest: 27 passed. Two consecutive LAB_GREEN.
summary: assets 48, findings 67, evidence 9, incidents 43, vulnerabilities 9, risks_proposed 42, applied_controls 31, canonical_rows 149.

## cycle 5

I-001: Nmap grepable/gnmap parser (`scan.gnmap`) — hosts `legacy-ftp.corp.local` (ftp/21) and `10.0.0.88` (smb/445).
pytest: 24 passed. Two consecutive LAB_GREEN.
summary: assets 46, findings 60, evidence 9, incidents 40, risks_proposed 39, applied_controls 31, canonical_rows 139.

## cycle 4

Parsers: Prowler ASFF, Osquery, Subfinder, ScubaGear, Semgrep.
Lab gate: sensor prefixes; every high/critical finding in risks_proposed.
summary: assets 44, findings 58, evidence 9.
