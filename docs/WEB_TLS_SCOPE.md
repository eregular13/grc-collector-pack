# Web / TLS live collector — SCOPE requirements

Live web/TLS probes (`python -m shared.web_tls_live --live`) are **fail-closed**.
Parse-only replay of recorded snapshots (`python collectors/web_tls.py`) never
opens a socket and does not need SCOPE.

## When live is allowed

`--live` requires **all** of:

1. A signed SCOPE file (`--scope PATH`, same contract as `dropbox.scope.load_scope`).
2. A current engagement window (`engagement.start` / `engagement.end` contain now).
3. Engagement **not revoked** (`status: revoked` or `revoked: true` refuses).
4. Every `--target` host/IP inside `internal` / `external` hosts, domains, CIDRs, or IPs.
5. Every probe port inside optional `ports_allowed`. **Absent `ports_allowed` keeps the current behavior** (any port on an in-scope host). An explicit list is fail-closed.

Any miss prints a clear error and exits non-zero. No snapshot is written. No
canonical findings are emitted.

```bash
python -m shared.web_tls_live --live --scope dropbox/SCOPE.yaml \
  --target 192.0.2.10 --ports 80,443 --out /tmp/web-tls-snap.json
```

The writer emits a `web_tls.probe.v1` snapshot for `collectors/web_tls.py`.
It does **not** POST `/api/risks`. RiskReady stay-out. CISO Assistant CSV is
the system of record; SimpleRisk is leave-behind only.

## What is refused

| Case | Result |
|---|---|
| No `--scope` / missing SCOPE | refuse, nonzero |
| Expired engagement window | refuse, nonzero |
| `status: revoked` | refuse, nonzero |
| Target host/IP outside SCOPE | refuse, nonzero |
| Port not in `ports_allowed` (when set) | refuse, nonzero |
| `collectors/web_tls.py --live` | exit 2 (parse-only; does not import live) |

Checks are non-destructive (TCP connect, GET/HEAD/OPTIONS, TLS handshake, SSH
banner). No exploit, no auth spray, no write.

## Honesty

Findings carry LAB / SAMPLE / DEMO / CLIENT labels from the pack estate stamp.
A live probe is **not** a client KEEP stamp and **not** a file-drop scanner
export. DEMO `scripts/lab.sh` / compose do **not** run this collector, so
existing DEMO `poam.csv` stays unchanged unless an operator drops
`in/web_tls/` snapshots.

## Parse path (no SCOPE)

Land recorded snapshots under `in/web_tls/*.json`. Empty `in/web_tls/` writes
nothing (no `fixtures/demo` fallback). Tests use `fixtures/samples/web_tls/`
only — no internet.
