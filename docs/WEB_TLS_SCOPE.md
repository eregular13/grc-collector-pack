# Web / TLS live collector — SCOPE requirements

Live web/TLS probes (`python -m shared.web_tls_live --live`) are **fail-closed**.
Parse-only replay of recorded snapshots (`python collectors/web_tls.py`) never
opens a socket and does not need SCOPE.

## When live is allowed

`--live` requires **all** of:

1. A signed SCOPE file (`--scope PATH`, same contract as `dropbox.scope.load_scope`).
   The pack DEMO `dropbox/SCOPE.yaml` is refused.
2. A current engagement window (`engagement.start` / `engagement.end` contain now).
3. Engagement **not revoked**. These all refuse: `status: revoked` / `terminated` /
   `suspended`, `revoked: true` / `yes` / `on` / `y`, and a **top-level**
   `revoked: true`.
4. `--target` is a **bare host or IP** (no URL, userinfo, path, or `host:port`).
5. That host/IP is inside `internal` / `external` hosts, domains, CIDRs, or IPs.
6. Every probe port is in **1..65535**. Optional `ports_allowed` further
   restricts. **Absent `ports_allowed` keeps any valid port on an in-scope host.**
7. Every HTTP(S) `--url` is parsed with `urlsplit`: http/https only, no userinfo.
   Implicit 80/443 and explicit URL ports are gated. Default URLs are generated
   only for allowed ports.
8. The **resolved IP** is re-checked against SCOPE at connect time; the probe
   connects to that checked IP. Out-of-scope DNS answers are refused.
9. Redirects are **never followed**.

Any miss prints a clear error and exits non-zero. No snapshot is written. No
canonical findings are emitted.

```bash
python -m shared.web_tls_live --live --scope dropbox/SCOPE.yaml \
  --target 192.0.2.10 --port 80 --port 443 --out /tmp/web-tls-snap.json
```

`--port` is repeatable. There is no `--ports 80,443` flag.

The writer emits a `web_tls.probe.v1` snapshot for `collectors/web_tls.py`.
It does **not** POST `/api/risks`. RiskReady stay-out. CISO Assistant CSV is
the system of record; SimpleRisk is leave-behind only.

## What is refused

| Case | Result |
|---|---|
| No `--scope` / missing SCOPE | refuse, nonzero |
| Pack DEMO `dropbox/SCOPE.yaml` | refuse, nonzero |
| Expired engagement window | refuse, nonzero |
| `status: revoked` / `terminated` / `suspended` | refuse, nonzero |
| `revoked: on` / `y` / `true` (engagement or top-level) | refuse, nonzero |
| Target is a URL or `host:port` | refuse, nonzero |
| Target host/IP outside SCOPE | refuse, nonzero |
| Resolved IP outside SCOPE | refuse, nonzero |
| Port not in 1..65535 | refuse, nonzero |
| Port not in `ports_allowed` (when set) | refuse, nonzero |
| `--url` userinfo, non-http(s), or out-of-scope host/port | refuse, nonzero |
| `collectors/web_tls.py --live` | exit 2 (parse-only; does not import live) |

Checks are non-destructive (TCP connect, GET/HEAD/OPTIONS, TLS handshake, SSH
banner). No exploit, no auth spray, no write. FTP/SSH use their gated ports
(21/22), not `ftp://` / `ssh://` URLs.

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
