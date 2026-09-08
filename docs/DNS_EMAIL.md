# Email / DNS Seen lane (`in/dns_email/`)

Pack twin of Covey evidence-matrix lane **`email_dns`**.
Machine contract: [evergreen-covey `docs/evidence_matrix.yaml`](https://github.com/eregular13/evergreen-covey/blob/main/docs/evidence_matrix.yaml).

| Said | Seen | Shown |
|---|---|---|
| SPF/DKIM/DMARC "set" | Published TXT / MX / optional cert snapshot | DMARC `p=reject` + sampled aggregate (not this collector) |

**Honesty:** a TXT record is Seen. Missing DMARC is a **control gap candidate**. This collector does not claim mailbox compromise, deliverability, or a breach. No RiskReady POST.

## Drop

Land files under `in/dns_email/` (empty `in/` loads `fixtures/demo/dns_email/`):

- `dns_email.v1` / checkdmarc-style JSON (`domain` + `spf` / `dmarc` / `dkim` / `mx`)
- dropped `dig` / `nslookup` transcripts (`IN TXT` / `IN MX`)
- crt.sh-style JSON (`common_name` + `not_after`)
- operator-dropped PEM or `openssl x509 -text` (no live TLS)

DKIM selectors are configurable on the JSON (`dkim_selectors`) or `GRC_DKIM_SELECTORS` for the optional live writer.

## Normalize

`collectors/dns_email.py` → `out/canonical/dns-email.jsonl`

## Prove bar (CoS)

```
fixtures/demo/dns_email/*  →  in/dns_email/ (file_drop)
                           →  python collectors/dns_email.py
                           →  out/canonical/dns-email.jsonl
```

Empty `in/dns_email/` loads the same fixtures and stamps `demo` labels.
This is SAMPLE / DEMO fixture theater — **not a client estate**. No
RiskReady POST. Paying-day stays **FAIL**. Locked by
`tests/test_dns_email.py` (`test_prove_bar_*`).

| SoR | When |
|---|---|
| asset `domain` / `mail_org` | Domain or MX host already in the export |
| finding `dmarc_missing` | No `_dmarc` TXT — medium control gap, POA&M |
| finding `spf_softfail_only` | `~all` only — low, not a breach |
| finding `spf_pass_all` | `+all` — high control gap |
| finding DKIM selector missing | Listed selector has no `v=DKIM1` |
| evidence `dns_txt` / `cert` | Snapshot of what was dropped |

## Live (optional, default off)

```bash
python -m shared.dns_email_live            # offline; prints stay file_drop
python -m shared.dns_email_live --live --scope dropbox/SCOPE.yaml \
  --domain mail.example.invalid --out /tmp/dns-txt.json
```

`--live` requires a signed SCOPE. Only `external.domains` / `external.hosts` are queried. Wildcards and CIDR are refused. `dig` must already be on PATH (farm `dig` slot; never vendored). The writer emits JSON for this collector — it does not POST `/api/risks`.

LICENSE-LOCK: no scanner zoo, no OpenVAS/Nuclei wrap, no live cert spray.
