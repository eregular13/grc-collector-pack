# Operator

Console (ingest pack, localhost only):

```powershell
python -m product
```

Open http://127.0.0.1:18765/

Drop-box brakes:

```powershell
python -m dropbox.orchestrator plan --scope dropbox/SCOPE.example.yaml
python -m dropbox.orchestrator run --scope dropbox/SCOPE.example.yaml --stage discover
python -m dropbox.orchestrator run --scope dropbox/SCOPE.example.yaml --stage deepen
python -m dropbox.orchestrator run --scope dropbox/SCOPE.example.yaml --stage ingest --run-pack
```

`--live` requests real stages and still **refuses** unsigned / unattested / empty SCOPE. Missing nmap/nessus on PATH → no install; fixture discover may fill a labeled stub.

1. Fill SCOPE from the signed authorization sheet (`consent_attested`, `signed`, named CIDRs/hosts/URLs, `allow_tools`).
2. `plan` — review shards and blast radius.
3. `run --stage discover` — quiet pass (one shard per worker, then destroy).
4. Review live set; tighten SCOPE if needed.
5. `run --stage deepen` — loud pass in batches of 2–5.
6. `run --stage ingest --run-pack` — collectors write CISO CSVs + `out/poam/`.
7. HITL: Reid reviews before any client-facing send. SimpleRisk leave-behind is the POA&M export, not a live GRC wrap.

Empty `in/` is demo fixtures, not a client estate.
