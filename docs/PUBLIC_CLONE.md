# Public clone

You cloned `https://github.com/eregular13/grc-collector-pack`. This is the published product tree.

## What to run

```powershell
python -m pytest tests -q
powershell -ExecutionPolicy Bypass -File .\scripts\lab.ps1
python -m product
```

Then open **http://127.0.0.1:18765/**. The console binds localhost only.

Drop real scanner output into `in/<sensor>/`. Empty `in/` uses `fixtures/demo/` and labels records `demo`.

## Optional agent-lab notes

`.cursor/`, `LOOP.md`, `AGENTS.md`, and `DONE_*.md` are agent-lab notes. They are not required to use the product. Leave them in the clone; you can ignore them.

See `docs/CANONICAL_TREE.md` if you also have another GRC tree on disk.
