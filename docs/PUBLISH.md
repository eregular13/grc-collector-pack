# Publish this lab pack

This directory (`C:\GRC Collector\grc-collector-pack`) is the **assessment engine snapshot** (product_demo, mapped web POA&M, pytest 208+). It did not have git history until ship 0.4.0.

`C:\Users\R\grc-collector-pack` is the older public clone (`https://github.com/eregular13/grc-collector-pack.git`). **Do not fast-forward mix** the two working copies. Do not copy dirty `in/lab-*` from the clone into this tree.

## Reid: point origin and open a PR

```powershell
cd "C:\GRC Collector\grc-collector-pack"
git remote add origin https://github.com/eregular13/grc-collector-pack.git
# if origin already exists on THIS pack, use it
git push -u origin ship-0.4.0
gh pr create --title "Ship 0.4.0 product_demo + mapped POA&M" --body-file docs/PUBLISH.md
```

Recommended: push branch `ship-0.4.0`, open PR, **do not force-push `master`** until Reid reviews.

Local commit is enough until `C:\GRC Collector\PUSH_OK.txt` exists.

## What must not land on the default branch blob

- `.env`, tokens, live SCOPE with real office CIDRs
- `out/`, `dropbox/out/`, `out-estate/`, engagement zips
- USB KEEP, the other clone’s dirty `in/lab-*`
