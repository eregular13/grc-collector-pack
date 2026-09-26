> **SAMPLE DATA: NOT A CLIENT**: Every finding below comes from bundled example files. None describes any real organization.
> Run `not recorded` · generated 2026-09-26 06:47 UTC · pack `1f8d347`

# OpenGRC import drop (file-only)

SAMPLE DATA: NOT A CLIENT: Every finding below comes from bundled example files. None describes any real organization.

These CSVs match the OpenGRC Data Manager import wizard (https://docs.opengrc.com/data-manager/import/).

## Files

| File | Entity | Required-ish columns |
|---|---|---|
| `risks.csv` | Risks | `code`, `name`, `description`, `status`, 1–5 likelihood/impact |
| `assets.csv` | Assets | `asset_tag`, `name` (hostname/IP when known) |
| `implementations.csv` | Implementations | `title`, `details` (from CISO applied_controls) |

## Operator path

1. Produce CISO CSVs: `python3 -m dropbox ciso` or `python3 scripts/prove_ciso.py`.
2. `python3 -m exporters --sink opengrc` (reads `out/ciso-assistant`).
3. In OpenGRC: Data Manager → Import Data → Risks, then Assets, then Implementations.
4. Download the in-app CSV template if the wizard rejects a header; map columns.
5. Status is **Not Assessed**. Owner / department / taxonomy FKs stay blank.

posted=false. No REST. This is not a paying-day PASS.
