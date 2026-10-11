# poam/

Runtime artifacts only. `poam-id-migration.csv` is generated per run into the
work `out/poam/` folder by `scripts/fixstack/build_migration_map.py` (via
`fixstack_apply.py`) from the prior ledger's per-finding IDs and the current
package-parent / TLS-posture rows. Do not commit lab-specific migration maps.
