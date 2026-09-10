# Covey braa pack_drop fixture (SAMPLE/DEMO)

SAMPLE/DEMO — not a client estate. Shaped like evergreen-covey `export_pack`
(`evergreen.pack_drop.v1`) for the **braa** stdout-class adapter.

braa is an **SNMP GET sweeper** (OID / sysDescr / sysName). This drop lists
hosts that answered a community GET with a sysDescr (and the sysDescr OID).
It does **not** invent open TCP ports or fake services to look like
rustscan/httpx.

This is a **file_drop** for `inventory-nmap` → CISO Assistant. Not a live
scan. Not a client KEEP. Not a paying-day PASS. RiskReady wrap stays
review-only.

| This drop is | This drop is not |
| --- | --- |
| A community / OID / sysDescr surface map Covey observed via SNMP GET | An open-TCP-port / service map |
| Conservative `snmp_community_observed` / `sysdescr_observed` / `oid_observed` rows | `open_port_observed` or a rustscan-shaped service list |
| SoR-ready assets / findings / evidence | A RiskReady wrap, POST, or API push |
| SNMP GET sweeper (OID/sysDescr/sysName) | Honeypot validated traffic or control OE |
