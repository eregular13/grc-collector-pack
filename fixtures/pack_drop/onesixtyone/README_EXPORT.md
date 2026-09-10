# Covey onesixtyone pack_drop fixture (SAMPLE/DEMO)

SAMPLE/DEMO — not a client estate. Shaped like evergreen-covey `export_pack`
(`evergreen.pack_drop.v1`) for the **onesixtyone** stdout-class adapter.

onesixtyone is **SNMP community / sysDescr** discover. This drop lists
hosts that answered with a community and a sysDescr. It does **not**
invent open TCP ports or fake services to look like rustscan/httpx.

This is a **file_drop** for `inventory-nmap` → CISO Assistant. Not a live
scan. Not a client KEEP. Not a paying-day PASS. RiskReady wrap stays
review-only.

| This drop is | This drop is not |
| --- | --- |
| A community / sysDescr surface map Covey observed via SNMP | An open-TCP-port / service map |
| Conservative `snmp_community_observed` / `sysdescr_observed` rows | `open_port_observed` or a rustscan-shaped service list |
| SoR-ready assets / findings / evidence | A RiskReady wrap, POST, or API push |
| SNMP community/sysDescr discover | Honeypot validated traffic or control OE |
