# Covey nbtscan pack_drop fixture (SAMPLE/DEMO)

SAMPLE/DEMO — not a client estate. Shaped like evergreen-covey `export_pack`
(`evergreen.pack_drop.v1`) for the **nbtscan** stdout-class adapter.

nbtscan is **NetBIOS name-table** host discover. Covey only parses live
hosts that printed a real NetBIOS name (not `<unknown>` / MAC-only). This
drop lists those hosts plus the observed names. It does **not** invent
open TCP ports or fake services to look like rustscan/httpx.

This is a **file_drop** for `inventory-nmap` → CISO Assistant. Not a live
scan. Not a client KEEP. Not a paying-day PASS. RiskReady wrap stays
review-only.

| This drop is | This drop is not |
| --- | --- |
| A NetBIOS name-table surface map Covey observed | An open-TCP-port / service map |
| Conservative `netbios_name_observed` rows | `open_port_observed` or a rustscan-shaped service list |
| SoR-ready assets / findings / evidence | A RiskReady wrap, POST, or API push |
| Host-only NetBIOS name discover | Honeypot validated traffic or control OE |
