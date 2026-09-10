# Covey fping pack_drop fixture (SAMPLE/DEMO)

SAMPLE/DEMO — not a client estate. Shaped like evergreen-covey `export_pack`
(`evergreen.pack_drop.v1`) for the **fping** stdout-class adapter.

fping is a **host-only** Covey adapter (ICMP / reachability discover). This
drop lists live hosts. It does **not** invent open ports or fake services
to look like rustscan/httpx.

This is a **file_drop** for `inventory-nmap` → CISO Assistant. Not a live
scan. Not a client KEEP. Not a paying-day PASS. RiskReady wrap stays
review-only.

| This drop is | This drop is not |
| --- | --- |
| A host-up / reachability surface map Covey observed via ICMP | An open-port / service map |
| Conservative `host_up_observed` rows | `open_port_observed` or a rustscan-shaped service list |
| SoR-ready assets / findings / evidence | A RiskReady wrap, POST, or API push |
| Host-only ICMP/reachability discover | Honeypot validated traffic or control OE |
