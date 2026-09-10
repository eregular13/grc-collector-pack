# Covey nping pack_drop fixture (SAMPLE/DEMO)

SAMPLE/DEMO — not a client estate. Shaped like evergreen-covey `export_pack`
(`evergreen.pack_drop.v1`) for the **nping** stdout-class adapter.

Nping is **port/service discovery** (not host-only). Covey parses live hosts
from ICMP echo replies and open ports from TCP handshake completed (not
RST/refused). This drop emits hosts plus open TCP services and matching
`open_port_observed` rows only. No invented vulnerability, control_failure,
honeypot_validated, or riskready_post claims.

This is a **file_drop** for `inventory-nmap` → CISO Assistant. Not a live
scan. Not a client KEEP. Not a paying-day PASS. RiskReady wrap stays
review-only.

| This drop is | This drop is not |
| --- | --- |
| A surface map of hosts/services Covey observed | Honeypot validated traffic |
| Conservative `open_port_observed` rows | A control operating-effectiveness test |
| SoR-ready assets / findings / evidence | A RiskReady wrap, POST, or API push |
