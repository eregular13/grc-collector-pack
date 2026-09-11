# Covey svmap pack_drop fixture (SAMPLE/DEMO)

SAMPLE/DEMO — not a client estate. Shaped like evergreen-covey `export_pack`
(`evergreen.pack_drop.v1`) for the **svmap** stdout-class adapter
(Covey registry id `svmap`).

svmap prints an **ASCII SIP Device | User Agent** table. Covey only
counts live hosts that printed a **real User-Agent**. This drop rejects
UA `unknown` / empty / `user agent` / `disabled`. Services are **UDP SIP
ports from the svmap table only** (default **5060**), protocol=`udp`,
service=`sip`. It does **not** invent TCP ports.

This is a **file_drop** for `inventory-nmap` → CISO Assistant. Not a live
scan. Not a client KEEP. Not a paying-day PASS. RiskReady wrap stays
review-only.

| This drop is | This drop is not |
| --- | --- |
| A SIP Device/UA surface map Covey observed via svmap | An invented TCP port / rustscan-shaped service list |
| Conservative `sip_user_agent_observed` / `sip_udp_port_observed` rows with unique ids | A collapsed sibling finding or UA=`unknown` live host |
| UDP/5060 SIP from the svmap table | Invented TCP `open_port_observed` |
| SoR-ready assets / findings / evidence | A RiskReady wrap, POST, or API push |
| SIP Device/UA discover (real UA only) | Honeypot validated traffic or control OE |
