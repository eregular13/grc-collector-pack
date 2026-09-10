# Covey ike-scan pack_drop fixture (SAMPLE/DEMO)

SAMPLE/DEMO — not a client estate. Shaped like evergreen-covey `export_pack`
(`evergreen.pack_drop.v1`) for the **ike-scan** stdout-class adapter
(hyphen; Covey registry id `ike-scan`).

ike-scan is an **IKE Main Mode / Aggressive Mode sweeper**. Covey only
counts live hosts that printed a handshake with a nonzero responder
cookie. This drop lists those IKE/VPN responders. It does **not** invent
open TCP ports or fake services to look like rustscan/httpx. UDP/500 IKE
presence is not an invented TCP `open_port_observed`.

This is a **file_drop** for `inventory-nmap` → CISO Assistant. Not a live
scan. Not a client KEEP. Not a paying-day PASS. RiskReady wrap stays
review-only.

| This drop is | This drop is not |
| --- | --- |
| An IKE/VPN host surface map Covey observed via Main Mode handshake | An open-TCP-port / service map |
| Conservative `ike_handshake_observed` / `ike_responder_observed` rows | `open_port_observed` or a rustscan-shaped service list |
| SoR-ready assets / findings / evidence | A RiskReady wrap, POST, or API push |
| IKE/VPN discover (nonzero responder cookie) | Honeypot validated traffic or control OE |
