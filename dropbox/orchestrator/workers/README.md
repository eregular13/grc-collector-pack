Short-lived workers are process/job specs, not a scanner image.

Discover: one shard per worker, then `destroy_workers("discover")`.
Deepen: one small batch (2–5 hosts) per worker, then `destroy_workers("deepen")`.

Do not bake Nmap, Nessus, Nuclei, or OpenVAS into these snippets. BYO on the drop box only.
