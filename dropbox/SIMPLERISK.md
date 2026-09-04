# SimpleRisk — leave-behind only

This slice does **not** push to SimpleRisk and does not invent a SimpleRisk API client.

After a consented drop-box run:

1. Take `out/ciso-assistant/*.csv` (and the console drop zip).
2. Import into CISO Assistant with clica/UI (Reid-side SoR).
3. If the client also uses SimpleRisk, a human copies relevant rows by their own process.

No `push_simplerisk.sh`. No auto-create of risks. No FindingsAssessment UUIDs.
