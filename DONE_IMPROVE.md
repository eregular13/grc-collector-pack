GREEN

KEEP-HK, KEEP-MAESTER, KEEP-TESTSSL, KEEP-ASFF2 each have a fixture and a passing parser test.

- HardeningKitty: `fixtures/demo/identity/hardeningkitty.csv` + `test_hardeningkitty_csv`
- Maester: `fixtures/demo/saas/maester.json` + `test_maester`
- testssl: `fixtures/demo/vuln/testssl.json` + `test_testssl`
- ScoutSuite (ASFF already covered): `fixtures/demo/cloud/scoutsuite.json` + `test_scoutsuite` / `test_prowler_asff`

pytest: 36 passed
lab: assets 62, findings 58, vulns 15, evidence 10
idempotent: double lab.ps1 assets 62 unique=62
compose: loader exit 0, same counts
evidence: all nine sensors named in evidences.csv
