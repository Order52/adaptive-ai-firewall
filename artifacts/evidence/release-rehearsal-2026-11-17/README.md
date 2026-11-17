# Release rehearsal, 2026-11-17

Non-attack steps of `docs/FINAL_DEMO.md` executed once against the live lab, as required by gate
R8 in `docs/RELEASE_CRITERIA.md`. Nothing here is an attack result; the attack step (demo step 10)
needs the team.

| Demo step | What was run | Result | File |
|---|---|---|---|
| 0 Before the audience | `afw lab status`, `afw lab verify`, `/api/readyz` | 8 VMs started; **41/41** isolation checks; readiness all green (disk 28.6 % used, certificate 395 days left) | `01-lab-status.txt`, `02-lab-verify.txt` |
| Dashboard tour | headless browser, viewer-level token, all 6 tabs | **0 console errors, 0 HTTP errors**, banner "All clear", monitor mode, nothing enforced | `06-dashboard-render.json`, `dashboard-*.png` |
| 1 Lab and isolation | as step 0 | 41/41 | `02-lab-verify.txt` |
| 2 Legitimate users | 180 s of benign v2 personas from new address 10.77.20.198 (`traffic/benign_personas.py`, valid routes and credentials only) | The controller proposed `rate_limit` for the new legitimate user (risk 58.5, band elevated); state `validated`, **not applied** (monitor mode). This is the known false-positive weakness (`RESULTS.md` §3a) and was stated as such | this file |
| 4 Explainable decision | `explain_policy` on that proposal | Drivers shown against profile baselines (`server_err_frac` z=8.33, `route_entropy` z=-5.15); thresholds 3.528 and 0.627; "NOT a probability"; model `isolation_forest-p2-20261017190622`, profile v2 | this file |
| 5 Safety guards | `simulate_block` on 10.77.50.10 and 10.77.20.198 | Management address **refused** ("protected ... recovery path", outside client zones); client address valid, `would_auto_apply: false` | `05-safety-guard.json` |
| 6 Verified enforcement | `AFW_LAB=1 pytest tests/lab` | **14 passed** (real OPNsense alias, WAF deny, rate limit, read-back, expiry, revoke, real-country blocks KP inbound and AU outbound with egress probe) | `03-live-lab-tests.txt` |

After the tests the firewall and WAF held no blocks, denies or rate limits (`lab_health`).
Note for demo day: the "latest enforcement decisions" table on the Overview tab shows these test
policies (rejected protected address, rolled-back test blocks) until newer decisions push them out.

Not rehearsed here (need a person at a desktop or a team run): 6b real country blocking on the
USR01 desktop, 7 the adaptive lifecycle walkthrough (state shown on the Learning tab), 8 and 8b
research results (documents), 9 telemetry liveness drills (done as drills A to G in `docs/SLO.md`),
10 attack scenarios.

## Findings fixed during the rehearsal

- The dashboard with no or a bad token polled about 15 times in a second and locked its own address
  out through the new authentication-failure limiter (fixed; browser-tested).
- Chart axes read 1, 5, 0 instead of 100, 50, 0 (`fmt()` stripped zeros from integers; fixed).
- The GeoIP database was 47 days old and stale (refreshed; refresh script and metrics added).
