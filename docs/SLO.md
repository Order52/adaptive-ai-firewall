# Service levels, capacity and drills

Targets for a lab-scale single-controller deployment. Every number below is either measured
(with the date and command) or marked *not measured*. Metrics come from `GET /api/metrics`
(viewer token, Prometheus text) and `GET /api/readyz`.

## Service level objectives

| # | Objective | Target | Indicator | Measured |
|---|---|---|---|---|
| 1 | Controller availability | ready 99 % of the time; restart after a crash under 30 s | `afw_ready`, `/api/readyz` | `SIGKILL` of the controller: ready again in **9.3 s**, policies unchanged (9 184), mode kept (drill A, 2026-11-16). Code rollback or upgrade: **16 s** |
| 2 | Telemetry freshness | a silent sensor is flagged within 150 s and recovery is seen within 10 s of its return | `afw_sensor_stale`, `afw_telemetry_degraded` | WAF heartbeat stopped: flagged at **151 s**, readiness 503 naming the failed checks; ready again **4 s** after restoring (drill B, 2026-11-16) |
| 3 | Pipeline latency | request visible in the observation store within 3 s (p95); pipeline tick under 100 ms (p95) up to the stated capacity | `afw_tick_milliseconds` | Telemetry latency **0.5-2.0 s** (upper bound of the method, `artifacts/evidence/a3-2026-10-29/telemetry-latency.txt`). Tick p95 **46 ms at 2 000 req/s** (`scripts/loadtest.py ingest`, 2026-11-16) |
| 4 | False blocks on benign traffic | zero enforced blocks on benign traffic | `afw_active_policies` | 0 policies over a 60-minute benign soak (`RESULTS.md` section 7). Enforce mode is not enabled (monitor mode) until the attack-recall gate passes |

Not measured: end-to-end time from first malicious request to an applied block (needs the
team's attack runs, Phase 1), and availability over a calendar month.

## Capacity (software, synthetic traffic)

`scripts/loadtest.py`, 2026-11-16, 200 sources, 10 s per rate, in-process pipeline of a
simulated controller (classify, correlate, window, features; no trained profile loaded, so
detector scoring is excluded: single-row scoring is about 11.9 ms for Isolation Forest, about
63 microseconds for the statistical arm, per `SECURITY_AND_LIMITATIONS.md`).

| Requests/s | Dropped | Tick p50 / p95 / max | RSS | Degraded flag |
|---|---|---|---|---|
| 100 | 0 | 2 / 12 / 14 ms | 182 MB | no |
| 500 | 0 | 8 / 22 / 87 ms | 207 MB | no |
| 1 000 | 0 | 18 / 28 / 87 ms | 246 MB | no |
| 2 000 | 0 | 35 / 46 / 111 ms | 266 MB | no |
| 3 000 | 25 000 of 30 000 | n/a (overflow) | 270 MB | **yes** |

**Ceiling: about 2 500 requests/s.** Records wait 2 s for their join partner and at most 5 000
may wait (`join_wait_s`, `max_pending`), so above roughly 2 500 requests/s the correlator
sheds load. Shedding is counted (`join_overflow`) and flips the telemetry-degraded flag, which
pauses automatic enforcement: the failure is loud, not silent. The lab's heaviest capture
(66 users) was far below this.

**API.** 20 concurrent clients, 20 s, dashboard request mix against a local instance:
1 283 requests/s, 0 errors, p50 12 ms, p95 35 ms, p99 45 ms (empty database, so
data-heavy endpoints are lighter than on the live lab). One open dashboard tab costs about
230 requests/min; the default limit of 3 000/min per client address supports about 13 tabs.

**Storage.** The controller database was 2.7 GB on 2026-11-16, of which 2.1 GB was free pages.
After `VACUUM` it is **517 MB** (disk use 48 % to 29 %). The `assessments` table, the only
table without retention, now ages out after 90 days unless a policy or feedback record cites
the row; freed pages are returned incrementally. See `runbooks/database-maintenance.md`.

## Failure drills (2026-11-16, live lab)

| Drill | Action | Observed | Safe end state |
|---|---|---|---|
| A. Controller crash | `SIGKILL` to `afw-controller` | systemd restarted it; ready in 9.3 s | policies 9 184 before and after, mode `monitor` kept |
| B. Sensor silent | stopped `afw-heartbeat.timer` on WAF01 | at 151 s: `sensors_fresh` and `telemetry_not_degraded` fail, `/api/readyz` 503, `afw_sensor_stale{sensor="waf"} 1` | recovered 4 s after restart; no enforcement change (monitor mode) |
| C. Bad release | rolled CTRL01 back to `main`, then forward | 16 s each way; API healthy after each | hardened version restored, exposure 2.9 |
| D. Certificate | rotated CTRL01's certificate | new key and cert, same SANs; clients unaffected (trust the CA) | `afw_tls_certificate_days_left` 397 |
| E. Backup and restore | `scripts/backup_controller.sh`, then restore onto CTRL01 | backup 10-14 s (31 MB) including a scratch restore proof. **First restore attempt, a hand-typed runbook, failed**: `tar` could not read an uploaded temp file, the command chain stopped, the controller stayed **stopped for about 4 minutes** and the old `-wal` file sat beside the new database (corrupt read view). Recovered by deleting the stale WAL and verifying the file against the backup's sha256. Fixed by `scripts/restore_controller.sh` (streams files, removes WAL first, checks sha256 and integrity before starting, keeps a pre-restore copy). Second rehearsal: backup + restore + ready in **22 s** | 9 184 policies, integrity ok, `afw lab verify` 41/41 |
| Not run | FW01 reboot, full disk | FW01 resources were fixed and stress-tested on 2026-10-29 (`artifacts/evidence/fw01-oom-fix-2026-10-29/`); disk is covered by the retention and vacuum change plus the `certificate`/`database` readiness checks | |

A stale `ids` sensor (FW01 Suricata) follows the same path as drill B. `degraded` pauses
automatic enforcement (ADR-031); IDS-only evidence never exceeds WATCH.
