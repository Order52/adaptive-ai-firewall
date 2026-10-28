# Cold lab restart and recovery (N7, 2026-10-28)

All 8 VMs stopped (19:40:49-19:47:34Z) and started together (`afw lab start`, 19:47:38Z).

| Check | Before | After | Result |
|---|---|---|---|
| Controller API | ok | up 19:50:00Z (+2 min 22 s), `reconciled_since_start` true | recovered |
| Telemetry | not degraded | degraded until 19:55:01Z (+7 min 23 s; automation paused meanwhile), then app/ids/waf heartbeats fresh | recovered, fail-closed while waiting |
| Trusted profile / models | v2 trusted | v2 trusted, `model_error` null | identical |
| Shadow challenger | 607 learned, counter 68, masses 18700/49500, ckpt-3446685f242e seq 16 | identical | exact restore |
| Network calibration | 1296 windows | 1296 windows; flow events flowing again (FW01 conf.d include survives reboot) | identical |
| Policies | 11 WATCH enforced (observe-only) | expired during the outage (600 s TTL) | correct |
| Enforcement backends | reachable | OPNsense and WAF reachable | recovered |
| Zone isolation | — | `afw lab verify` 41/41 | pass |
| Live lab tests | — | 14/14 (`AFW_LAB=1 pytest tests/lab`) | pass |

Operational defect found: `afw lab stop` (all nodes) hit an HTTP read timeout after
stopping 2 of 8 VMs; stopping the rest one by one worked within seconds each. The
restart itself needed no manual step.

Observation: after boot, one UDP flow each from USR01 (10.77.20.10) and ATK01
(10.77.10.10) was marked "unfamiliar" by the shadow network detector, as expected from
the degenerate calibration (`n1-2026-10-28/n2-calibration.txt`); its score was 4.5e9
because a 0 level divided it, now floored at 1 (fixed in the same commit).
