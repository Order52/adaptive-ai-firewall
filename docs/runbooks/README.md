# Runbooks

One page per failure or routine task. Each says how you notice, what to do, how to verify,
and how to undo. Commands run on the lab host unless stated; `CA` and `TOK` are:

```bash
CA=~/.config/afw/pki/lab-ca.pem; TOK=$(cat ~/.config/afw/api/dashboard.token)
api() { curl -s --cacert $CA -H "Authorization: Bearer $TOK" "https://10.77.50.10:8080$1"; }
```

| Situation | Runbook |
|---|---|
| Dashboard shows a stale sensor, or `/api/readyz` is 503 | [sensor-stale.md](sensor-stale.md) |
| API does not answer | [controller-down.md](controller-down.md) |
| A legitimate user was restricted or blocked | [false-positive.md](false-positive.md) |
| A promoted model behaves badly | [model-rollback.md](model-rollback.md) |
| A new version must be deployed, or a bad one backed out | [upgrade-rollback.md](upgrade-rollback.md) |
| Backup, or restore after data loss | [backup-restore.md](backup-restore.md) |
| API certificate or tokens near expiry | [credential-rotation.md](credential-rotation.md) |
| Database large, disk filling | [database-maintenance.md](database-maintenance.md) |

Monitoring: scrape `/api/metrics` (viewer token) and alert on `afw_ready == 0`,
`afw_sensor_stale == 1`, `afw_telemetry_degraded == 1`, `afw_tls_certificate_days_left < 30`,
and `afw_backend_reachable == 0`. Targets: `docs/SLO.md`.
