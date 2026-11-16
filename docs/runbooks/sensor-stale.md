# Sensor stale / readiness 503

**Notice:** dashboard "telemetry degraded"; `api /api/readyz` returns 503; metric
`afw_sensor_stale{sensor="waf|app|ids"} 1`. While degraded, automatic enforcement is
paused and evidence is marked degraded (ADR-031). Nothing is blocked because of it.

**Find which check fails**
```bash
api /api/readyz | python3 -m json.tool            # checks with "ok": false
api /api/overview | python3 -c 'import json,sys;print(json.load(sys.stdin)["telemetry"]["sensors"])'
```

**Fix by sensor** (SSH config: `~/.config/afw/ssh_config`)
| Stale sensor | Check | Action |
|---|---|---|
| `waf` | `ssh waf01 'systemctl status afw-heartbeat.timer rsyslog'` | `sudo systemctl restart afw-heartbeat.timer rsyslog` |
| `app` | `ssh app01 'systemctl status afw-heartbeat.timer rsyslog'` | same on `app01` |
| `ids` (FW01) | `afw lab verify`; `pgrep suricata` on FW01 empty means Suricata died (memory) | restart the IDS service from the OPNsense UI or `afw lab provision-ids`; if FW01 is wedged, reboot via the OPNsense API with the provisioning credential (`~/.config/afw/opnsense/provisioner.*`; the controller's own API user cannot reboot it, by design). RAM was raised to 2.5 GB on 2026-10-29; a reboot was drilled on 2026-11-16 (`SLO.md` drill G) |
| all three | controller restarted recently | wait up to 150 s: a sensor that has not reconnected since start counts as stale |

**Verify:** `api /api/readyz` returns `{"ready": true}` (about 5 s after the heartbeat returns).
**Drill reference:** `docs/SLO.md` drill B (detected at 151 s, recovered in 4 s).
