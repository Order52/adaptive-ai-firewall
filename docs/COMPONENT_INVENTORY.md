# Component inventory

Source of truth for nodes: `lab/gns3/topology.yaml`. For host firewall ports:
`lab/ansible/inventory.yaml`. For lab semantics (zones, services, protected
addresses, safety limits): `config/lab.yaml`.

## 1. Lab nodes (GNS3 project `AI-Adaptive-Firewall`)

| Node | Zone | Address | Role | Main services / ports |
|---|---|---|---|---|
| FW01 | all | .1 in every zone | OPNsense 26.7: zone firewall, `AFW_BLOCK_WEB` / `AFW_HEARTBEAT` aliases, Suricata (pcap) on ATTACK+USERS, heartbeat watchdog, NAT egress | REST API (TLS, lab CA); syslog-ng over mTLS → CTRL01:5514 (client cert `fw01-telemetry`) |
| CTRL01 | MGMT | 10.77.50.10 | Controller (`afw serve`, systemd `afw-controller`, user `afwctl`) | API + dashboard :8080 (HTTP, MGMT only); syslog mTLS :5514 (WAF01, APP01, FW01); no plaintext listener |
| DESK01 | MGMT | 10.77.50.20 | Operator desktop (XFCE/VNC, Firefox, Claude CLI) | — |
| WAF01 | DMZ | 10.77.30.10 | nginx + OWASP CRS 4.25.2; policy helper | 443 (clients); helper 9443 (CTRL01 only); rsyslog mTLS sender; heartbeat timer |
| APP01 | APP | 10.77.40.10 | Rental application v1.0.0 | 8000 (WAF01 only); rsyslog mTLS sender; heartbeat timer |
| DB01 | DB | 10.77.60.10 | PostgreSQL 16 (container) | 5432 (APP01 only) |
| USR01 | USERS | 10.77.20.10 (+ probe .250) | Benign clients (`traffic/benign_personas.py`), probe agent | probe 9180 (CTRL01 only) |
| ATK01 | ATTACK | 10.77.10.10 (+ probe .250) | Team attack host (team tooling only), probe agent | probe 9180 (CTRL01 only) |
| SW-* | — | — | One switch per zone | — |
| HOST-MGMT | MGMT | 10.77.50.254 | Host TAP `afw-mgmt0`; route 10.77.0.0/16 via FW01 | — |
| MAINT-NAT | — | — | Maintenance uplink | — |

Protected addresses that are always refused as targets: probe sources (.250),
CTRL01, WAF01 and the FW gateways (`config/lab.yaml` → `safety.protected`). The M6
harness also refuses the MGMT and DB networks as attack targets.

## 2. Host-side state (never in Git)

| Path | Contents |
|---|---|
| `~/.config/afw/gns3.env` | GNS3 API URL and credentials |
| `~/.config/afw/api/` | API tokens (dashboard/operator/admin/mcp) and `api_tokens.yaml` hashes |
| `~/.config/afw/pki/` | Lab CA and leaf certificates (mTLS sensors, FW01) |
| `~/.config/afw/opnsense/` | OPNsense controller and provisioner keys |
| `~/.config/afw/ssh_config`, `lab_ed25519` | SSH to lab guests |
| `~/.config/afw/runs/` | M6 attack-run journal |
| CTRL01 `/var/lib/afw/` | `afw.sqlite3`, datasets, model store, `geo/` (DB-IP database and metadata) |
| CTRL01 `/var/lib/afw/pre-m3-20261027.sqlite3` | DB backup taken before M3 |

## 3. Source tree (`src/afw/`)

| Package | Responsibility |
|---|---|
| `domain/` | Pure models: events (envelope v2), features, risk/evidence, policy, learning (checkpoints, evaluations, probations), adaptation |
| `ports/` | Repository and enforcement protocols |
| `telemetry/` | Syslog receivers (plain + mTLS), line parsers, request-id correlator |
| `features/` | Window aggregation (30 s / 5 s hop) and the 13 behavioural features |
| `profiling/` | Trusted behavioural profile builder and diff |
| `ml/` | Detectors (robust stats, Isolation Forest, HST), evaluation, experiments (M0/M1/M2 replay), online replay, adaptation experiment (M4), challenger gate (M3), run-level evaluation (M6), datasets |
| `correlation/` | Evidence items, independence rules, risk engine, IDS-only assessment |
| `policy/` | Decision engine, validator (safety), lifecycle service, reconciler |
| `enforcement/` | OPNsense alias backend, WAF helper backend, in-memory backend |
| `services/` | Runtime controller loop, learning service, shadow learner, challenger lifecycle, explanations |
| `persistence/` | SQLAlchemy schema, Alembic migrations 0001–0003, repositories |
| `api/` | FastAPI app, token auth, roles |
| `dashboard/` | Static single-page dashboard (reads the API only) |
| `mcp/` | MCP server (controller tools + GNS3 tools) |
| `lab/` | GNS3 automation, OPNsense provisioning, isolation verification, layout, M6 scenario harness |
| `geoip.py` | DB-IP country lookup, integrity, freshness, preview (M7) |
| `cli.py`, `config.py`, `container.py` | Entry point, configuration models, dependency wiring |

Other directories:

* `apps/rental/`: protected application.
* `waf/`: WAF configuration.
* `traffic/`: benign persona generator.
* `lab/`: topology, images, Ansible roles, OPNsense scripts.
* `config/`: `lab.yaml`, `scenarios.yaml`.
* `tests/`: unit, integration, and live-lab tests (`AFW_LAB=1`).
* `migrations/`: Alembic.

## 4. Operator entry points

| Surface | Commands / endpoints |
|---|---|
| CLI `afw` | `serve`, `config-check`; `db upgrade`; `token issue`; `dataset list/capture`; `train bootstrap/promote/rollback/status`; `experiment replay/online-replay/evaluate/adaptation`; `challenger evaluate/status`; `scenario list/begin/mark/end/abort/watchdog/manifest`; `geoip install/lookup`; `lab build/start/stop/status/recreate/provision-fw/provision-ids/deploy/layout/verify` |
| REST API (`/api/...`) | health, overview, resources, events, detections, assessments, sources/{ip}; policies (+ simulate, approve, reject, revoke, explain); mode, strategy, feedback; profiles (diff, candidates, promote, rollback, reject), models, adaptation, experiments, audit; learning/shadow, learning/challenger (+ evaluate, promote, rollback); geo/status, geo/lookup, geo/preview |
| Dashboard | `http://10.77.50.10:8080/` (SSH tunnel: `ssh -N -L 18080:10.77.50.10:8080 …`) |
| MCP server `afw` | Read: overview, detections, risk_assessments, model_status, profiles, adaptation_status, shadow_learning, challenger_lifecycle, active_policies, policy_history, explain_policy, experiment_results, geo_preview, geo_lookup, verify_isolation, lab_* tools. Write, validated: simulate_block, block_source, unblock, approve/reject_policy, set_mode, country_policy (simulated only), feedback, start/stop/restart_node (CTRL01 refused) |

## 5. Versions

* Python 3.12 (`uv`, locked in `uv.lock`); River, scikit-learn, FastAPI, SQLAlchemy 2,
  Pydantic 2.
* OPNsense 26.7, Suricata with ET Open, OWASP CRS 4.25.2, PostgreSQL 16.
* GNS3 2.2.61; host Ubuntu 24.04.5.
