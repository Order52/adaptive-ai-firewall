# Operator guide

Day-to-day operation of the AI-Adaptive-Firewall lab. Commands run on the host
unless marked (CTRL01). The controller runs as the `afw-controller` systemd service
on CTRL01 as user `afwctl`; its data dir is `/var/lib/afw`.

## Lab lifecycle

```bash
afw lab status            # node inventory + run state (8 VMs, 6 switches, cloud, NAT)
afw lab start | stop      # power the GNS3 project on/off
afw lab layout            # (re)apply the professional zone canvas (idempotent)
afw lab verify            # 37 zone-isolation checks from inside the guests
afw lab deploy            # idempotent Ansible (re-run is changed=0 when in sync)
```

Dashboard: `ssh -N -L 18080:10.77.50.10:8080 gns3@<host>` → `http://localhost:18080/`,
click **API token**, paste `~/.config/afw/api/dashboard.token`.

## AI / profiles / models

```bash
afw train status                                  # (CTRL01) profiles + models + status
# capture a benign run into a dataset, then train:
afw dataset capture <id> --manifest <m.json> --purpose train|validation|test|holdout
afw train bootstrap --train <train-ids> --val <val-ids>     # (CTRL01) builds a candidate
# promote (reloads the running controller) via the API:
curl -XPOST -H "Authorization: Bearer $(cat ~/.config/afw/api/admin.token)" \
     -H 'Content-Type: application/json' -d '{"note":"..."}' \
     http://10.77.50.10:8080/api/profiles/rental/<v>/promote
afw train rollback <v> <reviewer> "<note>"        # roll back to a previous trusted profile
afw experiment replay --datasets <held-out-ids>   # M0/M1/M2 comparison
```

Generating **benign** training traffic (legitimate journeys only):

```bash
# on a client guest (e.g. USR01), bind multiple source IPs for a richer profile:
AFW_SOURCES=10.77.20.10,10.77.20.11 AFW_DURATION=300 python3 traffic/benign_personas.py
```

## Operating modes

- `monitor` — detect + record, never enforce (safe default; "recorded, not applied").
- `assisted` — AI proposes; an operator approves each policy before it is applied.
- `auto` — AI applies validated, proportional, expiring policies itself.

Change mode (admin): `POST /api/mode {"mode":"assisted"}` or the MCP `set_mode` tool.

## Policies

- Watch the lifecycle on the dashboard: proposed → validated → applying →
  applied_unverified → enforced → expired / rolled_back. "Enforced" requires device
  read-back **and** traffic verification.
- Protected/management addresses (probe source, CTRL01, WAF01, FW gateway) are always
  refused by the validator — a block request against them ends `rejected`.
- Revoke: `POST /api/policies/<id>/revoke`; approve/reject pending: `/approve`,`/reject`.

## Online learning and model promotion (M2–M4)

- Dashboard **Online learning**: the challenger's learned count against the HST window,
  why windows were excluded (tainted, sensitive, overlap, tenure, …), champion vs
  challenger agreement, and learned windows with their provenance fingerprint. Shadow
  only: it never affects decisions.
- Evaluate a challenger (admin, CTRL01):
  `afw challenger evaluate --benign <holdout-ids> --attack <real-attack-run-ids>`
  (or `POST /api/learning/challenger/evaluate`). It fails without real attack runs:
  that is by design.
- Promote a *passed* evaluation (admin only, no MCP tool):
  `POST /api/learning/challenger/<evaluation_id>/promote {"note": "..."}`. Probation
  starts and rolls back automatically on excess anomalies or 3 false-positive reports.
- Report false positives with `POST /api/feedback {"label":"false_positive", ...}` or
  the MCP `feedback` tool; this is also how operator input reaches probation.
- Manual rollback: `POST /api/learning/challenger/rollback`.

## Telemetry health (M5)

The **Telemetry health** panel shows each mTLS sensor's heartbeat age. A sensor silent
for 150 s is **stale**: evidence is marked degraded and automatic actions pause
(header chip "telemetry degraded"). Fix with `afw lab deploy --limit <host>` or
check `rsyslog` / `afw-heartbeat.timer` on the sensor. **IDS-only sources** (seen by
Suricata without HTTP traffic) appear in their own panel and are watched at most.

## Attack runs (team only, M6)

The project never generates attack traffic. Team members run their own tools from
ATK01 against WAF01 using the harness:

```bash
afw scenario list
afw scenario begin web-sqli-probe <operator-name>     # ground truth starts
afw scenario mark <run-id> "phase 2"
afw scenario end <run-id>                              # or: afw scenario abort <run-id> "<reason>" (stops ATK01)
afw scenario watchdog                                  # keep running during a run: aborts past max duration
afw scenario manifest <run-id> run.json --benign 10.77.20.10   # then afw dataset capture
afw experiment evaluate --datasets <run-1>,<run-2>,<run-3>
```

Full procedure: `engineering/M6_ATTACK_EVALUATION.md` §2.

## GeoIP (M7)

`GET /api/geo/lookup/<ip>`, `GET /api/geo/preview/<CC>?direction=inbound|outbound` (MCP
`geo_lookup`, `geo_preview`) show the real country data and what a country policy
would cover. Real-country *enforcement* is refused; enforced country policies use the
SIMULATED lab mapping (`country_policy` with `simulated=true`). The **GeoIP** panel shows
the database release and age; refresh monthly (`DEPLOYMENT.md` §7).

## Via Claude Code (MCP)

`claude mcp list` → `afw ✔ Connected`. Then ask natural-language questions — see
`docs/MCP_GUIDE.md` for the 30 tools and examples ("show the lab", "why did the AI
block X", "compare M1 and M2", "restart the WAF").

## Recovery

- **Controller restart**: `ssh ctrl01 sudo systemctl restart afw-controller` — it
  re-runs DB migrations, reloads the trusted profile + active models, and restores
  the active block table on startup (verified: profile v2 restored after restart).
- **Full lab cold start**: `afw lab stop` then `afw lab start` (then `afw lab verify`).
  The project reopens with the saved canvas; the controller restores enforcement state.
- **Dead controller**: FW01's watchdog flushes dynamic blocks within ~120 s if
  heartbeats stop (fail-safe, ADR-009).

## Health & diagnostics

- `GET /api/overview` — mode, strategy, live sources, telemetry freshness, resources.
- `GET /api/health`, `/api/resources`, `/api/audit` — service health, RSS/CPU, audit.
- Telemetry panel shows per-sensor heartbeat age (stale after 150 s → evidence degraded) and per-feed counters.

## Secrets

All under `~/.config/afw/` (never in Git): `gns3.env`, `lab_ed25519`, `ssh_config`,
`opnsense/`, `pki/` (lab CA + leaf certs), `tokens/`, `api/` (API tokens + hashes).
