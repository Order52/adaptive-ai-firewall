# Deployment, configuration and recovery

Target: Ubuntu 24.04, GNS3 2.2.x, QEMU/KVM, ~16 GB RAM. Guests need no Internet to run
(the golden image carries all runtimes); since 2026-10-22 each zone nevertheless has
outbound egress via NAT on FW01 for real tests (see `SECURITY_AND_LIMITATIONS.md`).
Secrets are generated on the host into `~/.config/afw/` and never committed. Node and
port inventory: `COMPONENT_INVENTORY.md`.

## 1. Host prerequisites (one-time)

- GNS3 2.2.61 (official PPA, `apt-mark hold`), ubridge, dynamips, QEMU/KVM, libvirt.
- `uv` (Python package/venv manager). Then in the repo: `uv sync`.
- Host-only management TAP `afw-mgmt0` (10.77.50.254) + route `10.77.0.0/16` via FW01,
  and libvirt NAT (`virbr0`). The host bootstrap is scripted in
  `lab/host/bootstrap-host.sh` (review before running; needs sudo).
- GNS3 REST API credentials in `~/.config/afw/gns3.env`
  (`GNS3_URL`, `GNS3_USER`, `GNS3_PASSWORD`).

## 2. Build the lab from code

```bash
lab/images/bake-golden.sh     # one golden Ubuntu image (controller venv + CRS by digest)
afw lab build                 # create GNS3 nodes + links (idempotent)
afw lab start
afw lab provision-fw          # OPNsense: zones, rules, aliases, API user, lab-CA cert
afw lab provision-ids         # Suricata (pcap) on client zones, EVE → syslog → CTRL01
afw lab deploy                # Ansible: app, WAF, WAF helper, controller, probes,
                              #   sensor mTLS certs, heartbeat timers, host nftables
                              #   (subset: afw lab deploy --limit ctrl01,waf01,app01)
afw lab layout                # professional zone canvas
afw lab verify                # expect 37/37 isolation checks
```

## 3. Controller, tokens, dashboard

- The controller runs as the `afw-controller` systemd service on CTRL01 (HTTP :8080;
  TLS opt-in via `AFW_TLS_CERT`/`AFW_TLS_KEY` + `controller_tls: true`).
- Issue API tokens: `afw token issue <name> --role viewer|operator|admin [--channel api|mcp]`
  (writes a hash to the tokens file, prints the secret once).
- Dashboard: `ssh -N -L 18080:10.77.50.10:8080 gns3@<host>` → `http://localhost:18080/`,
  paste `~/.config/afw/api/dashboard.token`.

## 4. MCP for Claude Code

Project `.mcp.json` is committed (no secrets — token file paths). Approve once
(`claude`, accept `afw`) or it is recorded under the project's `enabledMcpjsonServers`.
Verify: `claude mcp list` → `afw ✔ Connected`. See `docs/MCP_GUIDE.md`.

## 5. Train the first real profile

```bash
# generate benign traffic from a client guest (legitimate journeys):
AFW_SOURCES=10.77.20.10,10.77.20.11 AFW_DURATION=300 python3 traffic/benign_personas.py
# capture train + validation runs and bootstrap (on CTRL01, as afwctl):
afw dataset capture <train-id> --manifest <m.json> --purpose train
afw dataset capture <val-id>   --manifest <m.json> --purpose validation
afw train bootstrap --train <train-id> --val <val-id>
# promote via POST /api/profiles/rental/<v>/promote (admin token)
```

## 6. Verify

```bash
uv run pytest                 # 155 tests (+9 live-lab with AFW_LAB=1)
uv run mypy src && uv run ruff check src tests
afw experiment replay --datasets <held-out>    # M0/M1/M2
```

## Tests requiring the live lab

`AFW_LAB=1 uv run pytest tests/lab` exercises real enforcement, the IDS path and MCP
against the running lab. Without `AFW_LAB=1` those 9 tests are skipped.

## 7. Real GeoIP (optional, M7)

```bash
curl -fLO https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz   # CC BY 4.0
scp -F ~/.config/afw/ssh_config dbip-country-lite-YYYY-MM.csv.gz ctrl01:/tmp/
ssh -F ~/.config/afw/ssh_config ctrl01 'sudo -u afwctl env AFW_CONFIG=/etc/afw/lab.yaml \
  AFW_DATA_DIR=/var/lib/afw /opt/afw/venv/bin/afw geoip install /tmp/dbip-country-lite-YYYY-MM.csv.gz \
  --release YYYY-MM --source https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz'
ssh -F ~/.config/afw/ssh_config ctrl01 'sudo systemctl restart afw-controller'   # loads it
```

Refresh monthly; `/api/geo/status` reports `stale` after 45 days.

## 8. Recovery procedures

| Situation | Procedure | Verified |
|---|---|---|
| Controller restart | `sudo systemctl restart afw-controller` on CTRL01. Policies are restored from the DB by the reconciler; sensors reconnect without action | restore 5 s; sensors 12–59 s (`m5-2026-10-27/`) |
| Controller dead | Nothing: FW01's watchdog flushes dynamic blocks after about 120 s | 106 s (`docs/archive/IMPLEMENTATION_STATUS.md`) |
| Sensor stale in dashboard | Check `systemctl status rsyslog afw-heartbeat.timer` on the sensor; `afw lab deploy --limit <host>` restores configuration | `m5-2026-10-27/heartbeat-liveness.txt` |
| Whole lab power cycle | `afw lab stop` → `afw lab start` → `afw lab verify` → `AFW_LAB=1 uv run pytest tests/lab` | `cold-restart-2026-10-18.md` |
| Bad promoted challenger | `POST /api/learning/challenger/rollback` (admin), or automatic during probation | unit and replay tests (M3/M4) |
| Bad promoted profile | `POST /api/profiles/rental/<v>/rollback` (admin) or `afw train rollback` | unit tests |
| Controller database | Stop the service, copy `/var/lib/afw/afw.sqlite3` (backup before M3: `/var/lib/afw/pre-m3-20261027.sqlite3`); restore by copying back, then `afw db upgrade` runs on start | backup taken 2026-10-27 |
| Rebuild from nothing | Sections 1–2, then `afw lab verify` | Phase 0 / M0 |
