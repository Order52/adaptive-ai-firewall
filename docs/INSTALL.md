# Install & first-time setup

Target: Ubuntu 24.04, GNS3 2.2.x, QEMU/KVM, ~16 GB RAM. All lab guests are offline
(no Internet needed at run time). Secrets are generated on the host into
`~/.config/afw/` and never committed.

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
afw lab deploy                # Ansible: app, WAF, WAF helper, controller, probes
afw lab layout                # professional zone canvas
afw lab verify                # expect 26/26 isolation checks
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
uv run pytest                 # 57 tests; AFW_LAB=1 adds 9 live-lab tests
uv run mypy src && uv run ruff check src tests
afw experiment replay --datasets <held-out>    # M0/M1/M2
```

## Tests requiring the live lab

`AFW_LAB=1 uv run pytest tests/lab` exercises real enforcement, the IDS path and MCP
against the running lab. Without `AFW_LAB=1` those 9 tests are skipped.
