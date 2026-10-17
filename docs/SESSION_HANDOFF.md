# Session handoff

_Exact state for the next session to resume without rediscovery. Updated
2026-10-17 (session 3)._

## Environment / services (verified this session)

- Repo: `~/uot/ai-adaptive-firewall`, branch `session3-mcp-dashboard-tls-gns3`
  (pushed to `origin` = git@github.com:Order52/adaptive-ai-firewall.git).
- GNS3 project `AI-Adaptive-Firewall`: 13/13 nodes started (6 guests, 5 switches,
  cloud, NAT). GNS3 API on 127.0.0.1:3080.
- Controller: `afw-controller` systemd on CTRL01, **HTTP** on 10.77.50.10:8080
  (TLS opt-in, off). Reached from a dev machine via SSH tunnel
  `-L 18080:10.77.50.10:8080` → `http://localhost:18080/`.
- MCP: project `.mcp.json`, `claude mcp list` → `afw ✔ Connected` (http, 26 tools).
- Tests: 57 passed, 9 lab-skipped; mypy strict clean; ruff clean.
- Tokens/secrets live in `~/.config/afw/` (never in Git). Dashboard token:
  `~/.config/afw/api/dashboard.token`.

## In-flight work (real-data AI training)

- **Benign traffic generator**: `traffic/benign_personas.py` (legitimate journeys,
  stdlib, source-bound). Copied to USR01 `/tmp/benign_personas.py`.
- **USR01 has source aliases** 10.77.20.11/12/13 added (plus .10) for multi-source
  benign traffic. _Reversible:_ `ip addr del 10.77.20.1X/24 dev ens3`.
- Running a real benign TRAIN capture, then VALIDATION. Then on CTRL01 (as afwctl,
  cwd `/var/lib/afw`): `afw dataset capture <id> --manifest <m.json> --purpose
  train|validation` → `afw train bootstrap --train <t> --val <v>` → promote via API
  `POST /api/profiles/rental/<v>/promote` (admin token) which reloads the controller.
- **Live controller currently has a SYNTHETIC demo profile v1** (`demo-*` datasets,
  scenario `synthetic-ui-demo (NOT a lab result)`). The real profile will become v2
  and be promoted over it. To fully remove the synthetic demo: reject/retire v1 and
  delete `/var/lib/afw/datasets/demo-*`.

## Exact next commands

```
# 1. (host) record start, run benign traffic from USR01 (4 sources), record end
# 2. (CTRL01, as afwctl, cwd /var/lib/afw) capture + bootstrap:
sudo -u afwctl env -C /var/lib/afw AFW_CONFIG=/etc/afw/lab.yaml AFW_DATA_DIR=/var/lib/afw \
  AFW_API_TOKENS_FILE=/etc/afw/secrets/api_tokens.yaml \
  /opt/afw/venv/bin/afw dataset capture real-benign-train --manifest /tmp/m_train.json --purpose train
# (same for validation), then:
  ... afw train bootstrap --train real-benign-train --val real-benign-val
# 3. (host) promote via API:
curl -s -XPOST -H "Authorization: Bearer $(cat ~/.config/afw/api/admin.token)" \
  -H 'Content-Type: application/json' -d '{"note":"real benign baseline"}' \
  http://10.77.50.10:8080/api/profiles/rental/<v>/promote
# 4. verify low FPR on fresh benign traffic; run `afw experiment replay`.
```

## Known blockers

- **Attack/adversarial labelled traffic**: not generable here (safety). Blocks
  attack recall, scenarios A/B/E, incremental-AI-value numbers. Machinery ready.
- GNS3 canvas: no pixel screenshot (desktop GUI); verified via API.

## Recovery

- Lab rebuilds from code (see `docs/GNS3_TOPOLOGY.md`). Controller DB on CTRL01
  `/var/lib/afw/afw.sqlite3`. To revert the USR01 aliases and synthetic demo, see
  above. No host networking was changed this session.
