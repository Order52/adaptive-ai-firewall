> **ARCHIVED (2026-10-27).** Superseded by `docs/PROJECT_STATUS.md` (status), `docs/VALIDATION_MATRIX.md` (evidence) and `docs/engineering/AUTONOMOUS_PROGRESS.md` (milestones). Kept unchanged below for history; statements here may be out of date.

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

## Completed this session (real-data AI milestone)

- Real benign traffic captured → **trusted profile v2** (361 win / 6 src) trained on
  real lab data, promoted over the synthetic demo. Validation FPR ~1.3%; live
  inference 0 FP on fresh benign; M0/M1/M2 on held-out real benign → FPR 0 / legit
  100%. Evidence: `artifacts/evidence/real-benign-baseline-2026-10-17.md`.
- Datasets on CTRL01: `real-benign-train2` (train), `real-benign-val` (validation),
  `real-benign-train` (held-out). Synthetic `demo-*` remain (labelled, inactive).

## Reusable tooling / next real-data work

- **Benign traffic generator**: `traffic/benign_personas.py` (legitimate journeys,
  stdlib, source-bound). Copied to USR01 `/tmp/benign_personas.py`.
- **USR01 source aliases removed** (were 10.77.20.11–15, added temporarily for
  multi-source benign capture; USR01 is back to .10 + .250 probe). To redo a
  multi-source capture: `ssh usr01 'for i in 11 12 13 14 15; do sudo ip addr add
  10.77.20.$i/24 dev ens3; done'` then remove with `ip addr del` afterwards.
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
