# MCP integration guide

The AI-Adaptive-Firewall lab is manageable from Claude Code (or any MCP client)
through the **`afw` MCP server** — a thin, typed façade over the controller REST
API (AI / policy / OPNsense enforcement) and the host-side GNS3 API (lab
infrastructure). It was verified end-to-end with a real MCP client on
2026-10-17: **26 tools**, real GNS3 topology, real AI data over HTTPS, and the
safety guards below.

## Design

- **No raw shell / no free-form firewall text.** Every tool is a typed,
  documented operation. There is no "run this command" tool.
- **Two backends, one server.** AI/policy/OPNsense/WAF tools call the controller
  REST API (`AFW_API_URL`) with a `channel=mcp` token, so every mutation flows
  through the *same* policy validator, enforcement and audit path as autonomous
  AI decisions. GNS3 infrastructure tools call the GNS3 API on the host
  (`~/.config/afw/gns3.env`). The control plane is on the host-only MGMT zone,
  reached locally or over SSH; it serves HTTP by default (set `AFW_TLS_CERT`/
  `AFW_TLS_KEY` for direct HTTPS, then add `AFW_API_CA` here).
- **Separation of concerns.** Read-only tools, operational tools (node power) and
  policy mutations are distinct. A policy mutation can never bypass the validator;
  protected/management addresses are always refused.
- **Guarded operations.** The controller node (CTRL01) is never stopped/restarted
  via MCP (it runs the control plane and this backend). The firewall (FW01) warns
  on restart. Nothing can touch hosts outside the GNS3 project.
- **No secrets in config.** `.mcp.json` references token *files*, never tokens.

## Setup (Claude Code on the lab host)

Project config is committed at `.mcp.json`:

```json
{
  "mcpServers": {
    "afw": {
      "command": "uv",
      "args": ["run", "afw-mcp"],
      "env": {
        "AFW_API_URL": "http://10.77.50.10:8080",
        "AFW_MCP_TOKEN_FILE": "${HOME}/.config/afw/api/mcp.token",
        "AFW_GNS3_PROJECT": "AI-Adaptive-Firewall"
      }
    }
  }
}
```

A project-scoped server needs a one-time approval: run `claude`, approve `afw`
(or it is recorded under `enabledMcpjsonServers` for this project). Verify:

```
$ claude mcp list
afw: uv run afw-mcp - ✔ Connected
```

The MCP token is minted with `afw token issue <name> --role <viewer|operator|admin>
--channel mcp`. Role gates mutations: `viewer` reads only; `operator` can
block/unblock/approve; `admin` can change mode and promote profiles.

## Tool catalogue (26)

**Lab infrastructure (GNS3, host-side)**
- `lab_topology` — every node (type, status, console, RAM/vCPUs) and link.
- `lab_node(name)` — one node's detailed status and ports.
- `lab_resources` — allocated RAM/vCPUs and run-state per guest.
- `start_node` / `stop_node` / `restart_node` — power control (CTRL01 refused).
- `verify_isolation` — run the 26-check zone-isolation gate from inside guests.

**AI controller (read)**
- `lab_health`, `overview` — mode, strategy, telemetry, resources, live sources.
- `recent_detections` — anomalous detector outputs with feature attributions.
- `risk_assessments` — correlated risk + evidence items.
- `model_status` — versioned models + validation metrics.
- `application_profiles` — behavioural profile versions + provenance.
- `adaptation_status` — shadow learning, drift, candidate-evaluation gates.
- `experiment_results` — M0/M1/M2 offline-replay comparison rows.
- `active_policies`, `policy_history`, `explain_policy(id)` — decisions + the
  full recorded explanation (evidence, model/profile, response, enforcement,
  effect on legit traffic).

**Policy / enforcement (mutations, validated server-side)**
- `simulate_block` — dry-run a source block.
- `block_source` / `unblock` — expiring source block + rollback (read-back verified).
- `approve_policy` / `reject_policy` — act on a pending AI proposal (assisted mode).
- `set_mode(monitor|assisted|auto)` — operating mode (admin).
- `country_policy` — simulated geo policy (optional extension).
- `feedback` — analyst label feeding drift/candidate learning.

## Example natural-language commands

| You ask Claude… | Tools used |
|---|---|
| "Show me the entire lab and the status of every device." | `lab_topology` |
| "Restart only the WAF." | `restart_node("WAF01")` |
| "Check all links and find the network problem." | `lab_topology` + `verify_isolation` |
| "Show the CPU/memory allocation of every lab guest." | `lab_resources` |
| "Show the machine-learning model's current performance." | `model_status` |
| "Show the last 20 AI detections." | `recent_detections` |
| "Why did the AI block 10.77.10.10?" | `policy_history` → `explain_policy` |
| "Compare the statistical and ML-assisted detectors." | `experiment_results` |
| "Is the application behaviour drifting?" | `adaptation_status` |
| "Block 10.77.10.23 for 10 minutes." | `block_source` (validated) |
| "Would blocking 10.77.50.10 be allowed?" | `simulate_block` → refused (protected) |
| "Switch to assisted mode." | `set_mode("assisted")` (admin) |

## Verified safety behaviour

- `restart_node("CTRL01")` → **refused** (`{"refused": true, …}`).
- `block_source("10.77.50.10")` (management address) → submitted then **rejected**
  by the validator; the address is never enforced.
- `experiment_results` rows carry a `scenario` field; a synthetic demo is labelled
  `synthetic-ui-demo (NOT a lab result)` and must not be cited as a lab result.

## Honesty contract

The server returns only what the controller recorded. An untrained model, a
synthetic test fixture and a model validated on captured lab runs are
distinguishable from the data itself (profile status, dataset purpose/scenario,
`model_version`). The server never fabricates scores, explanations or enforcement
status.
