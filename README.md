# AI-Adaptive-Firewall

An application-aware, explainable, safety-constrained **adaptive network defence**
built and evaluated in an isolated GNS3 laboratory. Mature engines (OPNsense pf +
Suricata IDS, OWASP CRS WAF) provide enforcement and telemetry; the project's
contribution is the **AI control plane on CTRL01** that closes the loop:

> **Observe → Profile → Detect → Correlate → Decide → Validate → Enforce → Verify → Learn.**

It learns a trusted behavioural profile of a protected application from real
traffic, detects and correlates deviations across WAF/app/IDS evidence, proposes
*proportional* responses, validates them against safety rules, enforces through a
real firewall/WAF, verifies the effect on live traffic, and adapts to legitimate
change via reviewed shadow learning — never letting an anomaly alone, or repeated
malicious traffic, silently redefine "normal".

## Status (2026-10-27)

Read `docs/PROJECT_STATUS.md` first. In short:

- **Works end to end on a real GNS3 lab** (8 VMs, 6 zone switches, 2 host connectors):
  * mTLS sensor telemetry with liveness;
  * behavioural detection and evidence correlation;
  * verified enforcement on OPNsense and the WAF;
  * dashboard and a 30-tool MCP interface;
  * a governed online-learning lifecycle (shadow challenger, promotion gate, probation
    rollback).
- **Measured on real traffic:** 0 false positives on the training population, but
  **high false-positive rates on new benign users** (`docs/RESULTS.md` §3). Online
  adaptation cut HST false alarms from about 65 % to about 3 % on recorded real drift.
  The gate still refuses promotion.
- **Gates:** A and D met; C, F and G partial; B and E not met. Attack-side evaluation
  is **blocked** on team-run attack scenarios. The harness is ready
  (`docs/engineering/M6_ATTACK_EVALUATION.md`).

## Quick start

```bash
# dev toolchain
uv sync
uv run pytest            # 155 unit/integration tests (+9 live-lab with AFW_LAB=1)
uv run mypy src && uv run ruff check src tests

# lab (GNS3 running; see docs/DEPLOYMENT.md for first-time host setup)
afw lab status           # node inventory + state
afw lab layout           # professional zone canvas
afw lab verify           # zone isolation (37 checks)

# AI
afw train status                               # profiles + models
afw experiment replay --datasets <held-out>    # M0/M1/M2 comparison

# controller + dashboard (on CTRL01 via systemd; or locally):
afw serve                # HTTP :8080 (TLS opt-in); dashboard at /
claude mcp list          # confirm the `afw` MCP server is Connected
```

Dashboard over SSH tunnel: `ssh -N -L 18080:10.77.50.10:8080 gns3@<host>` →
`http://localhost:18080/` (token: `~/.config/afw/api/dashboard.token`).

## Architecture

```
Claude Code / team ──(MCP, stdio)──► afw MCP tools ──► controller REST API
                                              │              │
                                     GNS3 lab automation   CTRL01: AI core
                                                           telemetry→profiles
                                                           ML+rules→correlation
                                                           policy→verify→feedback
                                                                 │
                                                        FW01 (OPNsense pf+IDS)
                                                        WAF01 (OWASP CRS)
Data plane:  ATK01/USR01 → FW01 → WAF01 → APP01      SQLite + API + dashboard
```

Modular monolith, hexagonal (`domain` / `ports` / adapters); SQLAlchemy confined to
`persistence`; typed + validated (Pydantic); ML/features/policy/adapters decoupled
so new apps, sensors, backends and models slot in without touching core logic.

## Documentation

| Doc | Purpose |
|---|---|
| `docs/PROJECT_STATUS.md` | **Read first**: gates, milestones, gaps, readiness |
| `docs/VALIDATION_MATRIX.md` | Every acceptance criterion → tests → evidence |
| `docs/ARCHITECTURE.md` | System architecture, flows, trust boundaries |
| `docs/COMPONENT_INVENTORY.md` | Nodes, ports, source tree, entry points |
| `docs/ARCHITECTURE_DECISIONS.md` | ADR-001…033 |
| `docs/AI_RESEARCH.md` | Research question, contribution, detectors, leakage controls |
| `docs/ADAPTATION_DESIGN.md` | Online learning, gate, promotion, rollback |
| `docs/THREAT_MODEL.md` | Threats and mitigations |
| `docs/EXPERIMENTS.md` | Methodology |
| `docs/RESULTS.md` | Measured results, including negative ones |
| `docs/SECURITY_AND_LIMITATIONS.md` | Safety invariants and known gaps |
| `docs/DEPLOYMENT.md` | Install, configuration, recovery |
| `docs/OPERATOR_GUIDE.md`, `docs/MCP_GUIDE.md` | Day-to-day operation |
| `docs/FINAL_DEMO.md` | Repeatable demonstration |
| `docs/GNS3_TOPOLOGY.md` | Live topology |
| `docs/engineering/` | Milestone design notes (M2–M7) and `AUTONOMOUS_PROGRESS.md` |
| `docs/archive/` | Superseded status files (history only) |

## Safety & integrity

Authorized activity only within the isolated lab. Secrets live in `~/.config/afw/`
(never in Git). Synthetic fixtures are software-correctness tests and are never cited
as research results; every experiment row records whether it is a synthetic demo or a
captured lab run.
