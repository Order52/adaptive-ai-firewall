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

## Status (2026-10-18)

- **Trained on REAL lab traffic** (not synthetic fixtures): trusted profile v2
  (6 real client sources, 361 windows); validation FPR ~1.3%; **live inference on
  CTRL01 → 0 false positives** on held-out benign traffic; M0/M1/M2 replay on real
  benign → FPR 0 / legit 100%. Evidence: `artifacts/evidence/`.
- **MCP control plane** (26 tools) connected to Claude Code; **dashboard** with real
  backend data; **GNS3 lab** 13 nodes / 5 zones, isolation 26/26.
- **Honest gap:** attack-side evaluation (recall, scenarios A/B/E) is **blocked** on
  team-supplied attack traces; the machinery is complete and tested. See
  `docs/IMPLEMENTATION_STATUS.md` and `docs/MASTER_COMPLETION_PLAN.md`.

## Quick start

```bash
# dev toolchain
uv sync
uv run pytest            # 57 unit/integration tests (+9 live-lab with AFW_LAB=1)
uv run mypy src && uv run ruff check src tests

# lab (GNS3 running; see docs/INSTALL.md for first-time host setup)
afw lab status           # node inventory + state
afw lab layout           # professional zone canvas
afw lab verify           # zone isolation (26 checks)

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
| `docs/IMPLEMENTATION_STATUS.md` | **Read first** — verified status with dates/evidence |
| `docs/MASTER_COMPLETION_PLAN.md` | P0–P10 gate board |
| `docs/SESSION_HANDOFF.md` | Exact resume state |
| `docs/ARCHITECTURE_DECISIONS.md` | ADR-001…026 |
| `docs/AI_RESEARCH.md` | Features, detectors, leakage controls, results |
| `docs/EXPERIMENTS.md` | M0/M1/M2 methodology + what was actually run |
| `docs/MCP_GUIDE.md` | MCP tools, setup, example NL commands |
| `docs/GNS3_TOPOLOGY.md` | Live topology + architecture diagram |
| `docs/OPERATOR_GUIDE.md` | Day-to-day operations |
| `docs/FINAL_DEMO.md` | 10–15 min repeatable demonstration |
| `docs/SECURITY_AND_LIMITATIONS.md` | Threat model, trust boundaries, limits |
| `docs/INSTALL.md` | First-time host + lab setup |

## Safety & integrity

Authorized activity only within the isolated lab. Secrets live in `~/.config/afw/`
(never in Git). Synthetic fixtures are software-correctness tests and are never cited
as research results; every experiment row records whether it is a synthetic demo or a
captured lab run.
