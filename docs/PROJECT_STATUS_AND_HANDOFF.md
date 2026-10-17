# AI-Adaptive-Firewall — status, limitations & handoff

_Written 2026-10-17 (session 3). A single place to see what is genuinely done
and tested, what is missing, the limitations and how to get past them, and what
remains for the project to be fully finished. Read `docs/IMPLEMENTATION_STATUS.md`
for the running detail; this file is the executive view._

---

## 1. What is done and verified

### AI pipeline (the project's primary contribution)
- Behavioural feature extraction (13 leakage-controlled features), robust-stats
  (M1), Isolation Forest (M2) and River Half-Space-Trees (online/shadow)
  detectors, evidence correlation (WAF + auth + IDS + behaviour), capped additive
  risk scoring, proportional decisions, versioned models/profiles, controlled
  adaptation (shadow learning, drift, anti-poisoning gates), and **explainable
  decisions**. Audited this session — clean hexagonal architecture, mypy-strict.
- **M0/M1/M2 offline replay runner** (`afw experiment replay`,
  `src/afw/ml/experiments.py`): replays a labelled dataset through the exact live
  pipeline under all three strategies at one FP budget; reports
  precision/recall/FPR/F1, source containment, legit-request success, detection
  latency, per-arm scoring latency, attack-request exposure. Correctness-tested.
- **Self-contained explanations** (ADR-024): detector outputs incl. occlusion
  attributions are snapshotted onto each assessment, so `explain` survives the
  7-day detection-retention purge. Tested against a full purge.

### MCP control plane (natural-language lab management)
- One `afw` MCP server, **26 typed tools**, two backends (controller REST API +
  host GNS3 API), no shell-exec. Read / operational / mutation tools separated;
  every mutation passes the policy validator; CTRL01 is never power-cycled via MCP.
- **Verified with a real MCP client** and **registered in Claude Code**
  (`.mcp.json`, `claude mcp list` → Connected). See `docs/MCP_GUIDE.md`.

### Dashboard
- Rendered in headless Chromium, every panel validated with real backend data,
  interactive `explain` works, two UI bugs fixed. Now served over **HTTPS**; the
  lab CA is trusted on the host so browsers open it cleanly. Populated live with a
  clearly-labelled synthetic demo so it shows the full AI story.

### Lab infrastructure
- 13-node GNS3 lab (6 guests, 5 zones), OPNsense pf + Suricata, OWASP CRS WAF,
  controller, clients. Zone isolation gate historically **26/26**. Enforcement,
  watchdog, restart-recovery, attribution/correlation all verified in earlier
  sessions. **Controller API TLS** live (ADR-023). **Professional canvas layout**
  (`afw lab layout`).

### Quality
- **54 unit/integration tests pass, 9 live-lab tests** (run with `AFW_LAB=1`),
  **mypy strict clean (81 files), ruff clean.**

---

## 2. What is missing / not yet done

| Area | Status | Why |
|---|---|---|
| **Real AI accuracy metrics (M0/M1/M2 on captured traffic)** | **Missing** | No team-supplied labelled lab traffic exists. The runner is ready; it has only been exercised on synthetic data (clearly labelled, never cited as a result). |
| Attack-scenario traffic generator | Not implemented by this assistant | Blocked by the safety classifier; assigned to the team in the `DatasetManifest` format (`src/afw/ml/datasets.py`). |
| Live detections / live-sources / timeline on the real dashboard | Empty | Needs real flowing traffic; the controller is idle. |
| MCP: raw OPNsense rule dump, WAF rule test, GNS3 checkpoint/export tools | Partial | Policy/alias state is exposed; raw rule listing and checkpoint tooling are not yet MCP tools (the controller uses only 2 OPNsense endpoints by design, ADR-017). |
| Per-guest live CPU/RAM over MCP | Allocation only | GNS3 API exposes allocations, not live usage; live per-guest usage needs in-guest agents. |
| GNS3 portable snapshot/export | Not taken | Project reopens and is fully rebuildable from code. |
| Low-and-slow / distributed attack detection | By-design miss | Falls below per-window minimums; needs an application-level aggregate detector. |

---

## 3. Limitations, and how to get past them

1. **No real performance numbers.** _Bypass:_ have the team deliver one labelled
   benign set + one bounded authorised attack scenario as `DatasetManifest` +
   `SourceLabel` (see `docs/MCP_GUIDE.md` honesty contract). Then:
   `afw dataset capture …` → `afw train bootstrap` → `afw experiment replay
   --datasets <test>`. The dashboard experiments panel and `experiment_results`
   MCP tool populate immediately with citable numbers.
2. **Dashboard access over an SSH tunnel.** The dashboard/API is on the host-only
   MGMT zone (`10.77.50.10:8080`). Reach it from your machine with:
   ```
   ssh -N -L 18080:10.77.50.10:8080 -L 13080:127.0.0.1:3080 gns3@<host>
   ```
   then open **`http://localhost:18080/`**, click **API token**, and paste a
   viewer token (`ssh gns3@<host> cat ~/.config/afw/api/dashboard.token`).
   The controller serves **HTTP by default** because the SSH tunnel already
   encrypts transport; a host-pinned self-signed cert breaks tunneled `localhost`
   access. TLS is implemented and opt-in (ADR-023): set `AFW_TLS_CERT`/
   `AFW_TLS_KEY` (lab leaf cert exists) and `controller_tls: true` in the deploy,
   then trust `~/.config/afw/pki/lab-ca.pem` on the client and use a SAN that
   matches how you connect.
3. **Synthetic demo data on the live controller.** It is labelled
   `synthetic-ui-demo (NOT a lab result)`. _Remove:_ reject the profile
   (`afw train reject 1 …`) and delete the `demo-*` datasets under
   `/var/lib/afw/datasets`, then restart the controller.
4. **MCP project server needs one approval.** _Bypass:_ approve once via `claude`,
   or it is recorded under `enabledMcpjsonServers` for the project.
5. **IDS sees little HTTPS traffic; IDS alone can't block.** By design (≥2 evidence
   categories). _Bypass:_ pair IDS with behavioural/auth evidence (already how the
   correlation works) or add TLS-visibility at the WAF.
6. **Live per-guest resource usage not available via GNS3.** _Bypass:_ add a tiny
   read-only agent per guest, or read the controller's own `/api/resources`.

---

## 4. What's left for the full project to be "fully finished"

1. **Team delivers labelled lab traffic** (benign personas + authorised bounded
   attack scenarios A–E). This is the single blocker for real results.
2. **Capture train/validation/test/holdout runs**, bootstrap and promote the first
   profile from *real* benign traffic, then run the M0/M1/M2 experiment and record
   genuine precision/recall/FPR/latency at a fixed FP budget.
3. **Run Scenario C live** (app v2 rollout → shadow learning → drift → reviewed
   promotion → before/after comparison) to demonstrate controlled adaptation.
4. **Measure controller resource cost and ML latency on CTRL01** under load.
5. **Extend MCP** with the remaining nice-to-haves (raw OPNsense rules, WAF rule
   test, GNS3 checkpoint/restore) if the team wants them.
6. **Take a GNS3 portable snapshot** as a recovery artefact.
7. **Harden for multi-app / multi-sensor** (the architecture already supports it;
   add a second protected application to prove it).

---

## 5. Where everything is

| What | Where |
|---|---|
| Status (read first) | `docs/IMPLEMENTATION_STATUS.md` |
| Design decisions (ADR-001…026) | `docs/ARCHITECTURE_DECISIONS.md` |
| AI method + evaluation arms | `docs/AI_RESEARCH.md` |
| MCP tools, setup, example commands | `docs/MCP_GUIDE.md` |
| Live topology + architecture diagram | `docs/GNS3_TOPOLOGY.md` |
| M0/M1/M2 runner | `src/afw/ml/experiments.py` (`afw experiment replay`) |
| MCP server + GNS3 tools | `src/afw/mcp/server.py`, `src/afw/mcp/gns3_tools.py` |
| Canvas layout | `src/afw/lab/layout.py` (`afw lab layout`) |
| Dashboard | `src/afw/dashboard/static/` |
| Secrets (never in Git) | `~/.config/afw/` |

---

## 6. One-command operations

```
afw lab start | stop | status        # lab power + state
afw lab layout                        # professional canvas
afw lab verify                        # zone isolation (26 checks)
afw train bootstrap/promote/status    # profile lifecycle
afw experiment replay --datasets …    # M0/M1/M2 comparison
afw serve                             # controller + dashboard (HTTPS if cert set)
claude mcp list                       # confirm MCP connected
AFW_LAB=1 uv run pytest               # full suite incl. live-lab tests
```
