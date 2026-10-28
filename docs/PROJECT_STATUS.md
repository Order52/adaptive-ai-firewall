# Project status

**As of 2026-10-28, branch `engineering-directive`.** This is the single status page.
Milestone detail is in `engineering/AUTONOMOUS_PROGRESS.md`; per-criterion evidence is
in `VALIDATION_MATRIX.md`. Older status files are in `docs/archive/` and are superseded.

## 1. Summary

The system runs end to end on a real GNS3 lab (8 VMs, 6 zone switches, 2 host
connectors; `GNS3_TOPOLOGY.md`):

* real telemetry from WAF, application and IDS sensors (mTLS-authenticated where the
  sensor supports it);
* behavioural detection and evidence correlation;
* safety-validated, verified enforcement on OPNsense and the WAF;
* an operator dashboard and an MCP interface;
* a governed online-learning lifecycle: shadow challenger, promotion gate, human
  promotion, probation rollback.

It is **not complete** against the directive's acceptance gates. The attack half of the
evaluation needs team-run attack scenarios. Online learning now runs live on CTRL01
(learning, pivots, restart restore, gate rejection), but no challenger has passed the
gate. Its most important measured weakness: the trusted v2 models, trained on one
5.4-minute run, restrict 13 of 16 unseen legitimate users in replay (`RESULTS.md` §3a).
A candidate trained on more varied users (v3) removes those false positives but loses
measurable ML sensitivity, so it fails its predeclared criteria and is not promoted.

## 2. Gates

| Gate | Status | Main gap |
|---|---|---|
| A Infrastructure | **MET** | — |
| B Detection | **NOT MET** | No labelled attack runs (BLOCKED-EXT); FN unmeasurable |
| C Genuine adaptation | **PARTIAL** | Live learning, pivots, restart restore and drift reports observed on CTRL01; no promotion: gate refuses (no attack recall data; sensitive invariance fails) |
| D Enforcement | **MET** | — |
| E Independent value | **NOT MET** | Benign-only comparison; value under attack BLOCKED-EXT |
| F Security and operations | **MET** | API HTTPS-only with lab CA (ADR-023 revised); all telemetry mTLS (ADR-035) |
| G Academic defensibility | **PARTIAL** | Team demonstration only the team can do; attack-side methodology unexercised |

## 3. Milestones (engineering directive)

| M | Scope | Status |
|---|---|---|
| M0 | Audit, baseline, hygiene | DONE |
| M1 | Provenance-aware corroboration | DONE (SV-1 open, needs attack runs) |
| M2 | Online shadow learning, eligibility, mTLS provenance | DONE (live learning observed 2026-10-28; rate-cap bug found and fixed) |
| M3 | Champion/challenger gate, promotion, probation, rollback | DONE; live gate BLOCKED-EXT |
| M4 | Adaptation experiments on real drift | DONE (poisoning flaw fixed; sensitivity loss traced to threshold calibration) |
| M5 | Telemetry v2, IDS-only view, liveness | DONE (found and fixed two live defects) |
| M6 | Attack-evaluation harness | DONE; Gate B BLOCKED-EXT |
| M7 | Real GeoIP lookup and preview | DONE; directional real-country enforcement added in P5 (ADR-036) |
| M8 | Dashboard views for M2–M7 | DONE |
| M9 | Documentation consolidation | DONE (this set) |
| P1 | Benign generalization (predeclared protocol) | DONE: v2 fails on unseen users; v3 candidate fails sensitivity; neither promoted |
| P2 | Sensitive invariance mechanism + matched-window gate | DONE |
| P3 | Independent attack evaluation | BLOCKED-EXT (`engineering/P3_TEAM_ATTACK_RUNBOOK.md`) |
| P4 | Real online adaptation | DONE for the governed loop; no promotion |
| P5 | Hardening | DONE: IDS mTLS, API HTTPS by default, directional real-country enforcement, node count reconciled |

## 4. Outstanding gaps, in priority order

1. **Team attack runs (unblocks B, E, the M3 live gate, half of G).** At least 3 runs
   per scenario family through `afw scenario begin/mark/end` → `afw scenario manifest`
   → `afw dataset capture` → `afw experiment evaluate`. Procedure:
   `engineering/P3_TEAM_ATTACK_RUNBOOK.md`. Also decides v3 and SV-1.
2. **A champion that both generalizes and stays sensitive.** v2 has too many false
   positives on unseen users; v3 has too little single-feature ML sensitivity
   (`engineering/P1_BENIGN_GENERALIZATION.md` §4). Next design step: keep benign variety
   in training but constrain the sensitive features (e.g. monotone constraints), then
   re-run the same predeclared protocol on fresh users.
3. **Online learning cannot correct the champion's own false positives** (policed
   sources are tainted, fail-closed by design; `M2_ONLINE_LEARNING_DESIGN.md` §9). An
   operator FALSE_POSITIVE path is the governed way to clear taint.
4. **Calibration side of sensitive invariance** (P2): the gate correctly rejects
   challengers whose recalibrated threshold loses sensitivity; whether to bound
   recalibration is an open design question.
5. **Hardening.** RELP for loss-free telemetry; a heartbeat for the FW01 IDS feed.
   Real-country inbound enforcement can only be verified by read-back in this lab.
6. **Residual poisoning risk** from 4 or more colluding similar sources; SV-1
   (occlusion is not a causal-independence proof).

## 5. Is it ready as a final-year project?

* **Ready to present as a working, carefully engineered system**, with real
  infrastructure, verified enforcement, governed adaptation and honest negative results.
* **Not ready to claim detection effectiveness or adaptive value under attack.** That
  needs item 1 above, which only the team can do.
* The team must be able to run `FINAL_DEMO.md` and explain `ARCHITECTURE.md`,
  `ADAPTATION_DESIGN.md` and `RESULTS.md` §3 themselves (Gate G).

## 6. Documentation map (directive Phase 11 deliverables)

| # | Deliverable | File |
|---|---|---|
| 1 | Architecture | `ARCHITECTURE.md` (+ `GNS3_TOPOLOGY.md`, `ARCHITECTURE_DECISIONS.md`) |
| 2 | Component inventory | `COMPONENT_INVENTORY.md` |
| 3 | AI research | `AI_RESEARCH.md` |
| 4 | Adaptation design | `ADAPTATION_DESIGN.md` (+ `engineering/M2_*`, `M3_*`, `M4_*`) |
| 5 | Threat model | `THREAT_MODEL.md` |
| 6 | Experiments | `EXPERIMENTS.md` |
| 7 | Results | `RESULTS.md` |
| 8 | Security and limitations | `SECURITY_AND_LIMITATIONS.md` |
| 9 | Deployment | `DEPLOYMENT.md` |
| 10 | Operator guide | `OPERATOR_GUIDE.md` (+ `MCP_GUIDE.md`) |
| 11 | Final demo | `FINAL_DEMO.md` |
| 12 | Validation matrix | `VALIDATION_MATRIX.md` |
| 13 | Project status | this file |
