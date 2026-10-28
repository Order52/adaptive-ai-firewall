# Project status

**As of 2026-10-27, branch `engineering-directive`.** This is the single status page.
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
evaluation needs team-run attack scenarios. Online adaptation is shown on recorded real
drift, not yet live. Its most important measured weakness: the v2 models, trained on one
5.4-minute run of six addresses, raise many false positives when the legitimate workload
changes (`RESULTS.md` §3, corrected 2026-10-28).

## 2. Gates

| Gate | Status | Main gap |
|---|---|---|
| A Infrastructure | **MET** | — |
| B Detection | **NOT MET** | No labelled attack runs (BLOCKED-EXT); FN unmeasurable |
| C Genuine adaptation | **PARTIAL** | Shown on real recorded drift offline; live challenger learned 0 (fail-closed); no live promotion; gate refuses (attack recall, sensitive invariance) |
| D Enforcement | **MET** | — |
| E Independent value | **NOT MET** | Benign-only comparison; value under attack BLOCKED-EXT |
| F Security and operations | **PARTIAL** | Plain-HTTP API on MGMT (by design, ADR-023); FW01 IDS feed plaintext |
| G Academic defensibility | **PARTIAL** | Team demonstration only the team can do; attack-side methodology unexercised |

## 3. Milestones (engineering directive)

| M | Scope | Status |
|---|---|---|
| M0 | Audit, baseline, hygiene | DONE |
| M1 | Provenance-aware corroboration | DONE (SV-1 open) |
| M2 | Online shadow learning, eligibility, mTLS provenance | PARTIAL (live learning not yet observed) |
| M3 | Champion/challenger gate, promotion, probation, rollback | DONE; live gate BLOCKED-EXT |
| M4 | Adaptation experiments on real drift | DONE (found and fixed a poisoning flaw) |
| M5 | Telemetry v2, IDS-only view, liveness | DONE (found and fixed two live defects) |
| M6 | Attack-evaluation harness | DONE; Gate B BLOCKED-EXT |
| M7 | Real GeoIP lookup and preview | DONE; real-country enforcement not implemented |
| M8 | Dashboard views for M2–M7 | DONE |
| M9 | Documentation consolidation | DONE (this set) |

## 4. Outstanding gaps, in priority order

1. **Team attack runs (unblocks B, E, the M3 live gate, half of G).** At least 3 runs
   per scenario family through `afw scenario begin/mark/end` → `afw scenario manifest`
   → `afw dataset capture` → `afw experiment evaluate`. Procedure:
   `engineering/M6_ATTACK_EVALUATION.md` §2.
2. **Broader benign training data.** The v2 profile generalises poorly to new users
   (`RESULTS.md` §3). Capture longer, multi-user benign runs, rebuild the profile via the
   reviewed batch path, and re-measure new-user FPR.
3. **Live online adaptation.** The deployed caps (30 min tenure, 20 windows per source
   per hour) plus taint from champion proposals mean live learning needs hours of
   untainted traffic. Options:
   * operator FALSE_POSITIVE feedback to clear taint;
   * a reviewed batch rebuild first.
4. **Sensitive invariance.** The adapted challenger lost sensitivity to auth-abuse-like
   variants. Investigate before any promotion.
5. **Hardening.** RELP for loss-free telemetry; TLS on the FW01 IDS feed; TLS for the API
   if access other than the SSH tunnel is needed.
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
