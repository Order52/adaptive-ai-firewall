# Project status

**As of 2026-10-29 ~05:50Z, branch `engineering-directive`.** This is the single status page.
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

**Since 2026-10-29.**

- *A3: authentication controls redesigned.* Per-account evidence and login-only
  graduated controls. On new unseen-user data, candidate S passed selection: 0 of 1 837
  legitimate logins refused, no site-wide restriction, FPR ≤ 0.0031. SYNTHETIC
  attack-resistance arithmetic passed. S is frozen; its one-shot final evaluation on
  Phase E data is **pending** (capture running).
- *NV1: network novelty on varied non-web benign traffic.* **Failed** its one-shot test
  on 22 unseen users: unfamiliar 6.8 %, and one legitimate heavy user hit the host-sweep
  ceiling. The detector stays in shadow.
- *Incremental supervised learning (river ARF/HAT).* Built with a full governance
  lifecycle; benchmarked on SYNTHETIC data only.

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
| M1 | Provenance-aware corroboration | DONE; SV-1 fixed by counterfactual residual windows (ADR-039), live attack confirmation pending |
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
| P6/P7 | Generalization without sensitivity loss (predeclared, `engineering/P6_GENERALIZATION_AND_SENSITIVITY.md`) | DONE, negative: no eligible candidate in P6 or P7 (A2); Phase E never collected. P7 on clean data: FPR ≤ 0.016, ≤ 1/16 users restricted, only by the AUTH rule on one forgetful user (predicted). Human decision needed (`RESULTS.md` §3c) |
| N1–N2 | Network visibility: Suricata flow/DNS/TLS/SSH metadata; residual network features; novelty detector | Live in **shadow** on ATTACK/USERS segments (ADR-042); calibration degenerate (web-only lab users) |
| N3–N4 | Supervised known-threat classifier; withheld-family novelty | Code + tests (synthetic); evaluation BLOCKED-EXT |
| N6 | Response states, shared-address guard | Deployed (ADR-043) |
| A3 | AUTH conflict: account-aware evidence, login-scoped graduated controls (ADR-044, `engineering/A3_AUTH_CONTROLS.md`) | Selection DONE (S eligible and selected; 0/1 837 legitimate logins refused; SYNTHETIC attack resistance passes); frozen `39b0c3b`; Phase E final evaluation running. Deployed live in monitor mode |
| NV1 | Network novelty on varied benign non-web traffic (`engineering/NV1_NETWORK_NOVELTY_VALIDATION.md`) | DONE, **negative**: dev 1.0 %, one-shot test on 22 unseen users 6.8 % [0.9, 15.8] and 1 strong verdict (heavy user, `dst_hosts_60` ceiling). Shadow; calibration installed live (shadow, not validated) |
| Item 3 | Incremental supervised classifier (river ARF/HAT), verified delayed labels, poisoning/forgetting guards, lifecycle (`ml/incremental.py`) | Code + tests; SYNTHETIC benchmark only: not clearly better than periodic RF refit. Not wired live; never enforcing. Real labelled data BLOCKED-EXT |
| Team procedure | All GNS3 scenarios incl. network (`TEAM_ATTACK_QUICKSTART.md`), withheld-family experiment (`NEW_THREAT_EXPERIMENT.md`) | Written; runs BLOCKED-EXT |
| N7 | §8 new-threat experiment; cold restart; dataset archive | Protocol + offline core (run BLOCKED-EXT); restart recovered with no manual step; archive hashed |
| Directive 10-28 items 5–8 | Attack-run preparation, four-way comparison, promotion review, reliability | DONE where not blocked: `afw dataset validate`; S-ML/HYB arms and IDS alerts in datasets (runbook §4.1); `engineering/AUTO_PROMOTION_REVIEW.md` (not enabled); crash-consistent switches (ADR-040) |

## 4. Outstanding gaps, in priority order

1. **Team attack runs (unblocks B, E, the M3 live gate, half of G).** At least 3 runs
   per scenario family through `afw scenario begin/mark/end` → `afw scenario manifest`
   → `afw dataset capture` → `afw dataset validate` → `afw experiment evaluate
   --streaming`. Procedure: `engineering/P3_TEAM_ATTACK_RUNBOOK.md`. Also confirms the
   SV-1 fix live (pure brute force is expected to be rate limited, not blocked).
2. **AUTH conflict: being resolved under A3 (owner-authorized).**
   - Selection passed and candidate S is frozen. Its final evaluation on Phase E runs
     once.
   - Passing would make S *eligible* for human promotion only. The controller stays in
     monitor mode, and the trusted v2 champion remains until then.
   - Limitation: the generated users never come near the AUTH thresholds (at most 3
     failures on one account). Friction for real users who fail 5 or more times is shown
     only by SYNTHETIC friction runs.
3. **Online learning cannot correct the champion's own false positives** (policed
   sources are tainted, fail-closed by design; `M2_ONLINE_LEARNING_DESIGN.md` §9). An
   operator FALSE_POSITIVE path is the governed way to clear taint.
4. **Calibration side of sensitive invariance** (P2): the gate correctly rejects
   challengers whose recalibrated threshold loses sensitivity; whether to bound
   recalibration is an open design question.
5. **Hardening.** Done: FW01 IDS-feed heartbeat (ADR-037) and RELP for WAF01/APP01 (ADR-038).
   Left: FW01's IDS feed cannot use RELP (OPNsense), so it keeps a ~100 s loss window.
   Real-country inbound enforcement can only be verified by read-back in this lab.
6. **Residual poisoning risk** from 4 or more colluding similar sources.
7. **Network-wide visibility is partial, and network novelty is not yet validated.**
   - *Visibility.* Only the ATTACK and USERS segments cross FW01's Suricata.
     DMZ/APP/DB/MGMT and intra-segment traffic are invisible, and TLS is opaque beyond
     SNI/version. Expanding the sensors is costed (`nv1-2026-10-29/fw01-load-*`) but not
     enabled.
   - *NV1 test failed.* Legitimate heavy users with up to 5.7 DNS lookups/min were not
     covered by the 3 heavy users in training. One heavy user reached the
     10-hosts-per-minute host-sweep ceiling.
   - *A further attempt* needs a new predeclared protocol, with per-habit or stratified
     calibration and a reasoned host-sweep ceiling, plus fresh data.
   - *Network attack recall* needs the team's runs. The incremental classifier is not
     wired live.

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
