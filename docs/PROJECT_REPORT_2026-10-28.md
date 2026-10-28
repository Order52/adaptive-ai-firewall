# AI-Adaptive-Firewall: complete project report

**As of 2026-10-28 ~15:40Z, branch `engineering-directive`.** This document covers
everything in one place:
- what the project is;
- what has been built and fixed;
- what works and what is wrong;
- the limitations;
- what is missing before it is a finished, defensible final-year project, and before it
  could ever be called "production ready".

It summarises the detailed documents and does not replace them (map in §11). Nothing here
claims the project is complete. Where a result does not exist yet, it says so.

---

## 1. What the project is

An adaptive firewall controller for a web application. It runs on a real GNS3 lab with
8 VMs, 6 zone switches and 2 host connectors (`GNS3_TOPOLOGY.md`):

| Node | Role |
|---|---|
| FW01 | OPNsense firewall: zone separation, dynamic block aliases, Suricata IDS |
| WAF01 | Reverse proxy / WAF in front of the application |
| APP01, DB01 | The protected application (car rental) and its database |
| CTRL01 (10.77.50.10) | The controller: telemetry intake, features, ML, correlation, policy, enforcement, API, dashboard |
| USR01 | Legitimate-user traffic generator (scripted personas) |
| ATK01 | Attack zone, used only by the team for authorized attack runs |

The pipeline:
1. Sensors (WAF, application, IDS) send telemetry over mTLS.
2. The controller builds 30-second behaviour windows per source.
3. Anomaly detectors score each window: robust statistics and Isolation Forest enforce;
   Half-Space-Trees runs in shadow only.
4. The anomaly score is combined with independent evidence categories (AUTH, WAF, IDS,
   HISTORY) into a capped evidence score.
5. The controller proposes an action (watch, rate limit, block), checks it against
   safety rules, applies it on OPNsense or the WAF, and reads it back to verify it.

A governed online-learning loop exists:
- a shadow challenger learns only from eligible benign traffic;
- a gate compares it with the champion;
- a human promotes;
- probation runs with automatic rollback.

**Stack.** Python, hexagonal architecture, Pydantic, SQLAlchemy/SQLite, typer CLI `afw`,
Ansible deployment, HTTPS API, operator dashboard and an MCP interface.

**Quality bar.** ruff, mypy strict, and 267 passing tests (14 more need the live lab).

---

## 2. Status at a glance

| Gate (from the engineering directive) | Status | Why |
|---|---|---|
| A Infrastructure | **MET** | Reproducible lab, isolation 41/41, idempotent deploy |
| B Detection | **NOT MET** | No labelled attack runs yet, so false negatives and recall cannot be measured |
| C Genuine adaptation | **PARTIAL** | Live learning, pivots and restart restore observed; no challenger has passed the gate, and no promotion has happened |
| D Enforcement | **MET** | Real OPNsense/WAF actions, read-back verification, expiry, protected-address refusal |
| E Independent value | **NOT MET** | Only a benign-side comparison exists; value under attack needs attack runs |
| F Security and operations | **MET** | HTTPS API, mTLS telemetry, audited and constrained MCP, tested recovery |
| G Academic defensibility | **PARTIAL** | Documentation and methodology done; the team demonstration is still to come |

**In one sentence:** the engineering (infrastructure, telemetry, enforcement, safety,
governance) works and is well tested. The central AI claim, that the system detects
attacks better than static rules and adapts safely, is **not yet demonstrated**. The
attack data needed for that comes only from the team, and the current champion model has
a real false-positive problem on unseen users.

---

## 3. What was done: chronological summary

### 3.1 Milestones M0–M9 (2026-10-27)

| M | What | Outcome |
|---|---|---|
| M0 | Audit, baseline tag, hygiene | Baseline `baseline-2026-10-27`; audit in `docs/audit/` |
| M1 | Provenance-aware corroboration (ADR-027) | Evidence must be independent; later found flawed (SV-1, fixed in ADR-039) |
| M2 | Online shadow learning, eligibility, mTLS provenance | Live learning on CTRL01 (367 windows, 2 pivots, exact restore across restarts). **Bug found and fixed:** a leaking per-source rate cap |
| M3 | Champion/challenger gate, promotion, probation, rollback | Code, 20 lifecycle tests, mutation-checked; the live gate correctly refuses (no attack recall data) |
| M4 | Adaptation experiments on real drift | **Real poisoning flaw found and fixed** (driver-name corroboration: 140/180 poison windows learned before, 0/180 after). Sensitivity loss traced to threshold recalibration |
| M5 | Telemetry v2, IDS-only view, sensor liveness | **Two live defects found and fixed:** a silent ~55-minute stall after restart, and heartbeat JSON mangled by systemd quoting |
| M6 | Attack-evaluation harness | Scenario registry, journal, kill switch, watchdog, run-level CIs; waiting for team runs |
| M7 | Real GeoIP (DB-IP Lite) | Lookup and preview with integrity and freshness checks |
| M8 | Dashboard panels for M2–M7 | Rendered live, no console errors |
| M9 | Documentation consolidation | 13 deliverables, validation matrix, single status page |

### 3.2 Directive priorities P1–P5 (2026-10-28, morning)

| P | What | Outcome |
|---|---|---|
| P1 | Benign generalization, with a protocol predeclared before data | **Negative result, reported honestly.** The v2 champion restricts **13 of 16 unseen legitimate users** in replay. The v3 candidate (more varied training data) restricts 0/16 but **fails** the predeclared sensitivity criteria, so it was not promoted. An earlier "six new users" claim was found to be false and corrected |
| P2 | Sensitive invariance | Mechanism found: threshold recalibration, not the learned model. The gate check was rebuilt on matched windows per feature (ADR-034); 6/6 desensitization mutants are caught |
| P3 | Independent attack evaluation | **BLOCKED-EXT.** Harness and the team runbook (`P3_TEAM_ATTACK_RUNBOOK.md`) are ready |
| P4 | Real online adaptation | Governed loop shown live; no promotion |
| P5 | Hardening | Each item below is done |

P5 items:
- FW01 IDS feed on mTLS (ADR-035).
- API HTTPS by default.
- Directional real-country enforcement (ADR-036). A live read-back defect was found and
  fixed.
- FW01 IDS heartbeat (ADR-037).
- RELP for WAF and application telemetry (ADR-038): dead-session loss went from 105/150
  to 0/150.

### 3.3 Directive 10-28a and 10-28b (2026-10-28, afternoon; this session)

**A. P6: generalization without sensitivity loss** (the main open AI question)

*Protocol, fixed before any data* (`engineering/P6_GENERALIZATION_AND_SENSITIVITY.md`):
- Separate training, calibration, selection and final datasets of real lab traffic, each
  with its own users.
- Seven candidates:
  - R2 and R3: v2 and v3, as references;
  - D: more data;
  - F: Wilson lower-bound fractions;
  - C: cohort thresholds;
  - S: D plus a fixed security path;
  - FS: F plus the security path.
- A selection rule and five final criteria, all predeclared.

*Amendment A1, also before selection data:* an adaptation stress test. Thresholds are
recalibrated with 3 % attack-shaped windows labelled benign. This checks whether
sensitivity can be silently eroded.

*Generator v2* adds legitimate archetypes: forgetful, slow, power, households, stale
links, city filtering. Building it exposed two old generator bugs:
- every v1 booking returned 422 (a missing `city` field);
- the deployed app is v1, so `/reviews` returns 404.

Both inflated legitimate errors in all earlier data. They are documented, not hidden.

*Data collected so far:*

| Phase | Dataset | Result |
|---|---|---|
| C | `p6-train` | 120,282 observations |
| C | `p6-val` | 39,517 observations |
| D | `p6-sel`, `p6-sel-shift` | Collecting now, 15:17:54Z to ~16:03Z |

Both Phase C datasets passed every validation check, and their counts **exactly equal the
WAF log counts (zero loss)**.

*Still to run:* Phase D model selection, the freeze commit, Phase E (`p6-final`,
`p6-final-shift`, `p6-final-v1`), and the final evaluation, run once. **No P6 result
exists yet.**

**B. SV-1: evidence independence was wrong (ADR-039)**

The old "occlusion" method called up to **76 %** of login-failure-caused anomalies
"independent" evidence. A block can therefore have rested on one cause counted twice.

The replacement re-scores each window *without* the requests behind the evidence
(counterfactual residuals). False independence is now 0 in every tested cell.

The behaviour change is stated openly: pure brute force now gets a strict rate limit, not
a block. Brute force plus another independent signal is still blocked.

Legacy stored vectors, which have no residuals, can **never** count as independent
evidence. A test confirms that they cannot authorize a block.

**C. Rollback and promotion reliability (ADR-040)**

Fault injection showed that an interrupted switch could leave:
- no active HST;
- no trusted profile;
- a profile with no models;
- a profile with robust statistics only.

All switches are now single transactions, and probation is recorded first.

The real-process validation run this session, on a copy of CTRL01's data, found two more
defects. Both are fixed (commit `37ab2e4`):
1. A corrupt **active** model file crashed the controller at load, causing a crash loop.
   The controller now runs with no ML, reports degraded and shows `model_error` in
   `/api/health`.
2. A promotion or rollback **to** a version with a corrupt file succeeded. Every file is
   now loaded and checked before the switch.

A rollback killed after any of its 8 writes always left the previous profile complete.

**D. IDS liveness (ADR-041)**

Suricata frozen for 240 s still looked healthy: the heartbeat only checked that a process
existed. **Defect demonstrated, then fixed.** The heartbeat now requires a running state
and a fresh `stats.log`. After the fix, a 300 s freeze was flagged stale and degraded at
+152 s and recovered 40 s after resume.

**E. RELP crash loss**

The controller was SIGKILLed mid-traffic 3 times: **0 of 6,851** WAF-logged requests were
lost. This does not prove that the sub-second "acknowledged but unprocessed" window can
never lose a line.

**F. Other work**

| Area | What | Outcome |
|---|---|---|
| GeoIP | Re-examined | No defect. Stale data affects an active policy for at most its 1-hour cap; new policies are refused on stale data |
| Attack-run preparation | `afw dataset validate`, runbook updates | `afw dataset validate` checks counts, time range, duplicate ids, labels, attack zone, provenance, synthetic data and split leakage. It confirmed a P1 fact: 5 of 6 "new" `real-drift-hold` users were in v2's training data |
| Four-way comparison harness | Static, frozen ML, streaming ML, hybrid | Ready. **Defect found and fixed:** evaluations had been replayed without IDS alerts |
| Automatic promotion review | `AUTO_PROMOTION_REVIEW.md` | **Not enabled.** Never automatic for enforcing models; for the shadow HST only after attack recall, live learning and P6 evidence exist, and only with bounds |
| Deployment | `3175203` at the Phase C/D boundary | Verified by file sha256; isolation 41/41, live-lab tests 14/14 |

---

## 4. Defects found and fixed (complete list)

Every item below was **demonstrated** before it was fixed.

| # | Defect | Fix | Where |
|---|---|---|---|
| 1 | Per-source learning rate cap leaked | Cap enforced correctly; 3/3 mutants caught | M2 |
| 2 | Poisoning via driver-name corroboration (140/180 learned) | Corroboration redesigned (0/180) | M4 |
| 3 | Telemetry silently stalled ~55 min after restart | Reconnect fixed | M5 |
| 4 | Heartbeat JSON mangled by systemd quoting | Quoting fixed | M5 |
| 5 | TCP syslog lost lines in dead sessions (105/150) | RELP (0/150) | ADR-038 |
| 6 | Country-enforcement read-back wrong live | Read-back fixed | ADR-036 |
| 7 | "Six new users" claim false | Corrected in RESULTS and P1 | P1 |
| 8 | Evidence independence (occlusion) up to 76 % wrong | Counterfactual residuals | ADR-039 |
| 9 | Legacy vectors could still count as independent | Never independent now | ADR-039 rev. |
| 10 | Interrupted switches left no model or profile | Single transactions | ADR-040 |
| 11 | Failed automatic rollback raised every tick, with the breached model still active | Fail closed, audited | ADR-040 |
| 12 | Corrupt active artifact crashed the controller | Run without ML, degraded, `model_error` | ADR-040 (`37ab2e4`) |
| 13 | Switch to a corrupt version succeeded | Artifacts verified before switch | ADR-040 (`37ab2e4`) |
| 14 | Frozen Suricata looked alive | Engine-liveness heartbeat | ADR-041 |
| 15 | Evaluations replayed without IDS alerts | IDS alerts stored with datasets | D6 |
| 16 | v1 generator bookings all returned 422 | Documented; v2 generator correct | P6 §3.2 |
| 17 | Selection driver used a missing key (`fpr`) | Uses `rate` | P6 driver |

---

## 5. What works (with evidence)

- **Infrastructure:** reproducible build and deploy (second run `changed=0`); zone
  isolation 41/41; cold restart recovers.
- **Telemetry:** WAF, application and IDS over mTLS. RELP gave zero loss in tests.
  Heartbeats make silent sensors visible, now including a frozen IDS engine.
- **Enforcement:** real OPNsense alias blocks, WAF deny and rate limits, each verified by
  read-back and probe before being marked `enforced`. Policies expire. Protected and
  management addresses are always refused. FW01 flushes dynamic blocks within ~120 s if
  the controller dies.
- **Safety logic:**
  - an anomaly alone never blocks: a block needs ≥ 2 independent evidence categories;
  - IDS-only evidence never exceeds WATCH;
  - automatic enforcement pauses when a sensor is stale.
- **Governance:** the trusted model is frozen. Promotion needs a passing gate and a human
  admin. Probation rolls back automatically, and switches are crash-consistent.
- **Online learning:** learns live from eligible traffic, with anti-poisoning controls,
  pivots and exact restore across restarts.
- **Evaluation machinery:** predeclared protocols, leakage checks, run-level CIs, dataset
  validation, and a four-way comparison harness.
- **Operations:** HTTPS API with role tokens, an audited and constrained MCP (no shell, no
  promotion tool), and the dashboard.
- **Engineering quality:**
  - 267 tests passing, 14 lab tests passing live;
  - mypy strict and ruff clean on `src` and `tests`;
  - mutation checks on the critical logic;
  - 41 ADRs.

---

## 6. What is wrong or unproven

1. **Detection is unproven.** No real labelled attack traffic has been evaluated, so
   recall, false negatives and the value over static rules are unknown. This is the
   biggest gap, and only the team can close it.
2. **The live champion (v2) produces too many false positives.** It restricts 13 of 16
   unseen legitimate users in replay, because it was trained on one 5.4-minute run.
   **Enforce mode must not be used with this profile.** P6 is the attempt to fix this;
   its result is pending.
3. **The generalization/sensitivity trade-off is unsolved so far.** More varied data (v3)
   removes the false positives but loses ML sensitivity. Whether any P6 candidate passes
   both is not yet known. If none does, that is reported as a failure.
4. **No promotion has ever happened live.** The gate refuses because it has no attack
   recall data and because of the sensitivity loss. Adaptation benefit has been shown
   offline only, for the HST arm.
5. **Online learning cannot fix the champion's own false positives.** Sources the
   champion polices are tainted by design (fail-closed). An operator false-positive
   feedback path is the governed route.
6. **The security path may be carrying the ML.** On P1 data under the stress test, P6
   candidate S's must-detect rate relies on the fixed security rules (IDOR: ML 0.78, rules
   0.22). The P6 report will separate ML-only, rules-only and combined so that weak ML
   cannot hide.
7. **Some earlier data is weak.** All pre-P6 legitimate traffic contained inflated client
   errors (the 422/404 generator bugs). Several "unseen" P1 users were actually seen in
   training. Those results stay separate and are never called independent.
8. **Lint debt.** One over-long line in `traffic/benign_personas.py` is deliberately left
   until P6 ends, because the running generator must match the committed file. The
   evidence scripts under `artifacts/` are outside lint scope.

---

## 7. Limitations (by design or by environment)

- **IDS visibility is limited.** Client-to-WAF traffic is HTTPS, so Suricata mostly sees
  scans and non-HTTP signatures. IDS is supporting evidence only.
- **Low-and-slow and distributed attacks** fall below the per-window minimum (3 requests
  per 30 s window). This is an expected miss; an aggregate detector is future work.
- **Residual poisoning risk.** Four or more colluding, tenured, similar sources can
  vouch for each other.
- **FW01's IDS feed cannot use RELP** (OPNsense limitation), so it keeps a loss window of
  about 100 s. Heartbeat staleness makes that gap visible.
- **RELP acknowledges on queueing.** A crash can lose sub-second, acknowledged but
  unprocessed lines. None were lost in 3 kills, which is not proof that none can be.
- **The IDS heartbeat** proves the engine loop runs, not that every packet is inspected.
  A hang without a stop was not reproduced.
- **Real-country inbound blocks** are verified by read-back only, because no
  real-country traffic reaches the lab. Countries above 40,000 networks are refused.
- **Scores are anomaly/evidence scores, not probabilities.** Isolation Forest costs about
  11.9 ms per row, against about 63 µs for the statistical arm.
- **Single host:** about 7 GB of a 16 GB machine. Throughput at scale is untested.
- **Self-signed lab PKI.** Clients must trust the lab CA. Not suitable outside the lab.
- **Not air-gapped.** Guests have Internet egress for real tests.
- **Lab fragility.** An unattended host upgrade restarted gns3server once and stopped
  every VM. Recommendation (a host change the agent did not make): exclude `gns3server`
  from needrestart's automatic restarts.
- **Datasets live on CTRL01** (`/var/lib/afw/datasets`), not in Git, so reproducing
  results needs the lab's data.
- **Legitimate traffic is scripted.** Personas approximate real users; they are not real
  users. Synthetic feature-level regression cases send no traffic and measure sensitivity
  regression only, never attack detection.

---

## 8. Data honesty rules followed throughout

- Three kinds of data are always kept apart:
  - **scripted legitimate traffic**: real packets from scripted personas;
  - **synthetic feature-level cases**: no traffic, labelled SYNTHETIC;
  - **real labelled attack traffic**: none exists yet.
- No attack-traffic generator was written. The team supplies all attack scenarios.
- No metric was fabricated. Every number has an evidence file under
  `artifacts/evidence/`.
- Protocols and acceptance criteria were committed **before** the data they judge, and
  were not changed to get a favourable result.
- Final test sets are used once, after selection is frozen, and never for tuning.
- The contaminated P1 "new-user" evaluation is kept separate from the independent P6
  final evaluation.

---

## 9. What is missing to finish it as a final-year project

In priority order:

| # | Item | Who | Unblocks |
|---|---|---|---|
| 1 | **Finish P6**: Phase D selection, freeze commit, Phase E, final evaluation run once; report denominators, CIs, decomposition and stress, including failure if nothing passes | Agent (in progress, ~2 h of lab time) | Answer to the false-positive problem |
| 2 | **Team attack runs**: ≥ 3 runs per scenario family (brute force, credential stuffing, enumeration, IDOR, scraping, scans) via `afw scenario begin/mark/end` → `manifest` → `dataset capture` → `dataset validate` → `experiment evaluate --streaming` (`P3_TEAM_ATTACK_RUNBOOK.md`) | **Team** | Gate B, Gate E, M3 live gate, four-way comparison, live SV-1 confirmation |
| 3 | **Four-way comparison results** (static vs frozen ML vs streaming ML vs hybrid) on those runs | Agent, after #2 | Gate E (the core "AI adds value" claim) |
| 4 | **One human-authorized promotion** through the gate, with probation observed live, if a candidate passes | Team approves, agent executes | Gate C fully |
| 5 | **Team demonstration**: run `FINAL_DEMO.md`; explain `ARCHITECTURE.md`, `ADAPTATION_DESIGN.md` and `RESULTS.md` without help | **Team** | Gate G |
| 6 | Update RESULTS, PROJECT_STATUS and VALIDATION_MATRIX with the P6 and attack results | Agent | Documentation |
| 7 | Archive the datasets (hashes already in manifests) with the submission, or document how to obtain them | Team decision | Reproducibility |

When #1 to #5 are done, the project is a strong, defensible final-year project, whether
or not the AI turns out to beat static rules. An honest negative result with sound
methodology is still a valid outcome. What cannot be submitted is a claim of detection
effectiveness without #2 and #3.

---

## 10. What "production ready" would additionally need (beyond a final-year project)

These are **not required** for the degree project, but they are what a real deployment
would need. State them in the report as future work:

1. **Detection validated on real traffic**: real users and real attacks over weeks, with
   a measured false-positive budget per user, not just per window.
2. **A champion that passes both generalization and sensitivity**, monitored
   continuously.
3. **High availability**: the controller is a single process on a single VM with SQLite.
   Production needs redundancy, a server database, and failover for enforcement state.
4. **A real PKI and secrets management** (an HSM or vault, rotation, revocation)
   instead of the lab CA and files under `~/.config`.
5. **Loss-free telemetry end to end**: durable queueing (acknowledge after persisting)
   and an IDS feed with guaranteed delivery.
6. **Scale and performance testing**: many sources, many applications, and
   enforcement-table limits on the firewall.
7. **Detectors for low-and-slow and distributed attacks** (aggregate, cross-source).
8. **A stronger poisoning defence** against colluding sources.
9. **Operational maturity**: alerting and on-call integration, runbooks for every failure
   mode, backup and restore drills, upgrade and rollback of the controller itself.
10. **Independent security review** of the API, MCP and enforcement paths, and
    penetration testing of the controller.
11. **Privacy and legal review** of telemetry retention and of country blocking.
12. **Automatic promotion stays off** until the bounds in `AUTO_PROMOTION_REVIEW.md` are
    implemented and independently validated. Human authorization remains mandatory for
    high-impact policy changes and model promotion.

---

## 11. Where everything is

| Topic | File |
|---|---|
| Single status page | `docs/PROJECT_STATUS.md` |
| Per-criterion evidence | `docs/VALIDATION_MATRIX.md` |
| Milestone detail | `docs/engineering/AUTONOMOUS_PROGRESS.md` |
| Decisions (ADR-001…041) | `docs/ARCHITECTURE_DECISIONS.md` |
| Results so far | `docs/RESULTS.md` |
| Limitations | `docs/SECURITY_AND_LIMITATIONS.md`, `docs/THREAT_MODEL.md` |
| P1 (negative result) | `docs/engineering/P1_BENIGN_GENERALIZATION.md` |
| P6 protocol | `docs/engineering/P6_GENERALIZATION_AND_SENSITIVITY.md` |
| Team attack runbook | `docs/engineering/P3_TEAM_ATTACK_RUNBOOK.md` |
| Promotion review | `docs/engineering/AUTO_PROMOTION_REVIEW.md` |
| Work logs | `docs/engineering/WORK_LOG_2026-10-27_28.md`, `WORK_LOG_2026-10-28_P6.md` |
| Demo and operation | `docs/FINAL_DEMO.md`, `docs/OPERATOR_GUIDE.md`, `docs/MCP_GUIDE.md`, `docs/DEPLOYMENT.md` |
| Evidence | `artifacts/evidence/` (per milestone and date) |
