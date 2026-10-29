# AI-Adaptive-Firewall: complete project report

**As of 2026-10-29 ~13:05Z, branch `engineering-directive`.** This is the one document that covers everything. It replaces the earlier
version of this file (~02:15Z) and `PROJECT_REPORT_2026-10-28.md`.

It covers:
- what the project is and how it works (§1);
- the status at a glance (§2);
- everything that was done, in order, including today (§3);
- every predeclared experiment and its result (§4);
- the defects found and fixed (§5);
- what works and what does not (§6);
- the limitations (§7);
- the **dashboard status** (§8);
- the **current deployed state** (§9);
- **what is missing to finish fully**, step by step (§10);
- future work beyond the degree (§11);
- where everything is (§12).

**The project is not complete, and nothing here says otherwise.** Where a result does not
exist, this report says so. Every number has an evidence file under
`artifacts/evidence/`.

---

## 1. What the project is

An adaptive firewall controller that protects a web application. It runs on a real GNS3
lab with 8 VMs, 6 zone switches and 2 host connectors (`GNS3_TOPOLOGY.md`).

| Node | Address | Role |
|---|---|---|
| FW01 | zone gateways (.1) | OPNsense: zone separation, dynamic block aliases, Suricata IDS, network metadata, pf block log |
| WAF01 | 10.77.30.10 (DMZ) | Reverse proxy / WAF in front of the application |
| APP01 | 10.77.40.10 (APP) | The protected application (car rental) |
| DB01 | 10.77.60.10 (DB) | Its database |
| CTRL01 | 10.77.50.10 (MGMT) | The controller: telemetry intake, features, ML, correlation, policy, enforcement, API, dashboard |
| USR01 | 10.77.20.0/24 (USERS) | Legitimate-user traffic (scripted personas) |
| ATK01 | 10.77.10.10 (ATTACK) | Attack zone, used only by the team for authorized attack runs |
| DESK01 | — | Operator desktop |

### How it works

1. **Collection.** Sensors send telemetry to CTRL01 over mTLS:
   - WAF and application logs (RELP);
   - Suricata alerts and network metadata (flow, DNS, TLS, SSH) from FW01;
   - since today, pf block log lines from FW01.
2. **Web behaviour windows.** Per-source 30-second windows built from web requests.
3. **Anomaly scoring.** Robust statistics and Isolation Forest are enforcing;
   Half-Space-Trees runs in shadow.
4. **Evidence score.** The anomaly score is combined with independent evidence
   categories (AUTH, WAF, IDS, HISTORY) into a capped evidence score.
   - Independence is decided counterfactually (ADR-039).
   - A block needs at least 2 independent categories.
5. **Action.**
   - Each proposed action has a response state (ADR-043).
   - It is checked against safety rules.
   - It is applied on OPNsense or the WAF and read back to verify it.
   - It expires automatically.
   - Addresses shared by several accounts are never auto-blocked.
6. **Login controls (A3, ADR-044).** Per-account AUTH evidence with graduated,
   login-only controls: throttle, then deny the login endpoint, never the site. These are
   deployed in monitor mode.
7. **Network novelty (shadow, ADR-042).**
   - It scores per-source network activity outside normal web use, with calibrated
     levels and fixed protocol ceilings.
   - It is validated for benign false-alarm rate only (NV2) and is never used for
     decisions.
8. **Server lateral-movement evidence (shadow, today).** pf blocks of connections that
   protected servers try towards forbidden zones are shown in `/api/network`.
9. **Governed learning.**
   - The shadow challenger learns only from eligible benign traffic.
   - A gate and a human decide promotion; probation follows, with automatic rollback.
   - An incremental supervised classifier (river ARF/HAT) exists with its own lifecycle,
     but is not wired live.

**Stack:**
- Python with a hexagonal architecture: Pydantic, SQLAlchemy Core with SQLite, Alembic.
- A typer CLI (`afw`) and Ansible deployment.
- An HTTPS API with role tokens, a dashboard, and an MCP interface (no shell, no
  promotion tool).
- No Kafka, Kubernetes, deep learning or LLMs inside the firewall.

**Quality checks (2026-10-29 ~10:10Z, current code):**
- ruff and format clean (151 files);
- mypy strict clean (111 files);
- **376 tests passed, 14 skipped**. The 14 need the live lab and pass there: **14/14,
  finished 10:24Z**.
- Isolation: **41/41** (`afw lab verify`, 10:19–10:21Z).

---

## 2. Status at a glance

### 2.1 Engineering-directive gates

| Gate | Status | Why |
|---|---|---|
| A Infrastructure | **MET** | Reproducible lab; isolation 41/41; idempotent deploy; cold restart recovers with no manual step |
| B Detection | **NOT MET** | No labelled attack runs exist, so recall and false negatives cannot be measured (blocked on the team) |
| C Genuine adaptation | **PARTIAL** | Live learning, pivots and exact restore observed. No challenger has passed the gate; nothing promoted |
| D Enforcement | **MET** | Real OPNsense and WAF actions, read-back verification, expiry, protected-address refusal, shared-address guard |
| E Independent value | **NOT MET** | Needs attack runs |
| F Security and operations | **MET** | HTTPS API, all telemetry over mTLS, audited MCP, tested recovery, log rotation |
| G Academic defensibility | **PARTIAL** | Methodology and honest negative results are documented. The team demonstration and the attack-side evidence are missing |

### 2.2 Master-directive items (2026-10-29)

| # | Item | Status |
|---|---|---|
| 1 | Resolve the AUTH conflict (A3, then A4) | **Done, positive under A4.** A3's candidate S failed its final (F1) on legitimate households. **A4** (predeclared) makes `distinct_usernames` ceiling-only and measures FPR on household/shared sets; on fresh unseen data with household coverage, S **passed** selection and the one-shot final (security FPR 0.0112 [0,0.034], 0.0 on households/shared, 0/2 791 logins refused, SYNTHETIC sensitivity 1.0). Not promoted; monitor mode. No real attack-detection claim |
| 2 | Make network novelty meaningful | **Benign side done.** NV1 failed; NV2 (new protocol, fresh unseen users) **passed**: 0.59 % [0.16, 1.15] unfamiliar, 0 strong. Segment visibility documented. Sensor expansion assessed (Suricata on DMZ/APP/DB **not enabled**, reasons recorded). pf lateral-movement evidence added in shadow. **Attack recall unmeasured (team)** |
| 3 | Supervised learning (RF baseline + incremental ARF/HAT, governed) | **Code + tests**; SYNTHETIC benchmark only (incremental not clearly better than periodic RF refit). Never enforcing; not wired live. Real labelled data needed (team) |
| 4 | New-threat experiment (withheld family) | Protocol predeclared (`content_discovery` withheld); **run blocked on the team** |
| 5 | Real attack evidence, team procedure, five-way evaluation | Procedure **done** (web and network scenarios, incl. `net-ssh-guessing`, `net-slow-scan`); **runs blocked on the team**; no attack measurement invented |
| 6 | Production quality | Monitor mode kept. Telemetry latency 0.5–2.0 s. WAF/APP log rotation deployed. Integrity, poisoning, shared-address and recovery mechanisms in place (§6.1). Infrastructure and backups preserved |
| 7 | Evidence for every claim; status files updated | Done after every milestone (`PROJECT_STATUS.md`, `VALIDATION_MATRIX.md`, `AUTONOMOUS_PROGRESS.md`, `RESULTS.md`) |

### 2.3 Master-directive gates (network-wide self-learning)

| Gate | Status | Why |
|---|---|---|
| Network visibility | **PARTIAL** | Flow/DNS/TLS/SSH metadata from the ATTACK and USERS segments. pf blocks of protected servers are visible (shadow). DMZ/APP/DB traffic that pf allows, and intra-segment traffic, are invisible. No attack traffic observed yet |
| Known-threat learning | **BLOCKED (team)** | RF and incremental classifiers written and tested on SYNTHETIC data only |
| Novelty | **MET for benign FP (this population) / BLOCKED (team) for recall** | NV2 passed its one-shot test; detection untested |
| Self-learning (§8 new-threat experiment) | **NOT MET** | Protocol and offline machinery ready, never run |
| Safe adaptation | **PARTIAL** | Web-path learning governed with poisoning defences; nothing promoted |
| Enforcement and response states | **MET** | Deployed; the shared-address guard has not triggered live |
| Recovery | **MET** | Cold restart of the whole lab, exact learner restore |
| Independent value (five-way comparison) | **NOT MET** | Needs attack runs |
| Academic readiness | **PARTIAL** | As gate G |

**In one sentence:** the engineering works and is well tested:
- infrastructure, telemetry and enforcement;
- safety, governance and recovery;
- the benign false-alarm rate of the network detector.

The central AI claim is **not demonstrated**: that the system detects real attacks
better than static rules and learns new ones safely. That data can only come from
team-run attacks. Model selection has now three times (P6, P7, A3) found no candidate
that meets every predeclared rule.

---

## 3. What was done, in order

### 3.1 Before 2026-10-27: the base system

- Lab build, zone isolation and deployment.
- WAF/application telemetry and the first detectors (robust statistics, Isolation
  Forest).
- Evidence correlation, enforcement on OPNsense and the WAF, the dashboard and the MCP.
- Real benign baseline, soak test and cold-restart test (evidence 2026-10-17 to 10-22).

### 3.2 Milestones M0–M9 (2026-10-27)

| M | What | Outcome |
|---|---|---|
| M0 | Audit, baseline tag, hygiene | Tag `baseline-2026-10-27`; audit in `docs/audit/` |
| M1 | Provenance-aware corroboration (ADR-027) | Done; later found flawed (SV-1) and fixed by ADR-039 |
| M2 | Online shadow learning, eligibility, mTLS provenance | Live learning on CTRL01. **Bug found and fixed:** leaking per-source rate cap |
| M3 | Champion/challenger gate, promotion, probation, rollback | 20 lifecycle tests, mutation-checked; the live gate correctly refuses |
| M4 | Adaptation experiments on real drift | **Poisoning flaw found and fixed:** 140/180 poison windows learned before, 0/180 after |
| M5 | Telemetry v2, IDS-only view, sensor liveness | **Two live defects fixed:** a silent ~55-minute stall after restart; heartbeat JSON mangled by systemd |
| M6 | Attack-evaluation harness | Scenario registry, journal, kill switch, watchdog, run-level CIs |
| M7 | Real GeoIP (DB-IP Lite) | Lookup and preview with integrity and freshness checks |
| M8 | Dashboard panels | Rendered live with no console errors |
| M9 | Documentation consolidation | 13 deliverables, validation matrix, status page |

### 3.3 Priorities P1–P5 (2026-10-28 morning)

| P | What | Outcome |
|---|---|---|
| P1 | Benign generalization | **Negative.** The v2 champion restricts 13 of 16 unseen legitimate users in replay. v3 fixes that but fails sensitivity; not promoted. A false "six new users" claim was found and corrected |
| P2 | Sensitive invariance | Cause: threshold recalibration. The gate was rebuilt on matched windows (ADR-034); it catches 6/6 desensitization mutants |
| P3 | Independent attack evaluation | **Blocked on the team**; runbook ready |
| P4 | Real online adaptation | Governed loop shown live; no promotion |
| P5 | Hardening | IDS feed over mTLS (ADR-035); HTTPS API; directional real-country enforcement (ADR-036); IDS heartbeat (ADR-037); RELP (ADR-038), with dead-session loss going from 105/150 to 0/150 |

### 3.4 Directive 10-28 (2026-10-28 afternoon)

- **SV-1 (ADR-039).** Counterfactual residuals replace occlusion. False independence
  went from up to 76 % to 0. Pure brute force now gets a strict rate limit, not a block.
- **Crash-consistent promotion and rollback (ADR-040).**
- **IDS engine liveness (ADR-041).** A frozen Suricata shows as stale in about 150 s.
- **RELP crash test.** 3 SIGKILLs lost 0 of 6 851 requests.
- **Attack-run preparation.**
  - `afw dataset validate`.
  - The four-way comparison harness, with IDS alerts now stored with datasets.
  - An automatic-promotion review (not enabled).
- **P6 generalization study** (§4.1).

### 3.5 Completion and master directive (2026-10-28 evening)

- P6 finished as predeclared; P7 (amendment A2) run on clean data (§4.1).
- **N1** FW01 Suricata exports flow/DNS/TLS/SSH metadata as versioned `NetworkEvent`s.
- **N2** Per-source 60 s / 300 s residual network features and a novelty detector in
  shadow; `/api/network`.
- **N3/N4** A supervised known-threat classifier:
  - a RandomForest with abstention;
  - run-grouped splits;
  - families can be withheld;
  - synthetic data is refused unless explicitly allowed.
- **N6** Response states and the shared-address guard (ADR-043).
- **N7** The §8 new-threat protocol and offline core; a whole-lab cold restart; a hashed
  dataset archive.
- `TEAM_ATTACK_QUICKSTART.md`.

### 3.6 Master directive of 2026-10-29 (today)

All of the following was autonomous work under the directive. Every experiment was
predeclared before its data.

| Time (Z) | Work | Commits |
|---|---|---|
| ~00:00–02:15 | WAF01/APP01 heartbeat outage at log rotation found and fixed (defect 23) | — |
| early | A3 and NV1 protocols committed **before** data. A3 implementation: account-aware AUTH tracker, AUTH-only view, LOGIN_CONTROL ladder (throttle → deny login endpoint); SYNTHETIC attack-resistance simulator; NV1 driver | `7eaa8d4`, `aa7ef1c`, `ecf2ec8`, `1b04900` |
| early | Item 3: incremental supervised classifier (river ARF/HAT) with verified delayed labels, predict-before-learn, LabelGuard, rehearsal, checkpoints and lifecycle; SYNTHETIC benchmark | `e16ca31` |
| early | Team procedure extended: network scenarios (`net-portscan`, `net-ssh-guessing`, `net-slow-scan`); predeclared withheld family (`content_discovery`) | `5a17521` |
| early | WAF/APP log rotation (copytruncate, daily, 200 MB max, 30 kept) and imfile `reopenOnTruncate`, deployed | `2d748ea` |
| 03:11–04:13 | A3/NV1 capture: a3-sel 17 503 obs, a3-sel-shift 4 179, nv1-train 51 497, nv1-val 23 030; all validation PASS, counts equal the WAF log | `a7d10e7` |
| — | FW01 load baseline (read-only): 2 vCPU, 95–97 % idle, Suricata 330 MB RSS | `aa1192f`, `6b9d286` |
| ~05:30 | NV1 freeze and one-shot test: **FAIL** (§4.3). Display defect fixed | `abd0366`, `ea584fd` |
| ~05:30 | A3 selection, run once: **S selected** (§4.2); frozen | `39b0c3b` |
| 05:33 | A3 controls deployed live in monitor mode; live lab 14/14, isolation 41/41; live login check 0 refused of 121; telemetry latency 0.5–2.0 s measured | `1261aa0`, `8b913ec` |
| 05:42–06:29 | Phase E capture: p6-final 19 400, -shift 2 944, -v1 1 670; 48 checks PASS | `b56286d`, `58d7ad1` |
| ~06:35 | A3 final, run once: **FAIL on F1** (§4.2) | `e42759a` |
| ~07:20 | NV2 protocol committed before data: `sweep_hosts` ceiling, stratified heavy users, new seeds. ADR-042 revised. NV1 post-hoc destination diagnosis | `e9ca05f` |
| ~07:30 | NV2 code deployed (shadow placeholder calibration) | `73fd1de` |
| 07:32–08:35 | NV2 capture: nv2-train 86 034 obs (32 users), nv2-val 12 527, nv2-test 30 904, nv2-test-shift 4 075; all validation PASS, counts equal the WAF log | `bfe8ce9` |
| ~08:45 | NV2 freeze (`c311aeeb…`) and one-shot test: **PASS** (§4.3) | `c7aee42`, `e304425` |
| ~08:50 | NV2 calibration installed live (shadow), identical to the frozen file; local gates 370 passed | `2628420` |
| ~10:08 | Sensor expansion assessed (read-only FW01 checks): Suricata on DMZ/APP/DB **not enabled** (§6.2, `SENSOR_EXPANSION_DECISION.md`) | `b12ae12` |
| ~10:15 | pf block evidence for protected sources: parser, runtime, API, FW01 feed `suricata,filterlog`; deployed; verify 41/41 with all 10 server deny checks seen; lab tests 14/14 | `f16798a`, `48b3946`, `f83c472` |
| ~10:32 | Dashboard rendered live and checked (§8) | this report |

---

## 4. Predeclared experiments and their results

All protocols were committed **before** the data they judge, and each test set was used
once.

### 4.1 P6 and P7: model selection for generalization without sensitivity loss

- **Candidates.**
  - References: R2 and R3, the current v2 and v3 models.
  - New: D (more data), F (Wilson fractions), C (cohort thresholds), S (D plus a
    security path), FS (F plus the security path).
- **Eligibility.**
  - Window FPR ≤ 0.02, with upper CI ≤ 0.05.
  - No new legitimate user restricted.
  - Must-detect sensitivity, nominal and stressed. It is measured on SYNTHETIC
    feature-level cases, which contain no traffic and are never called attack detection.

**P6: no eligible candidate.** Two causes:
- behaviour-only rate limits;
- a generator/app mismatch: `/reviews` returned 404.

**P7 (amendment A2, clean data):** 74 510 + 24 705 training/calibration observations
from 40 users; 13 173 + 3 033 selection observations from 22 new users.

| Candidate | Worst window FPR | Users restricted (sel / shift) | Must-detect min (nominal / stressed) |
|---|---|---|---|
| R2 (v2) | 0.843 | 1/16, 0/6 | 1.00 / 0.79 |
| R3 (v3) | 0.456 | 1/16, 0/6 | 1.00 / 0.73 |
| D | 0.016 | 1/16, 0/6 | 0.81 / 0.49 |
| F | 0.009 | 1/16, 0/6 | 0.86 / 0.78 |
| C | 0.032 | 0/16, 0/6 | 0.82 / 0.52 |
| S | 0.016 | 1/16, 0/6 | 1.00 / 1.00 |
| FS | 0.009 | 1/16, 0/6 | 1.00 / 1.00 |

There was still no eligible candidate. The only restriction for D, F, S and FS was one
rate limit on one "forgetful" persona, caused by the AUTH brute-force rule and not by
ML. This conflict led to A3.

### 4.2 A3 → A4: AUTH conflict, account-aware evidence, household-robust security path

**Design (ADR-044, `engineering/A3_AUTH_CONTROLS.md`).**
- AUTH evidence is counted per account and per source.
- Controls are graduated and limited to the login endpoint: throttle, then deny login.
  They never block the site.
- Criteria: B1–B4 at selection and F1–F5 at the final stage, plus SYNTHETIC attack
  resistance (AR1–AR4).

**Selection (run once on a3-sel / a3-sel-shift): S eligible and selected.**
- B1 FPR ≤ 0.0031.
- 0 of 1 837 legitimate logins refused; no site-wide restriction.
- SYNTHETIC attack resistance passed:
  - AR1: 25 guesses / 3 600 s;
  - AR2: 25 / 180 s;
  - AR3: 25 / 3 600 s;
  - AR4: 20 / 60 s.
- Friction k = 4, 6, 8: 0 refusals.
- Frozen as `cand-S.pkl`, sha256 `8994dfe8…`. A backup is kept outside Git.

**Final (run once on Phase E): FAIL on F1.**

| Criterion | Result |
|---|---|
| F1 window FPR (security path) | **0.0475 [0, 0.14]: fail.** All flagged windows came from legitimate multi-account ("household") users, who were absent from a3-sel. `distinct_usernames` was calibrated at 1 |
| F2 login friction | **Pass:** 0 of 2 418 legitimate logins refused, no restriction |
| F3–F5, A3c5 | Pass |
| Shift sets (reported, not criteria) | S security path 0.176 and 0.135 |

S is **not promoted**. Phase E is consumed.

**A4 (predeclared, run this session).** Diagnosis on the consumed Phase E data showed
287 of 293 household flags were the `distinct_usernames` quantity, calibrated at 1. A4
makes that quantity **ceiling-only** (fires at ≥ 5 accounts) and makes benign FPR a
criterion on household and shared sets. On fresh unseen data (disjoint from training;
an initial address/seed collision with the training sets was caught at validation and
re-captured), candidate S **passed** selection and the one-shot final:

| A4 final set | S security-path FPR |
|---|---|
| `a4-final` (natural) | 0.0112 [0, 0.0343] |
| `a4-final-hh` (households) | 0.0 |
| `a4-final-shift` (shared) | 0.0 |

0 of 2 791 legitimate logins refused; SYNTHETIC must-detect sensitivity 1.0 (nominal and
stressed). The A3 household failure is resolved. Still SYNTHETIC on the attack side, and
not promoted (monitor mode). Details: `engineering/A4_AUTH_HOUSEHOLD_REVALIDATION.md` §8.

### 4.3 NV1 and NV2: network novelty on ordinary (non-web) network use

**Generator.** Benign personas now also produce ordinary network use:
- DNS through public resolvers, with a few NXDOMAIN lookups;
- HTTPS visits;
- NTP and ping to the gateway;
- occasional typed `http://` attempts.

Each user has a light, normal or heavy habit.

| | NV1 | NV2 |
|---|---|---|
| Training | 24 users (3 heavy) | 32 users (13 heavy: 5 natural + 8 stratified) |
| Host-sweep ceiling | `dst_hosts_60` = 10 (every destination) | `sweep_hosts_60` = 10 (internal or unanswered destinations only) |
| Dev (val users) | 0.0102 | 0.0145 [0, 0.0406] |
| **One-shot test (22 unseen users)** | **0.0678 [0.0088, 0.1575], 1 user strong: FAIL** | **0.0059 [0.0016, 0.0115], 0 strong: PASS** |
| Frozen calibration | `90a1793b…` | `c311aeeb…` |

**NV1 diagnosis (post hoc, no re-test):**
- Heavy users were under-covered in calibration.
- One heavy user reached 11 *answered* CDN hosts in 60 s, which met the old ceiling.

**NV2 changes, both predeclared:** coverage of heavy users, and a ceiling that counts
only internal or unanswered destinations.

**What the NV2 pass allows:** for this lab population, the detector has learned normal
network use, with a false-unfamiliar rate of 0.6 %. Limits:
- **The ceiling change was not exercised.** The old ceiling would also have fired on
  0 test windows.
- **One generator-modelled population.** A validation heavy user just above the
  trained DNS range gave 14 % unfamiliar windows.
- **No detection claim.** Detection needs the team's network runs.
- **Disclosure.** The test users' habit parameters (not detector output) were printed
  once during development. Nothing was changed after that (NV2 §7.2).

### 4.4 Item 3: incremental supervised classifier (SYNTHETIC only)

River ARF/HAT, with:
- verified delayed labels;
- predict-before-learn;
- LabelGuard, rehearsal and checkpoints;
- a gate → approval → probation → rollback lifecycle; it is never enforcing.

On a SYNTHETIC benchmark it was **not clearly better** than periodic RF refits. This is
a mechanics check, not a detection result.

---

## 5. Defects found and fixed (complete list)

Every item was demonstrated before it was fixed.

| # | Defect | Fix | Where |
|---|---|---|---|
| 1 | Per-source learning rate cap leaked | Cap enforced; 3/3 mutants caught | M2 |
| 2 | Poisoning through driver-name corroboration (140/180 learned) | Corroboration redesigned (0/180) | M4 |
| 3 | Telemetry silently stalled ~55 min after restart | Reconnect fixed | M5 |
| 4 | Heartbeat JSON mangled by systemd quoting | Quoting fixed | M5 |
| 5 | TCP syslog lost lines in dead sessions (105/150) | RELP (0/150) | ADR-038 |
| 6 | Country-enforcement read-back wrong live | Read-back fixed | ADR-036 |
| 7 | "Six new users" claim false | Corrected | P1 |
| 8 | Evidence independence up to 76 % wrong | Counterfactual residuals | ADR-039 |
| 9 | Legacy vectors could count as independent | Never independent | ADR-039 |
| 10 | Interrupted switches left no model or profile | Single transactions | ADR-040 |
| 11 | Failed automatic rollback raised every tick | Fail closed, audited | ADR-040 |
| 12 | Corrupt active model crashed the controller | Runs without ML, degraded | ADR-040 |
| 13 | Switch to a corrupt version succeeded | Verified before switching | ADR-040 |
| 14 | Frozen Suricata looked alive | Engine-liveness heartbeat | ADR-041 |
| 15 | Evaluations replayed without IDS alerts | Alerts stored with datasets | 10-28 item 6 |
| 16 | v1 generator: every booking 422, `/reviews` 404 | v2 generator | P6/A2 |
| 17 | Selection driver read a missing key | Fixed | P6 |
| 18 | FW01 IDS failed to start for 1¾ min (second anomaly logger) | Include fixed; provisioning checks for a new Suricata PID, else rolls back | N1 |
| 19 | Management SSH assessed as a network source | Protected sources stored, never assessed | N1 |
| 20 | Network score 4.5 × 10⁹ when the calibrated level was 0 | Denominator floored | N2 |
| 21 | `afw lab stop` timed out after 2 of 8 nodes | Per-node timeout handling | N7 |
| 22 | Team docs referenced uncollected datasets | Corrected | report |
| 23 | WAF01/APP01 heartbeats stopped at the first midnight log rotation (~2 h 10 min, correctly reported as degraded) | copytruncate + `reopenOnTruncate` | `sensor_tls` |
| 24 | DNS answers stored under the resolver: resolvers scored as sources, NXDOMAIN never counted | Answers oriented to the client (schema 2) | `f1b352a` |
| 25 | Network reason text printed the effective level as "ceiling" | Prints the ceiling; regression test | `ea584fd` |
| 26 | Host-sweep ceiling counted answered internet (CDN) hosts, so heavy browsing looked like a sweep | `sweep_hosts`: internal or unanswered destinations only (NV2, predeclared) | `e9ca05f` |

---

## 6. What works, and what does not

### 6.1 Works, with evidence

- **Infrastructure:**
  - reproducible deploy;
  - isolation 41/41 (today 10:21Z);
  - live lab tests 14/14 (today, finished 10:24Z);
  - cold restart of the whole lab recovers with no manual step.
- **Telemetry:**
  - WAF, application and IDS over mTLS, RELP for WAF/APP, zero loss in controlled kills;
  - heartbeats for all three sensors, fresh at 10:32Z;
  - captured datasets equal the WAF log exactly (A3, Phase E and NV2 captures today);
  - latency from request to controller 0.5–2.0 s;
  - WAF/APP logs rotated without losing heartbeats.
- **Network metadata (N1):**
  - about 1 600 events a minute with 36 users, 0 drops;
  - with 66 users today, all NV2 datasets were captured and validated.
- **Network novelty (N2):** NV2 passed its one-shot benign test. Live in shadow with the
  validated calibration.
- **pf lateral-movement evidence:**
  - every server-originated forbidden connection in `afw lab verify` appears in
    `/api/network` with its zone;
  - client blocks are only counted;
  - no policy is created.
- **Enforcement:**
  - OPNsense alias blocks, WAF deny and rate limits, each verified before being marked
    `enforced`;
  - expiry;
  - protected addresses always refused;
  - FW01 flushes dynamic blocks if the controller dies.
- **Login controls (A3):** 0 of 4 255 legitimate logins refused across 5 unseen sets,
  with no site-wide restriction.
- **Safety logic:**
  - an anomaly alone never blocks;
  - IDS-only evidence stays at WATCH or below;
  - stale sensors pause automatic enforcement;
  - response states are recorded;
  - shared addresses are never auto-blocked.
- **Governance:**
  - frozen trusted model;
  - gate plus human promotion;
  - probation with automatic rollback;
  - crash-consistent switches.
- **Online learning:** live, with poisoning controls, pivots and exact restore.
- **Evaluation machinery:**
  - predeclared protocols and one-shot tests with frozen hashes;
  - dataset validation and leakage checks;
  - run-level CIs;
  - four-way and supervised experiment CLIs;
  - hashed dataset archive.
- **Operations:** HTTPS API, an audited MCP, and a dashboard with no console errors
  (§8).

### 6.2 Does not work, or is unproven

1. **Real attack detection is unproven.** There are no labelled attack runs, so recall,
   false negatives and value over static rules are unknown. This applies to the web
   path, the network path, pf evidence and both classifiers. **This is the biggest gap.**
2. **The live champion (v2) has too many false positives for enforce mode.** Its window
   FPR is 0.84 on P7 users; it restricts 13/16 new users on P1 data. It is fine for
   monitor mode only.
3. **No replacement model qualified.**
   - P6: no eligible candidate.
   - P7: no eligible candidate (the AUTH conflict).
   - A3: S failed F1 (households).
4. **No promotion has ever happened live.**
5. **The A3 ML security path does not generalize to multi-account users.** The login
   controls themselves are fine.
6. **Network novelty is validated for benign false alarms only, on one modelled
   population.** Its ceiling change was not exercised by the test.
7. **Suricata server-segment inspection is not enabled, by decision.**
   - Server sources are never assessed, so it would add no verdicts.
   - FW01 keys flows without the interface (`livedev.use-for-tracking: false`), so
     client→WAF01 traffic would be captured twice. That would either disturb stream
     reassembly on the main path or double-count client failures under the NV2
     calibration.
   - Cost was not the reason.
8. **The supervised classifiers and the §8 experiment are unevaluated** (SYNTHETIC
   only), and the classifiers have **no live path**.
9. **Online learning cannot fix the champion's own false positives.** Policed sources
   are tainted by design; operator false-positive feedback is the governed route.
10. **The shared-address guard has never triggered live.** It is unit-tested only.

---

## 7. Limitations

**Visibility**
- Suricata listens on ATTACK and USERS only.
  - Allowed traffic inside DMZ/APP/DB/MGMT (WAF01→APP01, APP01→DB01) is invisible, as is
    traffic inside one segment.
  - Server attempts that pf *blocks* are now visible as pf evidence.
  - Attempts pf *allows* (for example APP01 to the Internet) are not.
- TLS is opaque beyond SNI and version.
- A closed TCP flow reaches the controller about 70 s after it starts. The window
  lateness is 75 s.
- pf evidence is kept in a bounded in-memory list (500) and the controller journal.
  It is not stored in datasets.
- Verification runs are not marked, so their blocks look like any other.

**Detection**
- Low-and-slow and distributed web attacks fall below the per-window minimum (3 requests
  per 30 s).
- Scores are evidence scores, not probabilities.
- Isolation Forest costs about 11.9 ms per row, against about 63 µs for the statistical
  arm.

**Learning**
- Four or more colluding, tenured, similar sources can vouch for each other.
- Network calibration can only lower a threshold below its ceiling. Poisoned benign data
  cannot hide a scan, but it can make "unfamiliar" over-sensitive.
- The NV2 calibration covers the habit range the generator models (heavy DNS up to about
  5.2 lookups/min in training). Real users beyond it will look unfamiliar.

**Telemetry**
- FW01's feed (IDS and pf) cannot use RELP (an OPNsense limitation), so it keeps a loss
  window of about 100 s.
- RELP acknowledges on queueing, so a crash can lose sub-second, unprocessed lines.
- The IDS heartbeat proves the engine loop runs, not that every packet is inspected.

**Response**
- An attacker with several compromised accounts behind one address looks "shared". The
  guard downgrades the action to a strict rate limit plus human review. This is
  intended.

**Data and method**
- Legitimate users are scripted personas, not real people.
  - Generated users never come near the AUTH thresholds (at most 3 failures on one
    account).
  - Friction for real users who fail 5 or more times is shown only by SYNTHETIC
    friction runs.
- Each selection or final dataset can be used once. P7 selection, a3-sel and Phase E
  are consumed.

**Environment**
- **Single host:** about 7 GB of a 16 GB machine; scale untested.
- **Lab PKI:** self-signed.
- **Network:** not air-gapped.
- **Country blocking:** real-country inbound blocks can be verified only by read-back.
- **Host restarts:** an unattended host upgrade once restarted `gns3server`. Recommended
  (not made): exclude it from needrestart.
- **Dataset storage:** datasets live on CTRL01 and in the host archive, not in Git. Only
  hashes are in Git.

---

## 8. Dashboard status (rendered live 2026-10-29 10:32Z)

The dashboard was rendered with headless Chromium and the viewer token, against the
live controller (`https://10.77.50.10:8080/`).
- Screenshot: `artifacts/evidence/dashboard-2026-10-29/dashboard-live-1032Z.png`.
- Script: `render_dashboard.py` in the same folder.

**Health:**
- **0 console errors, 0 failed HTTP requests.**
- Header: mode **monitor**, strategy ml, **telemetry healthy**.

**Top tiles:**

| Tile | Value |
|---|---|
| Operating mode | monitor |
| Trusted profile | v2 (361 windows, 6 sources, `b4a83e64fc22`) |
| ML model | `isolation_forest-p2`, threshold 0.627 |
| Live sources | 0 (no traffic running) |
| Active policies | 0, 0 pending approval |
| Controller RSS | 283 MB; host available 1 472 MB; tick p50 0.1 ms |

**Panels (14), all rendering with data:**

| Panel | What it shows now | Note |
|---|---|---|
| Highest risk per 5 s window | Risk timeline; one spike at ~10:24 from the lab test suite (10:22–10:24Z) | Thresholds drawn as dashed lines |
| Requests observed per window | Request timeline | — |
| Live sources | Empty (no sources in the last 2 min) | Expected with no traffic |
| Baseline vs current behavior | Per-source detail on selection | — |
| Adaptive policy decisions | 10:24 policies from the lab test suite (MCP geo/source blocks), all **rolled back** or **rejected** by the validator, with read-back verification shown | Shows that enforcement and rollback work |
| Decision explanation | Per-policy explanation on click | — |
| Controlled adaptation | Drift reports (new endpoint, feature shift), reputation-gate rejections | — |
| Models & profiles | v1 retired, **v2 trusted**, v3/v4 candidates; detector table with validation FPRs | v3/v4 show "gate passed" for the *validation-FPR* gate only. P1/P6/P7 later showed v3 fails sensitivity; this panel does not show that (see gaps) |
| Online learning (shadow challenger) | HST challenger, 607 learned windows, checkpoint 16; champion vs challenger agreement | Shadow only |
| Promotion gate & probation | Latest gate: **failed, not promotable** (no attack recall data; sensitive invariance fails); no probation, no promotions | Correct state |
| IDS-only sources | 10.77.10.10 (ATK01 verify probes): suricata alerts, score 12–24, **no action** | IDS-only stays observation |
| GeoIP | DB-IP Lite 2026-10, 362 122 ranges, fresh; real-country aliases empty | — |
| Static vs statistical vs ML experiments | Older replay rows (real benign) and `synthetic-ui-demo` rows labelled **"NOT a lab result"** | Does not show P6/P7/A3/NV results (those are offline reports) |
| Telemetry health | Sensors app/ids/waf heartbeats 2–28 s old; counters incl. `net_*`, `pf_block_protected` 40, `pf_block_client` 66, `pf_other` 675, `relp_session` | pf and network counters are visible only here, as raw counters |
| Audit trail | Validator, reconciler and MCP actions | — |

**Dashboard gaps (what it does not show):**
1. **No network panel.** NV2 novelty verdicts, the calibration status ("validated for
   benign FP only") and the new `protected_blocked` pf evidence are only in
   `/api/network`, and as raw counters in Telemetry health.
2. **No A3 login-control view.** Per-account AUTH state and login throttles or denials
   are not visible on the dashboard.
3. **No response-state or shared-address view.** These are recorded on intents but not
   shown as their own panel.
4. **Misleading candidate status.** "Candidate v3/v4: gate passed" refers only to the
   validation-FPR gate. A viewer could read it as "qualified". It should show the P1/P6/P7
   outcome or a "not qualified" note.
5. **Experiment results are missing.** The P6/P7/A3/NV1/NV2 results are not on the
   dashboard; they are in `RESULTS.md` and the evidence files.

These are display gaps only; the underlying data and API exist. An agent can close them
without team input (§10, step 6).

---

## 9. Current deployed state (2026-10-29 ~10:40Z)

- **Controller (CTRL01).**
  - Code at `f16798a` or later.
  - **Monitor mode**; `behavior_only_rate_limit` on; strategy ml.
  - Trusted profile **v2**; model `isolation_forest-p2`.
  - No active policies.
- **A3 login controls.** Deployed, monitor mode.
- **Network novelty.**
  - Calibration: NV2, 3 680 emissions, live file identical to frozen `c311aeeb…`.
  - Mode: **shadow** ("not used for decisions"), no calibration error.
- **pf evidence.** Live in shadow; `protected_blocked` in `/api/network`.
- **FW01.**
  - Suricata 8.0.6, pcap on vtnet2 (ATTACK) and vtnet3 (USERS).
  - `afw-netflow.yaml` and `afw-liveness.yaml` included.
  - Syslog feed `suricata,filterlog` over mTLS to CTRL01:5514.
  - DMZ/APP/DB not inspected (by decision).
- **WAF01/APP01.** RELP over mTLS; daily copytruncate log rotation.
- **Telemetry.** All three heartbeats fresh; not degraded.
- **Data.**
  - Today's datasets on CTRL01: a3-sel, a3-sel-shift, nv1-train, nv1-val, p6-final,
    p6-final-shift, p6-final-v1, nv2-train, nv2-val, nv2-test, nv2-test-shift.
  - Older datasets are archived in `~/afw-datasets-archive/` with hashes.
  - The frozen A3 candidate is backed up at `~/.local/share/afw-frozen/`.
- **Git.**
  - **27 commits on `engineering-directive` are not pushed** (`origin` is at
    `7eaa8d4`), plus this report.
  - Push only when the owner asks.

---

## 10. What is missing to finish fully, and how

Do the steps in this order. Steps 1, 3, 4 and 7 need people; the agent can do the rest.
Commands are checked against the CLI; full detail is in `TEAM_ATTACK_QUICKSTART.md` and
`engineering/P3_TEAM_ATTACK_RUNBOOK.md`.

### Step 1: team attack runs (team; unblocks most of what is missing)

Before each run:
```bash
uv run afw lab status        # 8 VMs started
uv run afw lab verify        # 41/41
uv run afw scenario watchdog &
```

Each run:
1. Start 2 new benign background users on USR01 (10.77.20.200–.249, never reused).
2. `uv run afw scenario begin <scenario> <name> --notes "<tool, version, options>"`.
3. Run the tool from ATK01 against the allowed targets only.
4. `uv run afw scenario end <RUN_ID>`. In an emergency use `abort`, which powers ATK01
   off.
5. `uv run afw scenario manifest <RUN_ID> /tmp/<RUN_ID>.json --benign <ips>`, then copy
   the manifest to CTRL01.
6. On CTRL01:
   `afwc dataset capture <id> --manifest /tmp/<RUN_ID>.json --purpose test`, then
   `afwc dataset validate <id>`. Exit status 1 means the dataset must not be used.

What to run:
- **Web families:** `web-bruteforce-login`, `web-sqli-probe`, `web-content-discovery`.
  Each needs 3 test runs and 1 validation run, as separate sessions hours apart.
- **Network families:** `net-portscan`, `net-slow-scan`, `net-ssh-guessing`. Each needs
  3 test runs and 1 validation run.
- **Withheld family** for the §8 experiment: `content_discovery`, at least 2 independent
  runs.
- **Holdout:** `low-and-slow-bruteforce`, evaluated once at the very end.
- **New, recommended:** a **lateral-movement** scenario. From a server the team
  controls, attempt connections pf forbids, to measure the pf evidence. The scenario
  must be added to the registry first.

Report every begun run, including aborted ones.

### Step 2: evaluations (agent, after step 1)

- **Web comparison:** `afwc experiment evaluate --datasets <runs> --streaming --warmup
  p7-sel,p7-sel-shift`. It gives the static, frozen ML, streaming ML and hybrid arms,
  with recall, FPR and CIs.
- **Supervised known-threat:** `afwc experiment supervised --train <runs> --test <other
  runs>`. Run the RF baseline and the incremental ARF/HAT on the same splits.
- **§8 new-threat:** the same command with `--withhold content_discovery --introduce
  <first run>`.
- **Network recall:** run the frozen NV2 calibration on the network runs. The ceilings
  should mark scans `strong`; record what actually happens.
- **Five-way comparison:** static, supervised alone, novelty alone, frozen hybrid and
  adaptive hybrid.

This closes gates B and E and the known-threat, novelty-recall and independent-value
gates. A negative result is acceptable if it is reported honestly.

### Step 3: decide the AUTH model (owner), then re-run (agent)

A3's login controls work; its ML security path does not generalize to households. The
owner chooses one of:
- **(a) a new amendment A4.** It would have:
  - stratified archetype coverage, including households and shared addresses;
  - FPR measured on the shared sets as well;
  - a fixed `distinct_usernames` treatment;
  - new selection and final data (about 45 + 45 min of lab time).
- **(b)** keep the login controls and drop the ML security path for AUTH;
- **(c)** stop and report A3 as the final result.

The agent then runs the chosen protocol once.

### Step 4: one human-authorized promotion (owner approves, agent executes)

If a candidate passes, promote it through the gate and observe probation live. This
closes gate C. If none passes, report that; the lifecycle is already demonstrated in
shadow, restart and fault-injection tests.

### Step 5: network detector to decisions (owner; only after step 2)

Moving the novelty detector or pf evidence out of shadow needs:
- measured attack recall (step 2);
- a human decision.

NV1 §6.2 sets these conditions. Until then they stay in shadow.

### Step 6: agent work that needs no team input

- **Dashboard:**
  - a network panel (NV2 verdicts, calibration status, `protected_blocked`);
  - an A3 login-control view;
  - a response-state / shared-address view;
  - a "not qualified" status for the v3/v4 candidates (§8 gaps 1–4).
- **pf evidence:**
  - persist the blocks with datasets, so team runs capture them;
  - mark `afw lab verify` runs so their blocks are labelled.
- **Incremental classifier:** wire it live in shadow only, after real labelled data
  exists. It must never enforce until independently evaluated.
- **Server-segment Suricata:** only if all four conditions in
  `SENSOR_EXPANSION_DECISION.md` §4 are met.

### Step 7: documentation and demonstration (team)

- The agent updates `RESULTS.md`, `PROJECT_STATUS.md`, `VALIDATION_MATRIX.md` and this
  report with the step 1–5 results.
- The team runs `FINAL_DEMO.md` and can explain `ARCHITECTURE.md`,
  `ADAPTATION_DESIGN.md`, `RESULTS.md` §3 and this report without help. This closes
  gate G.
- Submit the dataset archive with its SHA-256 file, or say how to obtain it.
- The owner decides whether to push the 27+ local commits.

### Before submission, re-check

```bash
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy src
uv run pytest -o addopts="" -q                       # expect all pass (lab tests skipped)
AFW_LAB=1 uv run pytest -o addopts="" -q tests/lab   # expect 14/14 with the lab up
uv run afw lab verify                                # 41/41
git status                                           # clean
```

### What can be claimed at each point

| After | Can claim |
|---|---|
| **Now** | A working, governed, verified-enforcement system. Honest negative model-selection results (P6, P7, A3). Login controls with no measured friction. A network detector with a measured benign false-alarm rate (0.6 %) on this lab population. Partial network visibility plus server-block evidence |
| Steps 1–2 | Measured detection, with CIs, on real team-run attacks, and whether the AI adds value over static rules (either answer is valid) |
| Steps 3–4 | A model that generalizes to new users without losing sensitivity, if one qualifies |
| Never, in this lab | Perfect detection; full network visibility; production readiness |

---

## 11. Missing for "production ready" (future work, not required for the degree)

1. Detection validated on real users and real attacks over weeks.
2. A champion that passes both generalization and sensitivity, with continuous
   monitoring.
3. High availability: redundant controller, a server database, enforcement-state
   failover.
4. Real PKI and secrets management (vault or HSM, rotation, revocation).
5. Loss-free telemetry, acknowledged after persistence, including FW01's feed.
6. Sensors in every segment, with interface-aware flow tracking, and TLS-aware
   inspection where lawful.
7. Detectors for low-and-slow and distributed attacks.
8. A stronger defence against colluding poisoners.
9. Scale testing and firewall table limits.
10. Operational maturity: alerting, on-call, backup and restore drills, controller
    upgrade and rollback.
11. Independent security review and penetration test of the API, MCP and enforcement
    paths.
12. Privacy and legal review of telemetry retention and country blocking.
13. Automatic promotion stays off until the bounds in `AUTO_PROMOTION_REVIEW.md` are
    implemented and independently validated.

---

## 12. Where everything is

| Topic | File |
|---|---|
| Single status page | `docs/PROJECT_STATUS.md` |
| Per-criterion evidence | `docs/VALIDATION_MATRIX.md` |
| Milestone detail (M, P, N, A3, NV) | `docs/engineering/AUTONOMOUS_PROGRESS.md` |
| Decisions (ADR-001…044) | `docs/ARCHITECTURE_DECISIONS.md` |
| Results | `docs/RESULTS.md` (§3b P6, §3c P7, §3d A3, §3e NV1, §3f NV2) |
| P6/P7 protocol | `docs/engineering/P6_GENERALIZATION_AND_SENSITIVITY.md` |
| A3 protocol and results | `docs/engineering/A3_AUTH_CONTROLS.md` (§8) |
| NV1 / NV2 protocols and results | `docs/engineering/NV1_NETWORK_NOVELTY_VALIDATION.md`, `NV2_NETWORK_NOVELTY_REVALIDATION.md` (§7) |
| Sensor expansion and pf evidence | `docs/engineering/SENSOR_EXPANSION_DECISION.md` |
| New-threat experiment | `docs/NEW_THREAT_EXPERIMENT.md` |
| Team attack runs | `docs/TEAM_ATTACK_QUICKSTART.md`, `docs/engineering/P3_TEAM_ATTACK_RUNBOOK.md` |
| Limitations | `docs/SECURITY_AND_LIMITATIONS.md`, `docs/THREAT_MODEL.md` |
| Promotion review | `docs/engineering/AUTO_PROMOTION_REVIEW.md` |
| Demo and operation | `docs/FINAL_DEMO.md`, `docs/OPERATOR_GUIDE.md`, `docs/MCP_GUIDE.md`, `docs/DEPLOYMENT.md` |
| Evidence | `artifacts/evidence/`: `a3-2026-10-29/`, `nv1-2026-10-29/`, `nv2-2026-10-29/`, `sensor-expansion-2026-10-29/`, `dashboard-2026-10-29/`, `item3-2026-10-29/`, `p6-…`, `p7-…`, `n1-…`, `n7-…`, earlier milestones |
