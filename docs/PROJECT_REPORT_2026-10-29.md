# AI-Adaptive-Firewall: complete project report

**As of 2026-10-29, branch `engineering-directive`.** This report replaces
`PROJECT_REPORT_2026-10-28.md`, which was written before the P6/P7 results and the
network work (N1–N7) existed.

It puts in one place:
- what the project is;
- everything that was built, measured and fixed;
- what works and what does not;
- the limitations;
- what is missing, and the exact steps to get it ready for submission.

It summarises the detailed documents and does not replace them (map in §13).
**The project is not complete, and nothing here says otherwise.** Where a result does not
exist, this report says so.

---

## 1. What the project is

An adaptive firewall controller that protects a web application. It runs on a real GNS3
lab with 8 VMs, 6 zone switches and 2 host connectors (`GNS3_TOPOLOGY.md`).

| Node | Address | Role |
|---|---|---|
| FW01 | zone gateways | OPNsense: zone separation, dynamic block aliases, Suricata IDS, network metadata (new) |
| WAF01 | 10.77.30.10 | Reverse proxy / WAF in front of the application |
| APP01, DB01 | APP and DB zones | The protected application (car rental) and its database |
| CTRL01 | 10.77.50.10 | The controller: telemetry intake, features, ML, correlation, policy, enforcement, API, dashboard |
| USR01 | 10.77.20.0/24 | Legitimate-user traffic (scripted personas) |
| ATK01 | 10.77.10.10 | Attack zone, used only by the team for authorized attack runs |

### How it works

1. **Collection.** Sensors send telemetry to CTRL01 over mTLS:
   - WAF and application logs, over RELP;
   - Suricata alerts from FW01;
   - since 2026-10-28, Suricata flow, DNS, TLS and SSH metadata from FW01.
2. **Web behaviour windows.** The controller builds 30-second behaviour windows per
   source from web requests.
3. **Anomaly scoring.** Detectors score each window:
   - robust statistics and Isolation Forest enforce;
   - Half-Space-Trees runs in shadow.
4. **Evidence score.** The anomaly score is combined with independent evidence categories
   (AUTH, WAF, IDS, HISTORY) into a capped evidence score.
   - Independence is decided counterfactually (ADR-039).
   - A block needs at least 2 independent categories.
5. **Action.**
   - Each proposed action gets a response state, from normal to high risk (ADR-043).
   - The action is checked against safety rules.
   - It is applied on OPNsense or the WAF, then read back to verify it.
   - It expires automatically.
6. **Network novelty (shadow).** A separate network novelty detector scores per-source
   network activity outside normal web use (ADR-042). Its verdicts are recorded only and
   never used for decisions.
7. **Governed learning.**
   - A shadow challenger learns only from eligible benign traffic.
   - A gate compares it with the champion, and a human promotes it.
   - Probation follows, with automatic rollback.

**Stack:**
- Python with a hexagonal architecture, Pydantic, SQLAlchemy Core with SQLite, and
  Alembic.
- A typer CLI (`afw`) and Ansible deployment.
- An HTTPS API with role tokens, a dashboard and an MCP interface.
- No Kafka, Kubernetes, deep learning or LLMs inside the firewall.

**Quality checks (2026-10-28 20:05Z, current code):**
- ruff and format clean (146 files);
- mypy strict clean (108 files);
- **324 tests passed, 14 skipped**: the 14 need the live lab and pass there (14/14).

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
| F Security and operations | **MET** | HTTPS API, all telemetry over mTLS, audited MCP, tested recovery |
| G Academic defensibility | **PARTIAL** | Methodology and honest negative results are documented. The team demonstration and the attack-side evidence are missing |

### 2.2 Master-directive gates (network-wide self-learning)

| Gate | Status | Why |
|---|---|---|
| Network visibility | **PARTIAL** | Flow/DNS/TLS/SSH metadata live from the ATTACK and USERS segments. DMZ/APP/DB/MGMT and intra-segment traffic are invisible. No attack traffic observed on this path yet |
| Known-threat learning | **BLOCKED (team)** | Classifier written and tested on synthetic values only |
| Novelty | **BLOCKED (team) / PARTIAL** | Network novelty runs in shadow; its calibration is degenerate (§6.2) |
| Self-learning (§8 new-threat experiment) | **NOT MET** | Protocol and offline machinery ready, never run. The classifier has no live promotion path |
| Safe adaptation | **PARTIAL** | Web-path learning governed with poisoning defences; nothing promoted |
| Enforcement and response states | **MET** | Deployed; the shared-address guard has not triggered live |
| Recovery | **MET** | Cold restart of the whole lab, exact learner restore |
| Independent value (five-way comparison) | **NOT MET** | Needs attack runs |
| Academic readiness | **PARTIAL** | As gate G |

**In one sentence:** the engineering works and is well tested. That covers
infrastructure, telemetry, enforcement, safety, governance and recovery. The central AI
claim is **not demonstrated**: that the system detects real attacks better than static
rules and learns new ones safely. The data for that can only come from team-run attacks,
and model selection has twice found no candidate that meets every predeclared rule.

---

## 3. What was done, in order

### 3.1 Before 2026-10-27: the base system

- Lab build, zone isolation and deployment.
- WAF/application telemetry and the first detectors (robust statistics, Isolation
  Forest).
- Evidence correlation, enforcement on OPNsense and the WAF, the dashboard and the MCP.
- Real benign baseline, soak test and a cold-restart test (evidence files from
  2026-10-17 to 10-22 in `artifacts/evidence/`).

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
| P1 | Benign generalization | **Negative.** The v2 champion restricts 13 of 16 unseen legitimate users in replay. v3 fixes that but fails sensitivity, so it was not promoted. A false "six new users" claim was found and corrected |
| P2 | Sensitive invariance | Cause: threshold recalibration. The gate was rebuilt on matched windows (ADR-034); it catches 6/6 desensitization mutants |
| P3 | Independent attack evaluation | **Blocked on the team**; runbook ready |
| P4 | Real online adaptation | Governed loop shown live; no promotion |
| P5 | Hardening | Done (details below) |

P5 hardening:
- IDS feed over mTLS (ADR-035).
- HTTPS API.
- Directional real-country enforcement (ADR-036); its live read-back defect was fixed.
- IDS heartbeat (ADR-037).
- RELP (ADR-038): dead-session loss went from 105/150 to 0/150.

### 3.4 Directive 10-28 (2026-10-28 afternoon)

- **SV-1 (ADR-039).** The old occlusion method called up to 76 % of
  login-failure-caused anomalies "independent". It is replaced by counterfactual
  residuals; false independence is now 0. As a result, pure brute force gets a strict
  rate limit rather than a block.
- **Crash-consistent promotion and rollback (ADR-040).**
  - Every switch is now one transaction.
  - A corrupt active model no longer crash-loops the controller.
  - A switch to a corrupt version is refused.
- **IDS engine liveness (ADR-041).** A frozen Suricata now shows as stale within about
  150 s; before the fix it looked healthy indefinitely.
- **RELP crash test.** 3 SIGKILLs lost 0 of 6,851 requests.
- **Attack-run preparation:**
  - `afw dataset validate`;
  - the four-way comparison harness (a defect fixed: IDS alerts were missing in
    replay);
  - the automatic-promotion review (not enabled).
- **P6 generalization study.** Results in §4.

### 3.5 Completion directive and master directive (2026-10-28 evening)

- **P6 finished as predeclared; P7 (amendment A2) run on clean data.** Results in §4.
- **N1 network events.** FW01 Suricata now exports flow/DNS/TLS/SSH metadata. The
  controller stores it as versioned `NetworkEvent`s with content-derived ids.
- **N2 network features and novelty.** Per-source windows of 60 s and 300 s, computed
  only over activity outside normal web use. A novelty detector with calibrated levels
  and fixed protocol ceilings runs in shadow. `/api/network` shows its state.
- **N3/N4 supervised known-threat classifier.**
  - A RandomForest with a confidence threshold, so it answers "unknown" when unsure.
  - Splits are grouped by run, and leaky splits are refused.
  - Families can be withheld.
  - Synthetic data is refused unless explicitly allowed.
- **N5 governed adaptation.** The existing web-path governance (shadow, gate, human
  promotion, probation) is unchanged.
- **N6 response states and the shared-address guard (ADR-043).** If 3 or more different
  accounts logged in successfully from an address in the last hour, a block proposed for
  that address becomes a strict rate limit that always needs human approval.
- **N7:**
  - the §8 new-threat experiment protocol and its offline core (`learn_new_family`,
    `afw experiment supervised --withhold --introduce`);
  - a cold restart of the whole lab;
  - an archive of all datasets with SHA-256 sums.
- **Team documentation:** `TEAM_ATTACK_QUICKSTART.md`, including simulated versus real
  attack evaluation.

---

## 4. The model-selection results (P6 and P7)

Both experiments used protocols committed **before** the data they judge.
- **Data:** separate training, calibration, selection and final datasets of real lab
  traffic, each with its own users.
- **Candidates:**
  - R2 and R3: the current v2 and v3 models, as references;
  - D: more data;
  - F: Wilson lower-bound fractions;
  - C: cohort thresholds;
  - S: D plus a fixed security path;
  - FS: F plus the security path.
- **Eligibility:**
  - window FPR ≤ 0.02, with an upper 95 % CI ≤ 0.05;
  - no new legitimate user restricted;
  - must-detect sensitivity both nominally and under an adaptation stress test.
    Sensitivity uses **synthetic feature-level cases**: no traffic, never called attack
    detection.

### P6 (generator v2 data)

**No eligible candidate.** Two causes:
1. Behaviour-only rate limits from two detectors that read the same features. This
   breaks the rule that an anomaly alone never restricts.
2. A generator/app mismatch: the app returned 404 for `/reviews`, so the training data
   taught the models that 404 bursts are normal.

The final sets were never collected.

### P7 (amendment A2: fixed generator, new clean data, behaviour-only evidence observe-only)

Data: 74,510 training and 24,705 calibration observations from 40 users; 13,173 and 3,033
selection observations from 22 new users. Every count equals the WAF log.

| Candidate | Worst window FPR | Users restricted (sel / shift) | Must-detect min (nominal / stressed) |
|---|---|---|---|
| R2 (v2) | 0.843 | 1/16, 0/6 | 1.00 / 0.79 |
| R3 (v3) | 0.456 | 1/16, 0/6 | 1.00 / 0.73 |
| D | 0.016 | 1/16, 0/6 | 0.81 / 0.49 |
| F | 0.009 | 1/16, 0/6 | 0.86 / 0.78 |
| C | 0.032 | 0/16, 0/6 | 0.82 / 0.52 |
| S | 0.016 | 1/16, 0/6 | 1.00 / 1.00 |
| FS | 0.009 | 1/16, 0/6 | 1.00 / 1.00 |

**Still no eligible candidate, but the reason is now narrow:**
- **False positives are fixed.** Clean data dropped the false positives sharply (window
  FPR ≤ 0.016 for retrained candidates).
- **No behaviour-only restrictions.** No candidate restricted anyone on behaviour alone.
- **One remaining restriction.** For D, F, S and FS, the only restriction is one rate
  limit on one "forgetful" persona (10.77.20.155, typo rate 0.65). It comes from the
  AUTH brute-force rule (≥ 5 failures at ≥ 50 %), not from ML, as predicted in A2.
- **C fails on FPR only.**
- **FS would otherwise have been selected.** On IDOR, ML alone scores 0.86, the rules
  1.00 and both together 1.00. The ML is not hiding behind the rules.

**Human decision needed:**
1. accept one 120 s rate limit for a user who fails most logins quickly;
2. change the AUTH rule; or
3. change the criterion.

Each needs a new predeclared amendment and **new** selection data, because the P7
selection sets are used up. Until then the v2 champion stays, and **enforce mode must not
be used with v2**: its window FPR on new users is 0.84.

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
| 16 | v1 generator: every booking 422, `/reviews` 404 | v2 generator; documented | P6/A2 |
| 17 | Selection driver read a missing key | Fixed | P6 |
| 18 | **FW01 IDS failed to start for 1¾ min** (18:52:26–18:54:10Z): a second "anomaly" logger in the new netflow include; the health check passed falsely | Include fixed; provisioning now needs a **new** Suricata PID that writes stats, else rolls back. No capture affected | N1, ADR-042 |
| 19 | Management SSH (10.77.50.254) assessed as a network source | Protected sources stored but never assessed | N1 |
| 20 | Network score of 4.5 × 10⁹ when the calibrated level was 0 | Denominator floored at 1 | N2 |
| 21 | `afw lab stop` timed out after 2 of 8 nodes | Per-node timeout handling, waits for each stop | N7 |
| 22 | Team docs used `--warmup p6-final,…`, datasets that were never collected | Now `p7-sel,p7-sel-shift` (exist, benign) | this report |
| 23 | **WAF01 and APP01 heartbeats stopped at the first midnight log rotation** (2026-10-29 00:00Z, found at 02:09Z). logrotate renamed `heartbeat.log` and rsyslog's imfile logged "Permission denied" and never followed the new file. The controller correctly reported telemetry degraded for ~2 h 10 min. No traffic or capture was affected (no traffic was running) | `copytruncate` rotation + imfile `reopenOnTruncate`; deployed; a forced rotation afterwards kept heartbeats arriving | `lab/ansible/roles/sensor_tls` |

---

## 6. What works, and what does not

### 6.1 Works, with evidence

- **Infrastructure:**
  - reproducible deploy (second run `changed=0`);
  - isolation 41/41;
  - cold restart of the whole lab recovers with no manual step: API up within about
    2.5 min and telemetry normal within about 7.5 min of the start command; learner
    restored exactly (607 learned windows, checkpoint 16).
- **Telemetry:**
  - WAF, application and IDS over mTLS, with RELP for WAF and application;
  - zero loss in controlled kills;
  - heartbeats make silent or frozen sensors visible;
  - captured datasets equal the WAF log exactly.
- **Network metadata (N1), live since 19:03Z on 2026-10-28:**
  - about 1,600 events a minute with 36 users;
  - 0 drops and 0 late events;
  - FW01 load ≤ 0.44; Suricata +2 MB; controller 274 → 280 MB;
  - survives a reboot.
- **Enforcement:**
  - OPNsense alias blocks, WAF deny and rate limits, each verified before being
    marked `enforced`;
  - policies expire;
  - protected and management addresses are always refused;
  - FW01 flushes dynamic blocks if the controller dies.
- **Safety logic:**
  - an anomaly alone never blocks: a block needs 2 independent categories;
  - IDS-only evidence stays at WATCH or below;
  - automatic enforcement pauses when a sensor is stale;
  - every intent records its response state;
  - shared addresses are never auto-blocked.
- **Governance:**
  - frozen trusted model;
  - gate plus human promotion;
  - probation with automatic rollback;
  - crash-consistent switches.
- **Online learning:** live, with poisoning controls, pivots and exact restore.
- **Evaluation machinery:**
  - predeclared protocols;
  - dataset validation and leakage checks;
  - run-level CIs;
  - four-way and supervised experiment CLIs;
  - archived and hashed datasets.
- **Operations:** HTTPS API, an audited MCP with no shell and no promotion tool, and the
  dashboard.

### 6.2 Does not work, or is unproven

1. **Real attack detection is unproven.** There are no labelled attack runs, so the
   system's recall, false negatives and value over static rules are unknown. This is the
   biggest gap.
2. **The live champion (v2) has too many false positives.** In replay it restricts 13 of
   16 new users on P1 data, and its window FPR is 0.84 on P7 data. It is fine for
   monitor mode only.
3. **No replacement model qualified.** P6 and P7 both failed the predeclared rules; P7
   failed only on the AUTH conflict (§4).
4. **No promotion has ever happened live.** Adaptation benefit is shown offline only.
5. **The network novelty calibration is degenerate.** Lab users only browse the web, so
   all 1,296 calibration windows are zero vectors. Any non-web activity (one DNS lookup
   to an unusual name, one SSH flow) therefore counts as "unfamiliar". The fixed
   ceilings (for example 15 ports in 60 s) still work as intended. Because the detector
   runs in shadow, this has no effect on decisions.
6. **The supervised classifier and the §8 experiment are unevaluated.** Only synthetic
   unit tests exist, which prove the bookkeeping and nothing about detection. The
   classifier also has **no live promotion path**, so steps 10–11 of §8 are not
   implemented for it.
7. **Online learning cannot fix the champion's own false positives.** Sources the
   champion polices are tainted by design. The governed route is operator false-positive
   feedback.
8. **The shared-address guard has never triggered live.** It is tested only in unit
   tests.

---

## 7. Limitations

**Visibility**
- Suricata listens on the ATTACK and USERS segments only. Traffic in the DMZ, APP, DB
  and MGMT segments, and traffic inside one segment, never crosses FW01 and is
  invisible.
- TLS is opaque beyond SNI and version. IDS evidence is supporting evidence only.
- A closed TCP flow reaches the controller about 70 s after it starts (60 s Suricata
  timeout). The window lateness is 75 s; longer flows count in later windows.

**Detection**
- Low-and-slow and distributed attacks fall below the per-window minimum (3 requests per
  30 s). The 300 s network horizon helps only for network-level slow scans.
- Scores are evidence scores, not probabilities.
- Isolation Forest costs about 11.9 ms per row, against about 63 µs for the statistical
  arm.

**Learning**
- Four or more colluding, tenured, similar sources can vouch for each other (residual
  poisoning risk).
- Network calibration can only lower a threshold below its ceiling, so poisoned benign
  data cannot hide a scan. It can, however, make "unfamiliar" too sensitive.

**Telemetry**
- FW01's IDS feed cannot use RELP (an OPNsense limitation), so it keeps a loss window of
  about 100 s.
- The WAF access and audit logs on WAF01 are never rotated: about 170 MB on 2026-10-29,
  growing with every run. The disk has room for the project (8.1 GB of 11 GB free). Rotating them needs the
  same copytruncate handling as the heartbeat, done when no capture is running.
- RELP acknowledges on queueing, so a crash can lose sub-second, unprocessed lines.
- The IDS heartbeat proves the engine loop runs, not that every packet is inspected.

**Response**
- An attacker with several compromised accounts behind one address looks "shared". The
  guard then downgrades to a strict rate limit plus human review. This is intended.

**Environment**
- **Single host:** about 7 GB of a 16 GB machine; scale untested.
- **Self-signed lab PKI.**
- **Not air-gapped.**
- **Scripted users:** legitimate users are scripted personas, not real people.
- **Country blocking:** real-country inbound blocks can be verified only by read-back.
- **Lab fragility:** an unattended host upgrade once restarted `gns3server` and stopped
  every VM. Recommended host change (not made): exclude `gns3server` from needrestart's
  automatic restarts.

**Data**
- Datasets live on CTRL01 and in the host archive `~/afw-datasets-archive/` (23 MB),
  not in Git. Only their SHA-256 sums are in Git
  (`artifacts/evidence/n7-2026-10-28/SHA256SUMS-20261028T200252Z`).

---

## 8. Honesty rules followed throughout

- Three kinds of data are always kept apart:
  - scripted legitimate traffic: real packets;
  - synthetic feature-level cases: no traffic, labelled SYNTHETIC, refused by the
    evaluators unless explicitly allowed;
  - real labelled attack traffic: **none exists yet**.
- The project contains no attack-traffic generator. The team supplies every attack.
- No metric was fabricated. Every number has an evidence file under
  `artifacts/evidence/`.
- Protocols and criteria were committed before the data they judge and were never
  changed afterwards.
- Selection data was used once. Final sets were never collected, because nothing was
  selected.
- Model predictions are never used as labels. Labels come from the run journal, which
  records what the team did.
- Human authorization is kept for promotion and high-impact changes.
  `behavior_only_rate_limit` stays on live.

---

## 9. Simulated tests versus real attack evaluation

| | Synthetic regression cases (P6/P7, unit tests) | Team attack runs |
|---|---|---|
| What | Feature counts added to recorded benign windows in memory | Real packets from real tools through FW01 → WAF01 → APP01 |
| Traffic | None | Yes |
| Answers | "Did a model change make the detectors less sensitive?" | "Does the system detect, contain and respond to real attacks?" |
| Can support a detection claim | **No** | Yes, with run-level CIs |

Every sensitivity number in this report is from the left column.

---

## 10. How to get it ready for submission

Do the steps in this order. Commands are checked against the CLI; full detail is in
`TEAM_ATTACK_QUICKSTART.md`.

### Step 1: team attack runs (the team; unblocks most of what is missing)

Before each run:
```bash
uv run afw lab status        # 8 VMs started
uv run afw lab verify        # 41/41
uv run afw scenario watchdog &
```

Each run:
1. Start 2 new benign background users on USR01 (10.77.20.200–.249, never reused).
2. `uv run afw scenario begin <scenario> <name> --notes "<tool, version, options>"`
3. Run the tool from ATK01 against `https://10.77.30.10/` only.
4. `uv run afw scenario end <RUN_ID>`. Use `abort` in an emergency; it powers ATK01 off.
5. `uv run afw scenario manifest <RUN_ID> /tmp/<RUN_ID>.json --benign <ips>`, then copy
   the manifest to CTRL01.
6. On CTRL01:
   `afwc dataset capture <id> --manifest /tmp/<RUN_ID>.json --purpose test`, then
   `afwc dataset validate <id>`. Exit status 1 means the dataset must not be used.

What to run:
- **Web families:** `web-bruteforce-login`, `web-sqli-probe` and `web-content-discovery`.
  Each needs 3 test runs and 1 validation run, as separate sessions hours apart.
- **Network families**, for the network path:
  - `net-portscan`, 3 test + 1 validation;
  - SSH password guessing and a slow scan. These need new scenario entries in the
    registry before they are run.
- **Holdout:** `low-and-slow-bruteforce`, evaluated once at the very end.

Report every begun run, including aborted ones.

### Step 2: evaluations (agent, after step 1)

- **Web comparison:**
  `afwc experiment evaluate --datasets <runs> --streaming --warmup p7-sel,p7-sel-shift`.
  This produces the static, frozen ML, streaming ML and hybrid arms with recall, FPR and
  CIs.
- **Supervised known-threat classifier:**
  `afwc experiment supervised --train <runs> --test <other runs>`.
- **§8 new-threat experiment:** the same command with `--withhold <family> --introduce
  <first run>`. It needs at least 3 families and at least 2 independent runs of the
  withheld family.
- **Network path:** check `/api/network` during the scan and SSH runs. The fixed ceilings
  should mark them `strong`; record what actually happens.
- **Five-way comparison:** static, supervised alone, novelty alone, frozen hybrid and
  adaptive hybrid, assembled from the outputs above.

This closes gates B and E and the known-threat, novelty and independent-value gates. A
negative result is acceptable if it is reported honestly.

### Step 3: decide the AUTH conflict (human), then re-run selection (agent)

1. Choose option 1, 2 or 3 from §4.
2. Commit it as amendment A3 **before** new data.
3. Collect new selection data, about 45 min of lab time.
4. Run the selection once.
5. If a candidate is eligible, freeze it and collect the final sets (Phase E), then run
   the final evaluation once.

### Step 4: one human-authorized promotion (team approves, agent executes)

If a candidate passes, promote it through the gate and observe probation live. This
closes gate C. If none passes, report that; the lifecycle is already demonstrated on the
HST arm and in the restart and fault-injection tests.

### Step 5: give the network detector real benign variety (optional; improves N2)

1. Add benign non-web activity to the personas: DNS lookups, an occasional SSH session
   from an admin persona.
2. Recalibrate with `afwc experiment network-calibrate --datasets <new runs> --write`.

Without this, "unfamiliar" stays over-sensitive. It is harmless in shadow mode, but it
should be stated.

### Step 6: classifier promotion path (agent; only if step 2 shows the classifier works)

Add the same shadow → gate → human → probation lifecycle the web models have. Until then
§8 steps 10–11 stay "not implemented" for the classifier.

### Step 7: documentation and demonstration (team)

- Update `RESULTS.md`, `PROJECT_STATUS.md` and `VALIDATION_MATRIX.md` with the step 1–4
  results (agent).
- The team runs `FINAL_DEMO.md` and can explain `ARCHITECTURE.md`,
  `ADAPTATION_DESIGN.md`, `RESULTS.md` §3 and this report without help. This closes
  gate G.
- Submit the dataset archive (`~/afw-datasets-archive/`) with its SHA-256 file, or say
  how to obtain it.

### Before submission, re-check

```bash
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy src tests
uv run pytest -o addopts="" -q              # expect all pass (lab tests skipped)
AFW_LAB=1 uv run pytest -o addopts="" -q tests/lab   # expect 14/14 with the lab up
uv run afw lab verify                        # 41/41
git status                                   # clean
```

### What can be claimed at each point

| After | Can claim |
|---|---|
| Now | A working, governed, verified-enforcement system with honest negative model-selection results and partial network visibility |
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
4. Real PKI and secrets management: vault or HSM, rotation, revocation.
5. Loss-free telemetry, with acknowledgement after persistence, including the IDS feed.
6. Sensors in every segment, for full network visibility, and TLS-aware inspection where
   lawful.
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

## 12. Current deployed state (2026-10-29 ~02:15Z)

- **Telemetry:** all three sensor heartbeats fresh after the defect 23 fix.
- **Controller:** CTRL01 runs the latest code, in monitor mode, with `behavior_only_rate_limit` on.
- **Models:** trusted profile v2 (no promotion pending).
- **Network novelty:** calibration installed at `/var/lib/afw/network/calibration.json`
  (1,296 windows); shadow only.
- **FW01:** `conf.d/afw-netflow.yaml` and `afw-liveness.yaml` included; Suricata in pcap
  mode on vtnet2 (ATTACK) and vtnet3 (USERS).
- **Data and code:** dataset archive `~/afw-datasets-archive/datasets-20261028T200252Z.tar.gz`
  (23 MB, 49 hashed files). Git is pushed to
  `origin/engineering-directive`.

---

## 13. Where everything is

| Topic | File |
|---|---|
| Single status page | `docs/PROJECT_STATUS.md` |
| Per-criterion evidence | `docs/VALIDATION_MATRIX.md` |
| Milestone detail (M, P, N series) | `docs/engineering/AUTONOMOUS_PROGRESS.md` |
| Decisions (ADR-001…043) | `docs/ARCHITECTURE_DECISIONS.md` |
| Results | `docs/RESULTS.md` (§3b P6, §3c P7) |
| P6/P7 protocol | `docs/engineering/P6_GENERALIZATION_AND_SENSITIVITY.md` |
| New-threat experiment | `docs/NEW_THREAT_EXPERIMENT.md` |
| Team attack runs | `docs/TEAM_ATTACK_QUICKSTART.md`, `docs/engineering/P3_TEAM_ATTACK_RUNBOOK.md` |
| Limitations | `docs/SECURITY_AND_LIMITATIONS.md`, `docs/THREAT_MODEL.md` |
| Promotion review | `docs/engineering/AUTO_PROMOTION_REVIEW.md` |
| Demo and operation | `docs/FINAL_DEMO.md`, `docs/OPERATOR_GUIDE.md`, `docs/MCP_GUIDE.md`, `docs/DEPLOYMENT.md` |
| Work logs | `docs/engineering/WORK_LOG_*.md` |
| Evidence | `artifacts/evidence/` (`p6-…`, `p7-…`, `n1-…`, `n7-…`, earlier milestones) |
