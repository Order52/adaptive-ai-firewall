# AI-Adaptive-Firewall — everything done, what is left, limitations and how to fix them

**One document.** As of **2026-10-30 ~08:25Z** · branch `engineering-directive` · HEAD `576e19e` ·
183 commits on the branch, **96 not pushed to origin** · working tree clean · lab healthy
(monitor mode, nothing enforced). Every number below has an evidence file under
`artifacts/evidence/` (36 folders). This document supersedes the status numbers in earlier
summaries wherever they differ; three of those earlier claims turned out to be wrong and are
listed in §4 so you can see exactly what changed.

---

## 0. Bottom line

- **A working, safety-first adaptive firewall platform runs on a real 8-VM GNS3 lab.** Its
  engineering is verified: isolation 41/41, live lab tests 14/14, 384 unit tests, read-back-verified
  enforcement, governed model lifecycle, recovery from restarts and out-of-memory.
- **The central AI claim is only partly demonstrated.** On real *recorded* attack traffic
  (three CIC-IDS2017 captures, analysed offline) the models detect brute-force-style attacks well
  and learn new attack families, with clear limits. **On the live lab it is not demonstrated at
  all**, because that needs attack traffic executed in the lab, which I do not generate.
- **I found and corrected three mistakes in my own earlier results** (§4). The corrected picture is
  more modest than what I first reported, and that is the picture to present.
- **Not finished.** The remaining work is mostly one external step (the team running attack
  scenarios) plus roughly a day of evaluation that follows it. I cannot give a calendar date for
  the external step. Details in §7.

---

## 1. What the project is

A controller that protects a web application (a car-rental app) on a GNS3 lab: 8 VMs, 6 zone
switches, 2 host connectors.

| Node | Address | Role |
|---|---|---|
| FW01 | zone gateways | OPNsense: zone isolation, dynamic blocks, Suricata IDS, flow/DNS/TLS/SSH metadata, pf block log. **2560 MB RAM + 1 GB swap** |
| WAF01 / APP01 / DB01 | 10.77.30.10 / .40.10 / .60.10 | reverse proxy + WAF / application / database |
| CTRL01 | 10.77.50.10 | the controller: telemetry, features, ML, correlation, policy, enforcement, API, dashboard |
| USR01 / ATK01 / DESK01 | 10.77.20.10 / .10.10 / .50.20 | legitimate-user traffic / attack zone (team only) / operator desktop |

**How it works.** Sensors send telemetry to CTRL01 over mTLS → per-source behaviour windows →
anomaly scoring (robust statistics and Isolation Forest enforce; Half-Space-Trees run in shadow) →
combined with independent evidence categories → a block needs at least two independent categories
→ safety validation → applied on OPNsense/WAF and **read back to verify** → auto-expiry. In
parallel: a network-novelty detector (shadow), account-aware login controls, pf block evidence
from protected servers (shadow), and a champion/challenger learning lifecycle with human
promotion, probation and automatic rollback. Stack: Python, Pydantic, SQLite, a `typer` CLI
(`afw`), Ansible, an HTTPS API, a dashboard and an MCP server. No Kafka, Kubernetes, deep learning
or LLMs inside the firewall.

---

## 2. Current status at a glance

| Area | Status |
|---|---|
| Live lab: isolation, tests, controller, telemetry | **Working** — 41/41, 14/14, healthy |
| Enforcement and safety guards | **Proven live** (read-back, expiry, protected-address refusal, shared-address guard) |
| Governed learning lifecycle | **Proven live** — the promotion gate correctly *refuses* an unqualified challenger; nothing promoted |
| Benign generalisation (login controls A4, network novelty NV2) | **Proven on the lab** |
| Detection of brute-force-style attacks, recorded traffic, offline | **Demonstrated** (three captures, audited), family-specific |
| Learning a new attack family, offline | **Demonstrated, conditional** (needs rehearsal; modest) |
| AI value over static Suricata, offline | **Measured with a fair baseline** — about 2× the recall on brute-force-style activity; complementary |
| FW01 out-of-memory problem | **Fixed and made durable** |
| Live attack detection in the lab | **BLOCKED** (needs in-lab attack traffic) |
| Independent value over static rules *on the lab* | **BLOCKED** (same reason) |
| Project finished | **No** |

**Latest verification** (`scripts/final_verification.sh`, 2026-10-30 08:01Z): **11/11 pass** —
ruff, format and mypy clean; **384 passed, 14 skipped**; isolation 41/41; controller healthy and in
monitor mode; telemetry not degraded; network novelty calibrated; live lab tests 14/14.

---

## 3. Everything that was done

### 3.1 The platform (built and verified)
Lab build and zone isolation; WAF/application/IDS telemetry over mTLS (RELP for WAF/app);
detectors; evidence correlation with counterfactual independence; enforcement on OPNsense and the
WAF with read-back verification; a dashboard (network-novelty, pf-evidence, login-control and
model-lifecycle panels, with candidate models labelled "NOT qualified"); an MCP interface (the
shadow-learning and challenger-lifecycle tools return live data matching the REST API); log
rotation; a cold-restart procedure. 27 defects were found and fixed along the way, each shown
before it was fixed.

### 3.2 Predeclared experiments (each test set used once)
| Experiment | Result |
|---|---|
| P6, P7 model selection | no eligible model |
| A3 account-aware login controls | selection passed; **final failed** on legitimate multi-account households |
| **A4** (household fix) | **passed**: 0.0 false positives on households and shared addresses, 0 of 2,791 legitimate logins refused |
| NV1 network novelty | **failed** its one-shot test |
| **NV2** (fixed) | **passed**: unfamiliar-traffic rate 0.0059 [0.0016, 0.0115] on 22 unseen users |

### 3.3 Operational work
- **FW01 Suricata out-of-memory — fixed.** It was inside the firewall VM (1536 MB, no swap), not the
  host. Fixed with 2560 MB RAM plus a 1 GB swap file; detection settings were *not* weakened.
  Stress-tested with 54 users for 10 minutes: Suricata stable, swap barely used.
- **Made durable (this session).** The topology file still said 1536 MB, so a rebuild would have
  brought the problem back. It now says 2560. `afw lab provision-fw` installs the swap file and the
  boot hook (`lab/opnsense/afw-resources.syshook`) idempotently; 7 unit tests; run twice on the live
  firewall. Provisioning also leaves the firewall console at a login prompt, not an open root shell.
- **Reboot resilience.** The institutional host rebooted unattended several times. GNS3
  `auto_start` is on, so the lab restarts itself; `afw lab start` otherwise.
- **`net_dns` showing 0** after a firewall reboot was not a fault (12,330 DNS events were captured
  earlier; direct DNS produced events again).
- **Backups.** Verified git bundle; **encrypted off-host archives** (`scripts/make_offhost_backup.sh`,
  GnuPG AES-256, secrets in a separate archive, restore-tested). Nothing has been copied off this
  machine; that needs your approval.
- **Logins.** On your request the seven Linux VMs accept username `afw` / password `afw` on the GNS3
  console and over SSH (`scripts/set_vm_passwords.sh`, reversible with `--lock`). FW01, GNS3, the
  database and the API keep their own credentials. All of it is in `~/.config/afw/LAB_ACCESS.md`
  (not in Git).

### 3.4 Offline evaluation on real recorded attack traffic (separate gate)
Method: CIC-IDS2017 captures → Suricata offline (`-r`, nothing sent on any network) → the project's
own feature pipeline → models. Attackers labelled by IP; compromised internal hosts excluded.
Provenance, sha256 and citations are recorded.

| Capture | Families | Independent attack bursts |
|---|---|---|
| Tuesday (11 M packets) | FTP and SSH brute force | 3 |
| Friday (8.8 GB) | port scan, botnet, DDoS | 4 |
| Thursday (8.3 GB) | web brute force, XSS, SQL injection; infiltration (excluded) | 7 |

---

## 4. Mistakes I found in my own earlier results (and fixed)

| Earlier claim | What was actually true | Where corrected |
|---|---|---|
| "Learning a new family causes **no forgetting**" | Measured on windows the model had already trained on, from one seed. On held-out data over 10 seeds, incremental learning **without rehearsal forgets badly** (old-family recall 0.78 ± 0.36, as low as 0.08); with rehearsal 0.999 | `engineering/ERRATUM_FORGETTING.md` (8 documents corrected) |
| "Static Suricata detects **0.0**; the AI catches 128 windows it misses" | My Suricata setup put the attacker inside `HOME_NET`, so ~11,900 rules could never fire. With a fair setup static detects 0.43 / 0.13 / 0.28 | `engineering/ERRATUM_STATIC_BASELINE.md` |
| Window-level confidence intervals | Each family is **one attacker session**; Tuesday has 3 independent bursts, Friday 4. Honest block-bootstrap intervals are much wider (Tuesday recall [0.62, 0.98]; Friday [0.00, 0.59]) | `cic_robustness.py`, `STATUS_LIMITATIONS_FIXES.md` |

Earlier, smaller corrections: the "frozen ARF = 0.0" result was a data-ordering artifact;
"SSH→FTP = 0.0" was a port-feature artifact; "0 false positives" is bounded by the sample, not
absolute; FTP→SSH 0.99 is not universal zero-day; a suspicion that the detector keyed on DNS-absence
was **not** supported by the ablation. The old result files are kept (`SUPERSEDED.md`).

---

## 5. Results (corrected numbers)

**Brute-force detection (RandomForest, behaviour-only features, offline)**
| Measurement | Result |
|---|---|
| Tuesday, time-split | recall 0.846 (window CI [0.78, 0.90]; **block CI [0.62, 0.98]**), 0 false positives in 13,499 benign windows |
| Behaviour-only vs identity-only features | 0.92 vs 0.00 → the model learns behaviour, not the attacker's host or port |
| Removing timing, DNS, or port/host features | recall essentially unchanged; removing the *volume* features → 0.0 |
| Trained on Tue+Fri → Thursday (never seen) | recall **0.54** (block CI [0.36, 0.71]), 0 FP; morning web attacks **0.88** |
| Tuesday-trained → Friday | recall 0.11; even trained on Friday only 0.27 → **family-specific** |

**ML against static Suricata (fair `HOME_NET`)**
| Slice | Static recall (FP windows) | ML recall (FP) | Static OR ML |
|---|---|---|---|
| Tuesday brute force | 0.43 (3.2 %) | **0.90** (0 %) | — |
| Friday families | 0.13 (2.7 %) | 0.27 (0.05 %) | — |
| Thursday morning web attacks | 0.28 (5.5 %) | **0.88** (0 %) | 0.91 |
| Thursday afternoon | 0.04 | 0.20 | 0.23 |

**Self-learning, 10 seeds, held-out anchors** (new family = Thursday; old = Tuesday + Friday)
| Strategy | Benign FPR | Old: Friday family | New: Thursday | Learn time |
|---|---|---|---|---|
| Before learning | 0.0016 | 0.375 | 0.533 | — |
| Incremental, no rehearsal | 0.0092 | **0.097** (forgets) | 0.881 | 1.9 s |
| Incremental + rehearsal | 0.0112 | 0.572 | **0.918** | 3.6 s |
| Periodic batch retraining | **0.0007** | 0.406 | 0.859 | **0.24 s** |

Batch retraining gets within ~6 points of the best new-family recall at ~16× fewer false positives
and ~15× less compute. **No claim that online learning is superior.**

**Scan detection:** the fixed 15-ports/60 s ceiling is too low (13–57 % benign-source false
positives over longer horizons); 50–100 ports detects the real scan at 0 benign false positives
offline. Not applied: it must be re-calibrated on *lab* benign traffic first.

**Safeguards exercised on real windows:** immutable evaluation anchor, champion isolation,
checkpoint reload (identical predictions), rollback (exact restore), provenance gate against
injected false positives (FPR 0.72 / 0.98 without it → 0.019 with it). Residual gap: label-flip
poisoning is only caught by the anchor gate when the flipped labels carry valid provenance.

---

## 6. Limitations and how to fix each

| # | Limitation | How to fix it | Who / effort |
|---|---|---|---|
| 1 | **No live attack evidence** — gates B and E blocked | The authorised team runs the scenarios from ATK01 (`TEAM_ATTACK_QUICKSTART.md`, 3 test + 1 validation run per family); then I run capture, validation and the five-way comparison | **Team**, ~1 afternoon; agent ~1 day after |
| 2 | **Models are family-specific** (0.11 across families; 0.27 on Friday's families) | Features for slow, bursty and distributed behaviour (longer horizons, per-destination fan-in, inter-arrival regularity, beacon periodicity); train on a union of families; evaluate leave-one-family-out. Needs more labelled families | Agent, days; needs more data |
| 3 | **Run-level sample is tiny** (3–7 bursts per family) | Collect ≥ 2 independent runs per family (team runs or another dataset such as CSE-CIC-IDS2018) and hold a whole run out | Team or agent + download |
| 4 | **Static baseline is generic** (2026 ET Open rules on 2017 traffic) | Tune or select rules for the target app; the comparison is a lower bound on static | Agent |
| 5 | **Hybrid (ML OR novelty) hurts precision** | Use ML as the primary signal; keep novelty as evidence for human review, not an OR trigger | Agent, small |
| 6 | **Incremental learning forgets without rehearsal; helps only for genuinely new families** | Keep rehearsal on (production default) and the 0.05 per-family recall-drop gate; admit only examples the model currently misses; keep an immutable anchor | Already in `ml/incremental.py`; verify live |
| 7 | **Scan ceiling mis-tuned** | Re-calibrate on lab benign traffic (benign personas can generate it, no attack traffic needed), then raise toward 50–100 ports and evaluate 60 s and 300 s horizons together | **Agent, can start now** |
| 8 | **Offline results are CIC-domain; do not transfer to the lab** | Train and calibrate on lab benign plus team attack captures; per-feature normalisation if sources are mixed | Needs #1 |
| 9 | **Supervised classifier not wired into live shadow** | Deliberately not done (no lab-domain validation). Wire into shadow after #8; keep enforcement off and promotion human-gated | After #8 |
| 10 | **Limited visibility** (only ATTACK+USERS segments; TLS opaque; allowed DMZ/APP/DB traffic unseen) | pf blocks of server sources are already surfaced. Server-segment Suricata needs interface-aware flow tracking and its own detector (`SENSOR_EXPANSION_DECISION.md` §4) | Agent, design work |
| 11 | **Slow / distributed web attacks fall below the per-window minimum** | Per-account and per-source multi-horizon counters; evaluate on slow-brute-force runs | Agent + team data |
| 12 | **Colluding sources can vouch for each other; label-flip poisoning caught only by the anchor gate** | Cap per-cohort influence on admission; require provenance-verified labels; monitor challenger drift | Agent |
| 13 | **FW01 feed has no RELP** (OPNsense limit): ~100 s loss window | Accept, or use a RELP-capable relay; heartbeats already expose gaps | Optional |
| 14 | **After an OPNsense *firmware upgrade* the hook may need re-installing** | Re-run `afw lab provision-fw` (idempotent) | Owner, 1 command |
| 15 | **Host is centrally managed and reboots unattended** | `auto_start` makes the lab self-recover; ask the host administrators to exclude `gns3server` from needrestart | Owner / admins |
| 16 | **All plain backups are on this one host** | Encrypted archives are ready. **Copy them off with your approval** (`scp` to a destination you choose, or `git push origin engineering-directive`); keep the passphrase file elsewhere | **Owner decision** |
| 17 | **Legitimate users are scripted personas** | Validate with recorded real-user traffic; add more persona archetypes | Future work |
| 18 | **VM logins are `afw`/`afw`** (weak by your request) | Fine for a closed lab; run `scripts/set_vm_passwords.sh --lock` before any shared or networked use | Owner |
| 19 | **FW01 root password still long and random; a console was left logged in by my earlier automation** | Provisioning now logs out. Tell me if you want a simpler FW01 password (carries a lock-out risk, so I would do it carefully) | Owner decision |
| 20 | **Consumed one-shot test sets cannot be reused** | By design; use new data for any further tuning | — |
| 21 | **Single host, self-signed PKI, not air-gapped; not production-grade** | Real PKI, HA controller, scale tests — future work, not needed for the degree | Future |
| 22 | **No model has been promoted** | Needs a candidate that passes the gate (needs #1) plus a human approver | Team + owner |

---

## 7. How much is left

**Done:** everything that can be done without in-lab attack traffic — the platform, the
verification, the benign-side experiments, three offline captures with audits and corrections, the
reliability work and the backups. Counting the seven live acceptance gates: **3 met (A, D, F), 2
partial (C, G), 2 blocked (B, E)**. By my judgment, **roughly three-quarters of the work for a
defensible submission is done**; that is a judgment, not a measurement. The offline work lowered
what the *scientific* claims can say, not what the *engineering* delivers.

**Still to do, in order:**

| Step | Who | Effort | Closes |
|---|---|---|---|
| 1. Run the attack scenarios from ATK01 | **Team** | ~1 afternoon | unblocks everything below |
| 2. Capture, validate and run the five-way comparison (static / ML / novelty / hybrid / adaptive) on the lab runs | Agent | ~hours | gates **B, E** |
| 3. In-lab supervised and withheld-family learning; in-lab scan/SSH recall | Agent | ~hours | in-lab learning evidence |
| 4. One human-approved promotion, if a candidate qualifies, then probation | Team + owner | ~1 hour | gate **C** |
| 5. Run `FINAL_DEMO.md` and be able to explain it | Team | ~30 min | gate **G** |

**Calendar date:** I cannot give one. Step 1 is not mine to take, so completion happens when the team
schedules it; after that the agent work is about a day.

**Work I can do now without attack traffic** (optional, improves the evidence): calibrate the scan
ceiling on lab benign traffic (#7); more independent captures for repeat runs and more families
(#2, #3); leave-one-family-out evaluation; slow/distributed features. **Owner decisions pending:**
copy the encrypted backups off this machine (#16); whether to push the branch (96 commits); FW01
password (#19).

---

## 8. Acceptance gates

| Gate | State | Basis |
|---|---|---|
| A Infrastructure | **MET** | isolation 41/41, reproducible deploy, restart/OOM/reboot recovery |
| D Enforcement | **MET** | read-back-verified actions, expiry, protected-address refusal, shared-address guard |
| F Security and operations | **MET** | HTTPS API, mTLS telemetry, audited MCP, log rotation, recovery |
| C Adaptation | **PARTIAL** | live learning, rollback and a live gate refusal; no promotion (needs attack recall) |
| G Academic defensibility | **PARTIAL** | methodology and honest, self-corrected results documented; demo and in-lab evidence missing |
| B Detection | **BLOCKED** | no in-lab attack runs |
| E Independent value | **BLOCKED** | needs the in-lab five-way comparison |

Separated gate states (`engineering/GATE_STATES.md`; an offline result never advances a live gate):
live attack detection **BLOCKED** · offline recorded-attack detection **MET (offline)** · supervised
learning **MET (offline), family-specific** · unfamiliar-threat detection **PARTIAL** · safe
adaptation and promotion **PARTIAL** · network enforcement **MET**.

---

## 9. Is it a defensible final-year project now?

Yes, with honest framing. It is a real, verified, safety-first system with a governed learning
lifecycle and an unusually self-critical method that caught and corrected its own errors. It
**cannot yet claim** effective live attack detection, or that adaptation beats static rules in the
lab. Those are the measurements that wait for step 1, and a negative result there would still be a
valid outcome if reported honestly.

---

## 10. Where things are

| What | Where |
|---|---|
| Run everything verifiable | `scripts/final_verification.sh` |
| Recover the lab after a host reboot | `uv run afw lab start` (GNS3 `auto_start` should do it) |
| Re-apply FW01 swap/hook after an upgrade | `uv run afw lab provision-fw` |
| Encrypted off-host backup (build + restore test) | `scripts/make_offhost_backup.sh` → `~/afw-backups/offhost/` |
| VM logins on/off | `scripts/set_vm_passwords.sh` / `--lock` |
| Credentials and access sheet | `~/.config/afw/LAB_ACCESS.md` (not in Git) |
| Team attack runs | `docs/TEAM_ATTACK_QUICKSTART.md`, `docs/engineering/P3_TEAM_ATTACK_RUNBOOK.md` |
| Corrections | `docs/engineering/ERRATUM_FORGETTING.md`, `ERRATUM_STATIC_BASELINE.md` |
| Offline evidence | `docs/engineering/OFFLINE_CIC_AUDIT.md`, `OFFLINE_INDEPENDENCE.md`, `OFFLINE_THIRD_CAPTURE.md`; `artifacts/evidence/offline-cic-*` |
| Gates and assessment | `docs/engineering/GATE_STATES.md`, `REVISED_ASSESSMENT.md`, `docs/ARCHITECTURE_VS_GOALS.md`, `docs/FINAL_REPORT.md` |
| Results and matrix | `docs/RESULTS.md`, `docs/VALIDATION_MATRIX.md` |
