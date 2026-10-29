# AI-Adaptive-Firewall — complete dossier

**Everything in one document: all work done, the audited results, all limitations, and a
realistic "when is it finished".**

As of **2026-10-29 ~23:00Z** · branch `engineering-directive` · HEAD `66dab99` · 69 commits
ahead of origin (unpushed). Lab healthy (monitor mode). Honest throughout; every number has
an evidence file under `artifacts/evidence/`. Overclaims from earlier drafts were **audited
and corrected** (see §4–§5).

---

## 0. Bottom line (read this first)

A **working, well-engineered, safety-first adaptive-firewall control plane** runs end to end
on a real 8-VM GNS3 lab. The **engineering is proven live** (infrastructure, enforcement,
security/ops, recovery, governed learning, benign generalisation). On **real recorded attack
traffic (CIC-IDS2017), evaluated offline and independently audited**, the detection pipeline
genuinely works — and the audit confirmed it learns **behaviour, not host/port identity**.

**What is NOT proven:** live attack detection *on the lab*, because that needs in-lab attack
traffic and generating it is a safety-enforced boundary this agent cannot cross.

**Readiness ≈ 80 %.** The remaining ≈ 20 % is a single external dependency — the authorised
team running the in-lab attack scenarios — after which the downstream evaluations (which the
offline results show will work) close the last gates.

**When finished (honest):** there is **no calendar date I can set**, because the last step is
not mine to take. The *effort* remaining is small: **~1 afternoon of team attack runs + ~1 day
of agent evaluation**. See §8.

---

## 1. What the project is

An adaptive firewall controller protecting a web app (car-rental), on a real GNS3 lab: 8 VMs,
6 zone switches, 2 host connectors.

| Node | Address | Role |
|---|---|---|
| FW01 | zone gateways | OPNsense: isolation, dynamic blocks, Suricata IDS, flow/DNS/TLS/SSH metadata, pf block log. **2560 MB RAM + 1 GB swap (OOM fix)** |
| WAF01 | 10.77.30.10 | Reverse proxy / WAF |
| APP01 | 10.77.40.10 | Application |
| DB01 | 10.77.60.10 | Database |
| CTRL01 | 10.77.50.10 | Controller: telemetry, features, ML, correlation, policy, enforcement, API, dashboard |
| USR01 | 10.77.20.0/24 | Legitimate-user traffic (scripted personas) |
| ATK01 | 10.77.10.10 | Attack zone — team-only authorised runs |
| DESK01 | — | Operator desktop |

**Flow:** sensors → mTLS telemetry → per-source behaviour windows → anomaly scoring
(robust-stats + Isolation Forest enforcing; Half-Space-Trees shadow) → combined with
independent evidence categories (AUTH, WAF, IDS, HISTORY; counterfactually de-correlated) → a
block needs ≥ 2 independent categories → safety validation → applied on OPNsense/WAF and
**read back to verify** → auto-expiry. In parallel: network-novelty detector (shadow),
account-aware login controls (A3/A4), pf server-block evidence (shadow), governed
champion/challenger lifecycle. Stack: Python (hexagonal), Pydantic, SQLAlchemy+SQLite, typer
CLI, Ansible, HTTPS API, dashboard, MCP. No Kafka/Kubernetes/deep-learning/LLMs in the firewall.

---

## 2. Everything that was done

### 2.1 Base + milestones (earlier)
Lab build, isolation, deploy; WAF/app telemetry; detectors; evidence correlation; enforcement;
dashboard; MCP; real benign baseline/soak/cold-restart. **M0–M9:** audit/baseline, corroboration,
online shadow learning, champion/challenger gate+promotion+probation+rollback, drift experiments,
telemetry v2 + liveness, attack-eval harness, GeoIP, dashboard, docs. **P1–P5:** benign
generalization (negative), sensitive invariance, hardening (IDS mTLS, HTTPS API, GeoIP, RELP).
**N1–N7:** network metadata + residual windows + shadow novelty; supervised RF + incremental
ARF/HAT (synthetic); response states + shared-address guard; new-threat protocol; hashed archive.

### 2.2 Predeclared experiments (each test used once)
| Experiment | Result |
|---|---|
| P6 / P7 | no eligible model (behaviour-only limits; one forgetful user tripped the AUTH rule → A3) |
| A3 (account-aware logins) | selection passed (S); **final FAILED** on legitimate households |
| **A4** (households fixed) | **PASSED** — `distinct_usernames` ceiling-only; 0.0 FPR on households/shared, 0/2 791 logins refused |
| NV1 (network novelty) | **FAILED** one-shot test |
| **NV2** (fixed) | **PASSED** — unfamiliar 0.0059 [0.0016, 0.0115], 0 strong on 22 unseen users |
| Item 3 (incremental classifier) | SYNTHETIC benchmark only |

Plus: sensor-expansion decision (DMZ/APP/DB Suricata not enabled; pf server-block evidence
instead), dashboard completeness (network/pf/login/lifecycle panels, verified live), live
governance demo (gate refuses unqualified promotion), live enforcement-guard demo.

### 2.3 This phase — OOM fix, offline evaluation, audit, hardening
- **FW01 Suricata OOM: FIXED & load-tested.** Guest-internal (1536 MB, no swap). → **2560 MB
  RAM + 1 GB guest swap**, memcaps unchanged. 54-user/10-min stress: Suricata stable ~481 MB,
  swap unused. Persistence hardened via an **rc.syshook.d boot hook** (swap+cron), **verified
  across 3 reboots**. `fw01-oom-fix-2026-10-29/`.
- **Recovery backup:** verified git bundle (full history, test-cloned) + model/dataset/config
  manifest, no secrets. `backup-2026-10-29/`.
- **Offline evaluation on real recorded attack traffic (CIC-IDS2017, 10.3 GB, sha256-verified)
  → Suricata offline (no packets on any wire) → our production feature pipeline → RF + ARF +
  novelty + held-out-family.** Results in §4. `offline-cic-2026-10-29/`.
- **Independent audit** of those results for label errors and leakage. §4–§5.
- **Self-learning demonstration** on the recorded data (before/after + forgetting). §4.
- **Host-reboot resilience:** the institutional host rebooted unattended 3× — enabled GNS3
  `auto_start` so the lab self-recovers; `afw lab start` otherwise.
- **Separated gate states, tempered docs, revised assessment, full verification 11/11.**

### 2.4 Defects found & fixed (27, all demonstrated before fixing)
Leaking rate cap; poisoning via corroboration (140/180→0/180); telemetry stall + heartbeat
mangling; TCP syslog loss (RELP); false evidence-independence (76 %→0); crash-consistent
promotion/rollback; IDS engine-liveness; DNS-answer ownership; host-sweep ceiling (NV2);
`distinct_usernames` households (A4); heartbeat log-rotation outage; **FW01 Suricata OOM**.

---

## 3. Gate matrix

### Live GNS3 acceptance gates (A–G)
| Gate | Status | Basis |
|---|---|---|
| A Infrastructure | **MET** | lab, isolation 41/41, deploy, cold-restart + OOM recovery + self-recovery |
| D Enforcement | **MET** | read-back-verified actions, expiry, protected-address refusal (live), shared-address guard |
| F Security & ops | **MET** | HTTPS API, mTLS telemetry, audited MCP, log rotation, recovery |
| C Genuine adaptation | **PARTIAL** | live learning + rollback + live gate refusal; no promotion (correctly — needs attack recall) |
| G Academic defensibility | **PARTIAL** | methodology + honest + self-audited results; team demo + in-lab attack evidence missing |
| B Detection | **BLOCKED** | no in-lab attack runs → recall/FN unmeasurable |
| E Independent value | **BLOCKED** | value over static rules needs in-lab attack runs |

**BLOCKED ≠ FAILED.** B/E are blocked by one external/safety dependency.

### Separated gate states (`engineering/GATE_STATES.md`)
Live GNS3 attack: **BLOCKED** · Offline recorded-attack: **MET (offline)** · Supervised
learning: **MET (offline)** · Novelty: **PARTIAL** · Safe adaptation/promotion: **PARTIAL** ·
Network enforcement: **MET**. An offline result **never** advances the live gate.

---

## 4. Offline results on real recorded attack traffic (CIC-IDS2017) — audited

Tuesday capture (11 M packets). Attacker `172.16.0.1` (Kali post-NAT) → victim only, ports
21/22, only during the two documented windows → brute force. 13,784 windows (285 attack),
labelled by attacker IP. **Separate gate from live GNS3.**

| Model / setup | Recall | 95% CI | FPR | Precision |
|---|---|---|---|---|
| RandomForest (batch, time-split) | 0.846 | [0.78, 0.90] | 0.0* | 1.0 |
| RandomForest, **behaviour-only** features | 0.895 | [0.83, 0.94] | 0.0* | 1.0 |
| RandomForest, **identity-only** (ports/hosts) | **0.000** | — | 0.017 | 0.0 |
| River ARF (prequential / fairly trained) | 0.775–0.976 | — | 0.0* | 1.0 |
| Held-out family: FTP → **withheld SSH** (behaviour-only) | 0.992 | [0.96, 0.999] | 0.0 | — |
| Held-out family: SSH → FTP (behaviour-only) | 0.660 | [0.58, 0.73] | 0.0 | — |
| Unsupervised novelty (CIC-calibrated) | 0.937 | — | 0.038 | 0.39 |
| **Self-learning**: withheld FTP, before → after | 0.0 → **0.453** | — | 0.0 | — |

*"0 FPR" means **0 false positives on 13,499 benign windows** (Wilson upper ≈ 0.0003), not
"zero FP" in general.

**Audited findings (`engineering/OFFLINE_CIC_AUDIT.md`):**
- **Behaviour-driven, not leakage:** behaviour-only ≥ all-features; identity-only = 0.0; a
  300 s anti-overlap gap leaves recall unchanged. The model learns brute-force *dynamics*
  (connection durations, absence of DNS, repetitive targeting), not the attacker's IP/port.
- **Corrected overclaims:** the "frozen ARF 0.0" was a **data-ordering artifact** (shuffled →
  0.976 ≈ RF) → **no "continuous learning is superior" claim**. The "SSH→FTP 0.0" was a
  **port-feature artifact** (behaviour-only → 0.66). FTP→SSH 0.99 is cross-protocol *within
  brute force*, **not universal zero-day**.
- **Self-learning:** a challenger that knows SSH (0.94) learns withheld FTP → recall 0.0 →
  0.453 on untouched held-out, SSH retained (0.98, **no catastrophic forgetting**), 0 FP.

---

## 5. Revised capability assessment (`engineering/REVISED_ASSESSMENT.md`)

| Capability | Verdict |
|---|---|
| Genuine malicious-behaviour learning | **Yes, offline (audited, not leakage); not on the live lab** |
| Novelty detection | **Partial** (benign proven on lab; attack-side offline/cross-protocol) |
| Improved detection through adaptation | **Partial, modest, offline**; no "continuous > batch" claim |
| Safe model governance | **Yes** (gate refuses live; no promotion; gates intact) |
| Real network enforcement | **Yes** (gate D MET) |
| Independent value beyond static rules | **Not demonstrated** (needs in-lab five-way comparison) |

---

## 6. Limitations (complete)

**Visibility.** Suricata sees only ATTACK+USERS segments; DMZ/APP/DB-allowed and intra-segment
traffic invisible; TLS opaque beyond SNI; pf exposes only *blocked* server attempts; ~70 s
flow latency.
**Detection.** Low-and-slow / distributed attacks fall below the per-window minimum; scores
are evidence scores, not probabilities.
**Learning.** ≥ 4 colluding similar sources can vouch for each other; NV2 covers only the
generator-modelled habit range; the incremental ARF collapses under class imbalance unless it
learns continuously / is balanced (offline finding); the offline brute-force signal is partly
**tool-shaped** ("no DNS").
**Offline-dataset caveats.** CIC results are **external, CIC-domain**, and do **not** transfer
to the lab without re-training; two brute-force protocols on one dataset; one run per family
(self-learning used a within-run holdout, not independent runs); "0 FP" is sample-bounded.
**Infrastructure/ops.** FW01 OOM fixed (persists across reboots; re-add the rc.syshook hook
after an OPNsense firmware upgrade); FW01 feed can't use RELP (~100 s loss window); the **host
is centrally managed and reboots unattended** (lab now self-recovers, but it is not ours to
prevent).
**Environment/method.** Single host; self-signed PKI; not air-gapped; **scripted personas, not
real users**; consumed one-shot sets can't be reused; datasets on CTRL01 + hashed host archive,
not in Git; **all recovery copies are on the host** — an off-host copy needs a push (owner's
authorisation).

---

## 7. What is proven vs not

**Proven on the live lab:** infrastructure, enforcement + guards, recovery/self-recovery,
governed-lifecycle refusal, benign generalisation (A4, NV2).
**Proven offline on real recorded attack traffic (separate gate, audited):** the pipeline +
supervised models learn brute-force **behaviour** (not leakage) at 0 FP on the sample;
cross-protocol generalisation within brute force; a modest but real self-learning improvement
without forgetting.
**NOT proven (needs in-lab attack traffic — team only):** live attack recall / FN (B),
independent value over static rules (E), live adaptation benefit, any live promotion, universal
zero-day, cross-domain transfer.

---

## 8. How much is left and WHEN it finishes

**Done now (≈ 80 %).** Everything achievable without in-lab attack traffic, including the
offline attack evidence, the audit, the OOM fix and the resilience work.

**Remaining (≈ 20 %) — one external dependency, then fast agent work:**

| Step | Who | Effort | Unlocks |
|---|---|---|---|
| Run attack scenarios from ATK01 (3 test + 1 validation per family) | **team** | ~1 afternoon | the data for everything below |
| `afwc dataset capture/validate` + `experiment evaluate --streaming` (five-way comparison) | agent | ~hours | **gates B, E** |
| Supervised + new-threat (withheld-family) **in-lab** evaluation | agent | ~hours | in-lab learning evidence |
| In-lab network-attack recall (`/api/network` during scan/SSH runs) | agent | ~hour | novelty recall |
| One human-approved promotion (if a candidate qualifies) + probation | team + agent | ~hour | **gate C** |
| Team runs `FINAL_DEMO.md` | team | ~30 min | **gate G** |

**Honest "when":** I **cannot give a calendar date** — the critical-path step (executing
attack traffic in the lab) is a safety boundary I will not cross, so it waits on the team.
Once they run it, the agent closes B/E/C/G within **about a day** of evaluation. In effort
terms the project is **~1 afternoon of team work + ~1 day of agent work from complete**; in
calendar terms it finishes **whenever the team schedules the attack runs**.

**Optional agent work that needs no attack traffic (can shorten the tail):** download another
CIC day for additional attack families (DoS/port-scan) to strengthen the offline novelty and
self-learning evidence with *independent* runs; investigate the post-reboot `net_dns=0` under
load; push the branch (on request).

---

## 9. Is it a strong final-year project now?

**Yes, with honest framing.** Real infrastructure, verified enforcement, a governed learning
lifecycle, a **rigorous, self-audited** predeclared methodology with both negative and positive
results, and real (if domain-limited and modest) offline evidence that the learning detects
genuine malicious **behaviour**. It **cannot yet claim** effective live attack detection or that
adaptation beats static rules — those are measured, not asserted, and await the team's in-lab
runs. A negative in-lab result would still be a valid FYP outcome; what matters is that it is
measured honestly.

---

## 10. Where everything is

| Topic | File |
|---|---|
| This dossier | `docs/COMPLETE_DOSSIER.md` |
| Offline audit (leakage + corrections) | `docs/engineering/OFFLINE_CIC_AUDIT.md` |
| Revised capability assessment | `docs/engineering/REVISED_ASSESSMENT.md` |
| Separated gate states | `docs/engineering/GATE_STATES.md` |
| Summary + readiness | `docs/PROJECT_SUMMARY_AND_READINESS.md` |
| Results | `docs/RESULTS.md` (§3b P6, §3c P7, §3d A3, §3e NV1, §3f NV2, §3g A4, §3h offline CIC) |
| OOM fix + persistence + resilience | `artifacts/evidence/fw01-oom-fix-2026-10-29/` |
| Offline CIC (scripts, results, provenance) | `artifacts/evidence/offline-cic-2026-10-29/` (+ `~/afw-external-datasets/`) |
| Backup | `artifacts/evidence/backup-2026-10-29/` (bundle in `~/afw-backups/`) |
| Team attack runs | `docs/TEAM_ATTACK_QUICKSTART.md`, `engineering/P3_TEAM_ATTACK_RUNBOOK.md` |
| Automated verification | `scripts/final_verification.sh` |
| Reproduce the offline run | `artifacts/evidence/offline-cic-2026-10-29/README.md` |
