# AI-Adaptive-Firewall — complete summary, evidence, limitations and readiness

**As of 2026-10-29 ~14:50Z · branch `engineering-directive` · HEAD `215edfc` (48 commits ahead of origin, unpushed).**

This single document covers: what the project is, everything that was built and measured,
what is **proven** versus **not proven**, the limitations, and **how much is left** to
make it a strong, fully-working final-year project. It is honest: where a result does not
exist, it says so. Every number has an evidence file under `artifacts/evidence/`.

---

## 0. One-paragraph verdict

A working, carefully-engineered **adaptive firewall control plane** runs end-to-end on a
real 8-VM GNS3 lab: real telemetry over mTLS, behavioural + evidence-based detection,
safety-validated and read-back-verified enforcement, a governed online-learning
lifecycle, an operator dashboard and an MCP interface. The **engineering is proven**
(infrastructure, enforcement, security/ops, recovery, governance). The **central AI claim
— that it detects real attacks better than static rules and safely learns new ones — is
not yet proven**, because that requires labelled **attack traffic**, and generating
attack traffic is a safety-enforced boundary this agent cannot cross. Model selection has,
honestly, produced mostly negative results (no over-fit-free champion yet), with two
**positive** benign-side results this session (A4 AUTH households, NV2 network novelty).
**Readiness: ~75% of a top-grade FYP is done and verifiable now; the remaining ~25% is
one external dependency — the team running the attack scenarios — plus the evaluations
that unlock from it.**

---

## 1. What the project is

An adaptive firewall controller that protects a web application (a car-rental app) on a
real GNS3 lab: 8 VMs, 6 zone switches, 2 host connectors (`docs/GNS3_TOPOLOGY.md`).

| Node | Address | Role |
|---|---|---|
| FW01 | zone gateways | OPNsense: zone isolation, dynamic block aliases, Suricata IDS, flow/DNS/TLS/SSH metadata, pf block log |
| WAF01 | 10.77.30.10 (DMZ) | Reverse proxy / WAF in front of the app |
| APP01 | 10.77.40.10 (APP) | The application |
| DB01 | 10.77.60.10 (DB) | Its database |
| CTRL01 | 10.77.50.10 (MGMT) | The controller: telemetry, features, ML, correlation, policy, enforcement, API, dashboard |
| USR01 | 10.77.20.0/24 | Legitimate-user traffic (scripted personas) |
| ATK01 | 10.77.10.10 (ATTACK) | Attack zone — used only by the team for authorized attack runs |
| DESK01 | — | Operator desktop |

**How it works:** sensors stream telemetry to CTRL01 over mTLS → per-source behaviour
windows → anomaly scoring (robust-statistics + Isolation Forest enforcing;
Half-Space-Trees in shadow) → combined with independent evidence categories (AUTH, WAF,
IDS, HISTORY, counterfactually de-correlated) → a block needs ≥ 2 independent categories →
response state + safety validation → applied on OPNsense/WAF and **read back to verify** →
auto-expiry. In parallel: a **network-novelty** detector (shadow), **account-aware login
controls** (A3/A4), **pf server-block evidence** (shadow), and a **governed
champion/challenger** online-learning lifecycle.

**Stack:** Python (hexagonal), Pydantic, SQLAlchemy Core + SQLite, Alembic, a `typer` CLI
(`afw`), Ansible deploy, HTTPS API with role tokens, a static dashboard, MCP. No Kafka,
Kubernetes, deep learning or LLMs inside the firewall.

---

## 2. Current verified state (runnable now)

`scripts/final_verification.sh` runs every non-attack check and prints the gate matrix.
Latest run: **10/10 verifiable checks pass**.

| Check | Result |
|---|---|
| ruff / format / mypy | clean (111 source files) |
| unit + integration tests | **377 passed, 14 skipped** |
| live lab isolation (`afw lab verify`) | **41/41** |
| live lab tests (`AFW_LAB=1 pytest tests/lab`) | **14/14** |
| controller health | ok, **monitor mode**, telemetry not degraded, no model error |
| network novelty | calibrated (NV2), **shadow** |
| dataset archive | hashed, 100 files (incl. A4/NV2) |

Lab is healthy, in **monitor mode**, nothing enforced, trusted profile **v2**.

---

## 3. Acceptance gates — the honest matrix

| Gate | Status | Proven? | Why |
|---|---|---|---|
| **A Infrastructure** | **MET** | ✅ | Reproducible lab, isolation 41/41, idempotent deploy, cold-restart recovery |
| **D Enforcement** | **MET** | ✅ | Real OPNsense/WAF actions, read-back verification, expiry, protected-address refusal (shown live), shared-address guard |
| **F Security & ops** | **MET** | ✅ | HTTPS API, all telemetry mTLS, audited MCP, log rotation, recovery |
| **C Genuine adaptation** | **PARTIAL** | ⚠️ | Live learning, pivots, restart-restore, drift reports, and a **live governed gate refusal** shown; **no promotion** (gate correctly refuses — needs attack recall) |
| **G Academic defensibility** | **PARTIAL** | ⚠️ | Methodology + honest negative/positive results documented; **team demo + attack-side evidence missing** |
| **B Detection** | **BLOCKED** | ❌ | No labelled attack runs exist → recall / false-negatives unmeasurable |
| **E Independent value** | **BLOCKED** | ❌ | Benign-only comparison; value-over-static-rules needs attack runs |

**BLOCKED ≠ FAILED.** B and E are blocked by a single external/​safety dependency, not by
a defect.

---

## 4. What was built and measured — the full list

### 4.1 Core platform (proven)
- **Lab + isolation:** 41/41 isolation checks; clients cannot bypass the WAF; DB reachable
  only from the app tier; management reaches everything. Cold restart recovers with no
  manual step; learner restored exactly.
- **Telemetry:** WAF/app over RELP (mTLS), Suricata alerts + flow/DNS/TLS/SSH metadata,
  and pf block log — all over mTLS. Zero loss in controlled kills; heartbeats expose
  silent/frozen sensors; captured datasets equal the WAF access log exactly.
- **Enforcement:** OPNsense alias blocks, WAF deny + rate limits, each **read-back
  verified** before being marked enforced; policies expire; protected/management addresses
  always refused (shown live 2026-10-29: 10.77.50.10 and 10.77.60.10 refused); FW01 flushes
  dynamic blocks if the controller dies.
- **Safety logic:** an anomaly alone never blocks (≥ 2 independent categories, ADR-039);
  IDS-only evidence stays at WATCH; automatic enforcement pauses on a stale sensor;
  response states (ADR-043); shared addresses never auto-blocked.
- **Governance:** frozen trusted model, gate + human promotion, probation with automatic
  rollback, crash-consistent switches (ADR-040). The promotion **gate was exercised live**
  (2026-10-29) and correctly **refused** an unqualified challenger.
- **Operations:** HTTPS API, audited MCP (no shell, no promotion tool), dashboard.

### 4.2 Model-selection experiments (all predeclared; each test used once)
| Experiment | Result | Meaning |
|---|---|---|
| **P6** (generator v2) | no eligible model | behaviour-only rate-limit + generator/app mismatch |
| **P7** (A2, clean data) | no eligible model | only blocker: one forgetful user hit the AUTH brute-force rule → led to A3 |
| **A3** (account-aware login controls) | selection passed (S); **final FAILED (F1)** | S's security path flagged legitimate multi-account **households** |
| **A4** (this session) | **PASSED** ✅ | `distinct_usernames` made ceiling-only; S passed selection **and** one-shot final — **0.0 FPR on households and shared addresses**, 0/2 791 logins refused, SYNTHETIC sensitivity 1.0 |
| **NV1** (network novelty) | one-shot test **FAILED** | heavy users under-covered; a legit browser hit the host-sweep ceiling |
| **NV2** (this session) | one-shot test **PASSED** ✅ | stratified heavy users + ceiling counts only internal/unanswered hosts; **unfamiliar 0.0059 [0.0016, 0.0115]**, 0 strong on 22 unseen users |
| **Item 3** (incremental ARF/HAT classifier) | SYNTHETIC benchmark only | not clearly better than periodic RF refit; never enforcing |

**A4 and NV2 are the two positive results**: the benign side of AUTH and network novelty
now generalise to unseen users (incl. households/shared addresses) with low false-alarm
rates. Both stay in **monitor/shadow** — neither makes an attack-detection claim.

### 4.3 Network visibility (N1/N2, ADR-042) — partial, proven for what it sees
- Suricata on FW01 exports flow/DNS/TLS/SSH metadata; the controller stores versioned,
  de-duplicated `NetworkEvent`s and builds 60 s/300 s residual windows (shadow detector).
- **Sensor-expansion decision (NV1 §6.3):** DMZ/APP/DB Suricata **not enabled** — server
  sources are never assessed (no verdicts without a separate validated detector), and
  FW01's flow tracking would capture client→WAF traffic twice (`SENSOR_EXPANSION_DECISION.md`).
- **Instead: pf server-block evidence (shadow)** — connections pf drops from a protected
  server toward a forbidden zone (the shape of lateral movement) are forwarded and shown
  in `/api/network`; verified end-to-end (all 10 server-deny checks of `afw lab verify`
  appear).

### 4.4 Dashboard (complete, real backend data, 0 console errors live)
14 panels, all bound to the live API: risk/requests timelines, live sources, baseline-vs-
current, adaptive policy decisions (with read-back/rollback), decision explanations,
controlled adaptation, **models & profiles (with explicit "candidate = NOT qualified"
labels)**, **online-learning + promotion-gate lifecycle (shows the live governed
refusal)**, IDS-only sources, GeoIP, **network novelty (shadow)**, **pf server-block
evidence**, **login-controls + shared-address guard**, static-vs-ML experiments, telemetry
health, audit trail.

### 4.5 Defects found and fixed this project (26 total)
All demonstrated before fixing. Highlights: leaking rate cap (M2), poisoning via
corroboration 140/180→0/180 (M4), silent telemetry stall + heartbeat mangling (M5), TCP
syslog loss 105/150→0/150 via RELP (ADR-038), false evidence-independence up to 76%→0
(ADR-039, SV-1), crash-consistent promotion/rollback (ADR-040), IDS engine-liveness
(ADR-041), DNS-answer ownership (schema 2), host-sweep ceiling counting CDN hosts (NV2),
`distinct_usernames` calibrated at 1 flagging households (A4), and the WAF/APP heartbeat
log-rotation outage. **This session also found and recovered a live FW01 Suricata OOM**
(see §6).

---

## 5. What is proven vs not proven (the crux)

### Proven (with live/real evidence)
- The lab, its isolation, and reproducible deployment.
- Telemetry integrity and loss-free delivery under controlled faults.
- Real, read-back-verified enforcement and the safety guards (incl. live protected-address
  refusal).
- Recovery: whole-lab cold restart, exact learner restore, FW01 OOM reboot recovery.
- The **governed** lifecycle runs live and correctly **refuses** unqualified promotion.
- **Benign generalisation of the AUTH controls (A4) and the network-novelty detector
  (NV2)** to unseen users, at measured low false-alarm rates.
- Cost/latency: statistical arm ~14–63 µs/window; Isolation Forest ~11–12 ms/row;
  telemetry latency 0.5–2.0 s.

### NOT proven (requires labelled attack traffic)
- **Attack detection recall / false-negative rate** (Gate B) — web *and* network path.
- **Value of the AI over static rules** (Gate E, the five-way comparison).
- **Learning a withheld threat family** (the §8 new-threat experiment).
- **Supervised classifier (RF vs incremental ARF/HAT) real-attack performance.**
- **A successful live promotion** — no candidate qualifies, because qualification needs
  attack-recall data; the gate correctly blocks it.
- Any claim of effectiveness against real attacks. **None is made.**

---

## 6. Limitations (complete)

**Visibility**
- Suricata sees only the ATTACK and USERS segments; allowed DMZ/APP/DB and intra-segment
  traffic is invisible; TLS is opaque beyond SNI/version. pf exposes *blocked* server
  attempts only.
- Network events arrive ~70 s after a flow starts (Suricata 60 s timeout; 75 s lateness).

**Detection**
- Low-and-slow / distributed attacks fall below the per-window minimum (3 req/30 s).
- Scores are evidence scores, not probabilities.

**Learning**
- ≥ 4 colluding, tenured, similar sources can vouch for each other (residual poisoning).
- NV2 calibration covers only the generator-modelled habit range; a heavy user just above
  it gives ~14% unfamiliar windows. A4's ceiling-only `distinct_usernames` means a 3–4
  account spray is caught by the live `credential_spraying` rule, not that quantity.

**Infrastructure (operational)**
- **FW01 Suricata can be OOM-killed under heavy capture load** — OPNsense Nano, 1.5 GB RAM,
  **no swap**. The 66-user A4 capture OOM-killed it (~11:59Z); it stayed down until found
  via the live lab suite and recovered by a reboot (~13:25Z). Mitigation (not yet applied):
  fewer concurrent capture users, or a lower Suricata memcap. Evidence:
  `artifacts/evidence/fw01-ids-oom-2026-10-29/`.
- FW01's feed cannot use RELP (OPNsense) → ~100 s loss window; RELP acks on queue (sub-
  second crash loss possible); the IDS heartbeat proves the loop runs, not full inspection.

**Environment / method**
- Single host (~7 GB of 16 GB); self-signed PKI; not air-gapped.
- Legitimate users are **scripted personas**, not real people; they never approach the
  AUTH thresholds (friction for ≥ 5 failures is shown only by SYNTHETIC runs).
- Consumed one-shot sets (a3-sel, Phase E, a4-sel/final, nv1/nv2 test) cannot be reused.
- Datasets live on CTRL01 + a hashed host archive, not in Git (only the SHA-256 sums are).

---

## 7. How much is left — readiness breakdown

Think of it as **done now (~75%)** + **one external dependency unlocks the rest (~25%)**.

| Area | State | Left to do | Who |
|---|---|---|---|
| Infrastructure, isolation, deploy, recovery | ✅ done | — | — |
| Telemetry + enforcement + safety | ✅ done | — | — |
| Governed learning lifecycle (mechanics) | ✅ done | — | — |
| Benign generalisation (AUTH A4, network NV2) | ✅ **proven** | — | — |
| Dashboard, docs, reproducibility, automation | ✅ done | — | — |
| **Attack runs (web + network families)** | ❌ **blocked** | 3 test + 1 validation run per family from ATK01 | **team** |
| Five-way comparison (static/supervised/novelty/frozen-hybrid/adaptive-hybrid) | ❌ blocked | run after attack data exists | agent (after team) |
| Supervised RF-vs-ARF real-attack eval | ❌ blocked | run after attack data | agent (after team) |
| Withheld-family (§8) new-threat experiment | ❌ blocked | run after attack data | agent (after team) |
| Network-attack recall | ❌ blocked | measure detector on scan/SSH runs | agent (after team) |
| One governed promotion (if a candidate qualifies) | ❌ blocked | needs attack-recall data + human approval | team + agent |
| Final team demonstration (`FINAL_DEMO.md`) | ⚠️ ready | team runs and can explain it | team |

**The single thing that unblocks everything else:** the authorized team runs the attack
scenarios from ATK01 (`docs/TEAM_ATTACK_QUICKSTART.md` — harness, allowlist, watchdog and
tools are all in place). Why not the agent: generating attack traffic is a safety-enforced
boundary that stopped the attempt this session; it is not circumvented or faked.

### Exact next steps once attack data exists (agent does all of these)
1. `afwc dataset capture/validate` each run (ground-truth labels from the journal).
2. `afwc experiment evaluate --datasets <runs> --streaming` → recall, FPR, containment,
   latency, CIs for every arm (the five-way comparison → **Gate B, E**).
3. `afwc experiment supervised --train … --test …` and `--withhold content_discovery
   --introduce …` → supervised + new-threat results.
4. Check `/api/network` during scan/SSH runs → network-attack recall.
5. If a candidate then qualifies, one human-approved promotion + live probation →
   **Gate C**.
6. Team runs `FINAL_DEMO.md` → **Gate G**. Update `RESULTS.md`, this file, and the matrix.

### Optional hardening the agent can do now (no attack traffic)
- Apply the FW01 Suricata memcap mitigation so heavy captures don't OOM the IDS.
- Investigate the post-reboot `net_dns=0` observation under a fuller benign load.
- Push the branch (only on request).

---

## 8. Can it be presented as a strong final-year project now?

**Yes, with honest framing.** It is a genuinely engineered, safety-first adaptive security
system on real infrastructure, with verified enforcement, a governed learning lifecycle,
and a rigorous **predeclared** experimental methodology that produced both negative and
(now) positive results without fabrication. That demonstrates real engineering and
scientific maturity.

**What it cannot yet claim:** that the AI detects real attacks better than static rules, or
that it safely learns new ones — those are measured, not asserted, and the measurement
needs the team's attack runs. A negative result there would still be a valid FYP outcome;
what matters is that it is measured honestly.

**Bottom line:** ~75% complete and defensible today; the remaining ~25% is one afternoon of
authorized team attack runs plus the agent's downstream evaluations. After that, every gate
is either MET or has a real, reported measurement.

---

## 9. Where everything is

| Topic | File |
|---|---|
| Single status page | `docs/PROJECT_STATUS.md` |
| Per-criterion evidence | `docs/VALIDATION_MATRIX.md` |
| Milestone detail | `docs/engineering/AUTONOMOUS_PROGRESS.md` |
| Decisions (ADR-001…044) | `docs/ARCHITECTURE_DECISIONS.md` |
| Results | `docs/RESULTS.md` (§3b P6, §3c P7, §3d A3, §3e NV1, §3f NV2, §3g A4) |
| AUTH protocols | `docs/engineering/A3_AUTH_CONTROLS.md`, `A4_AUTH_HOUSEHOLD_REVALIDATION.md` |
| Network novelty | `docs/engineering/NV1_…`, `NV2_NETWORK_NOVELTY_REVALIDATION.md` |
| Sensor/pf decision | `docs/engineering/SENSOR_EXPANSION_DECISION.md` |
| Team attack runs | `docs/TEAM_ATTACK_QUICKSTART.md`, `engineering/P3_TEAM_ATTACK_RUNBOOK.md` |
| New-threat experiment | `docs/NEW_THREAT_EXPERIMENT.md` |
| Full prior report | `docs/PROJECT_REPORT_2026-10-29.md` |
| Automated verification | `scripts/final_verification.sh` |
| Evidence | `artifacts/evidence/` (a3-, a4-, nv1-, nv2-, sensor-expansion-, dashboard-, live-governance-, fw01-ids-oom-, final-verification-, p6-, p7-, n1-, n7-, …) |
