# Separated gate states

The directive requires **distinct** gate states, so results of different provenance are
never conflated. Each gate below is tracked on its own evidence and can only be advanced
by evidence of its own kind. **An offline recorded-PCAP result can NEVER advance the live
GNS3 gate**, and vice versa.

Legend: **MET** (evidence exists) · **PARTIAL** · **BLOCKED** (needs something outside
this agent's authority) · **PENDING** (run in progress / scheduled).

Last updated 2026-10-29.

| # | Gate | State | Evidence / basis | What would advance it |
|---|---|---|---|---|
| 1 | **Live GNS3 attack detection** | **BLOCKED** | No in-lab attack traffic exists; generating it is a safety-enforced boundary for this agent (fired this session). Harness/allowlist/watchdog ready (`TEAM_ATTACK_QUICKSTART.md`) | The authorized team runs the scenarios from ATK01; then the agent runs `experiment evaluate` |
| 2 | **Offline recorded-attack detection** | **MET (offline)** | CIC-IDS2017 Tuesday: RandomForest recall **0.846** at **0 FPR** on real brute force (§Offline). Separate from gate 1 | — (maintained); live relevance = gate 1 |
| 3 | **Supervised malicious-behaviour learning** | **MET (offline), family-specific** | Brute force RF 0.846; but cross-family only 0.11 and within-Friday 0.27 (`OFFLINE_INDEPENDENCE.md`). Self-learning on independent family 0→≈0.68 (10 seeds); retention requires rehearsal (`ERRATUM_FORGETTING.md`). Batch≈incremental | Lab-domain labelled data (team) |
| 4 | **Unfamiliar-threat (novelty) detection** | **PARTIAL** | Benign: NV2 0.0059 FPR on unseen lab users. Offline held-out family: FTP→SSH recall 0.992 but SSH→FTP 0.0 (asymmetric, §Offline). Live attack recall BLOCKED (gate 1) | Live recall from team runs |
| 5 | **Safe adaptation & promotion** | **PARTIAL** | Governed lifecycle live; promotion **gate exercised live and correctly refused** an unqualified challenger (`live-governance-2026-10-29/`); poison-resistant admission, checkpoints, crash-consistent rollback (M3/M4 tests). **No gate disabled.** No promotion (needs attack recall + human) | A candidate qualifies (needs attack recall) + human approval |
| 6 | **End-to-end network enforcement** | **MET** | Read-back-verified OPNsense/WAF actions, expiry, protected-address refusal shown live, shared-address guard; isolation 41/41; live lab 14/14 | — (maintained) |

## Why gates 1 and 2 must stay separate

- **Gate 1 (live GNS3)** answers: does the deployed system, on its own lab traffic,
  detect and contain attacks executed through FW01 → WAF01 → APP01? That needs real
  packets on the lab wire from ATK01.
- **Gate 2 (offline recorded)** answers: does our *feature + model pipeline*, fed real
  recorded attack traffic from a public dataset, separate attack from benign? It transmits
  no packets and runs on a different network population (CIC-IDS2017), so it cannot speak
  to the lab's live behaviour.
- Conflating them would let external data masquerade as a lab result — exactly what the
  directive forbids.

## Offline (gates 2/3/4) — results

**CIC-IDS2017 Tuesday, full day** (11 M packets, 2017-07-04; 294,866 Suricata flow events).
Attacker `172.16.0.1` (Kali): 35,745 flows to FTP (port 21) + 5,959 to SSH (port 22) —
FTP-Patator + SSH-Patator brute force. 13,784 per-source 30 s windows (285 attack: 159
FTP + 126 SSH; 13,499 benign). Our production feature pipeline, labelled by attacker IP.
Evidence: `artifacts/evidence/offline-cic-2026-10-29/cic-offline-results.json`.

| Model | Setup | Recall | Precision | FPR |
|---|---|---|---|---|
| **RandomForest** | batch, time-aware split (train past, test future) | **0.846** | 1.00 | **0.00** |
| **River ARF** | prequential (predict-before-learn on the stream) | **0.775** | 1.00 | **0.00** |
| River ARF | frozen snapshot, batch split (no learning on test) | 0.00 | — | 0.00 |
| NetworkNovelty (unsupervised) | calibrated on CIC benign (domain-adapted) | 0.937 | 0.39 | 0.038 |

**Held-out attack family (cross-protocol generalisation, frozen RF):**

| Train | Test (withheld) | Recall | Benign FPR |
|---|---|---|---|
| FTP-Patator | **SSH-Patator** | **0.992** | 0.00 |
| SSH-Patator | FTP-Patator | 0.00 | 0.00 |

### What this shows (gates 2, 3, 4 — offline only)
- **Gate 2 (offline recorded-attack detection): supported.** RandomForest 0.846 recall
  (95% CI [0.78, 0.90]) at **0 FP on 13,499 benign windows** (Wilson upper ~0.0003 — not
  "zero FP" in general). **Audited** as behaviour-driven, not host/port-identity leakage
  (`OFFLINE_CIC_AUDIT.md`).
- **Gate 3 (supervised malicious-behaviour learning): supported; RF and ARF comparable.**
  RF 0.846 @ 0 FPR; a fairly-trained incremental ARF ~0.92-0.98 (`OFFLINE_CIC_AUDIT.md`).
  The earlier "frozen ARF 0.0" was a **data-ordering artifact** (attack in one late burst),
  not evidence that continuous learning is superior — with representative ordering ARF
  matches RF. No superiority claim.
- **Gate 4 (unfamiliar-threat): partial.** A model trained on FTP brute force detects
  withheld SSH at 0.99; SSH->FTP is 0.66 (behaviour-only; the earlier 0.0 was a
  port-feature artifact, `OFFLINE_CIC_AUDIT.md`). This is **cross-protocol generalisation
  within brute force on one dataset — NOT universal zero-day detection.** Unsupervised
  novelty 0.94 @ 3.8% FPR.

### Domain-adaptation assessment (P5) — external → lab relevance
These results are **CIC-specific** and do **not** transfer to our GNS3 lab as-is:
- **Different benign population:** CIC is a university network (varied hosts/services);
  our lab is a car-rental web app with scripted personas. Benign feature distributions
  differ, so a CIC-calibrated detector (e.g. the novelty's 3.8% FPR here) would not hold
  on lab traffic, and vice-versa.
- **Different attack realisation:** CIC FTP/SSH Patator vs the lab's `net-ssh-guessing` —
  related but not identical flow shapes.
- **What would make it lab-relevant:** (i) re-calibrate/re-train on lab benign; (ii)
  per-feature normalisation; (iii) ideally fine-tune on lab attack captures (team runs).
Until then this is **external evidence that the pipeline and models work on real recorded
attack traffic** — it strengthens confidence in the design, but **cannot** advance gate 1
(live GNS3).
