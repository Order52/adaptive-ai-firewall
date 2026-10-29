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
| 2 | **Offline recorded-attack detection** | **PENDING → see §Offline** | External CIC-IDS2017 PCAP, Suricata offline (-r), our feature pipeline. Provenance-labelled; strictly separate from gate 1 | The full-day run completes (this session) |
| 3 | **Supervised malicious-behaviour learning** | **PENDING → see §Offline** | RandomForest + River ARF on CIC network features, ground truth by attacker IP. Domain-adaptation caveat (CIC ≠ lab) | Offline run completes; live relevance needs lab-domain labelled data (team) |
| 4 | **Unfamiliar-threat (novelty) detection** | **PARTIAL** | Benign side proven: NV2 one-shot test 0.0059 FPR on unseen lab users (`RESULTS.md` §3f). Offline held-out-family (FTP↔SSH) test pending. Live attack recall BLOCKED (gate 1) | Offline held-out-family result; then live recall from team runs |
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

## Offline (gates 2/3/4 partial) — results

*(Filled when the CIC-IDS2017 full-day run completes. Methodology:
`artifacts/evidence/offline-cic-2026-10-29/README.md`.)*
