# Final architecture vs original goals — rigorous comparison

**2026-10-30.** The required closing comparison: every demonstrated capability, failure,
uncertainty, and remaining blocked gate, measured against the original vision of a
**network-wide AI firewall that learns useful behavioural patterns, improves from
independently-verified new evidence, and provides measurable value beyond static rules.**
Nothing is asserted without a measurement. Offline recorded-traffic results are a
**separate gate** and never advance the live GNS3 gate. This document does **not** declare
the project complete.

Evidence: `engineering/OFFLINE_CIC_AUDIT.md`, `OFFLINE_INDEPENDENCE.md`,
`REVISED_ASSESSMENT.md`, `GATE_STATES.md`, and `artifacts/evidence/offline-cic-*/`.

---

## 1. Original goal → verdict (with the measurement)

### Goal A — Learn useful behavioural patterns (benign + malicious)

- **Benign: demonstrated on the live lab.** A4 login controls 0.0 FPR on households/shared
  addresses; NV2 network novelty 0.0059 FPR on 22 unseen users.
- **Malicious (brute force): demonstrated offline, audited as genuine behaviour.** RF 0.846
  recall, 0 FP on 13,499 benign windows; **behaviour-only features 0.85–0.90, identity-only
  0.0** (the model learns behaviour, not the host/port).
- **Failure/uncertainty:** the model is **family-specific**. Cross-family a brute-force model
  detects only **0.11** of a different day's attacks; even trained on that day, **0.27**
  (port-scan/botnet/DDoS are hard for window-level features). It is **not** a general attack
  detector.

### Goal B — Improve from independently-verified new evidence (self-learning)

- **Demonstrated offline, on genuinely independent data, but conditional.** On CIC Friday
  (different day/family/tool), a challenger learns the withheld family **0.0 → 0.72**
  (23/32, 95 % CI [0.55, 0.84]). **Correction (`engineering/ERRATUM_FORGETTING.md`):** that run did not show
  retention. Over 10 seeds on held-out data the learner *without* rehearsal is unstable
  (old-family recall 0.78 ± 0.36, down to 0.08); *with* rehearsal, as the production learner
  does, it is 0.999.
- **Crucial honest limit (new):** the improvement appears **only when the withheld family is
  genuinely novel** (base model at 0.0). For families the model already detects, learning
  adds nothing (SSH 1.0 → 1.0) or slightly **hurts** (FTP 0.83 → 0.73). So "self-learning
  improves detection" is **true for novel families, not universally**.

### Goal C — Measurable value beyond static rules

- **Demonstrated on brute-force-style activity, but smaller than first reported (#3).**
  **Correction (`engineering/ERRATUM_STATIC_BASELINE.md`):** the first static baseline put the attacker inside `HOME_NET`
  and could not match external-source rules. With a fair baseline, static Suricata (ET Open)
  detects **0.43** of the Tuesday brute force at 3.2 % false-positive windows; the supervised ML
  detects **0.895 at 0 FP**. On Thursday web attacks, with an ML model that never saw Thursday:
  static **0.28** vs ML **0.88**. ML catches 68 / 102 windows static misses, and static catches a
  few ML misses (2 / 5), so the two are **complementary** (union 0.91 on Thursday morning).
- **Failure/uncertainty:** on the **harder Friday families both are weak** (static 0.13, ML
  0.27, hybrid 0.32), so the AI's advantage is **family-dependent**. The **hybrid (ML OR
  novelty) hurts precision** (novelty false-strongs); the **supervised ML alone is the best
  single method**. Caveat: ET Open is generic/untuned.

### Goal D — Network-wide coverage of attack categories

- **Partial / with a measured limit.** Brute force: well covered. Reconnaissance (port
  scan): the concentrated scan burst is caught, but the fixed **15-ports/60 s ceiling is
  mis-tuned** — raising it to **50–100 ports detects the real scan at 0 benign FP**
  (#1/#7, offline). Low-and-slow / distributed (botnet/DDoS): **poorly covered** by
  window-level behaviour features (0.27). Non-web: flow/DNS/TLS/SSH metadata is captured and
  net_dns is confirmed working.

---

## 2. Static-strategy / learning-strategy comparison (#3, #4)

| Method | Brute-force recall | Brute-force FPR | Friday recall | Note |
|---|---|---|---|---|
| Static Suricata (ET Open, fair `HOME_NET`) | **0.43** | 0.03 (attack-cat) | 0.13 | catches about half of brute force; alerts on many benign sources; complementary to ML |
| Supervised ML (RF) | **0.895** | **0.00** | 0.27 | best single method |
| Novelty (ceilings) | 0.92 | 0.03 | 0.05 | high recall, poor precision |
| Hybrid (ML∪novelty) | 0.93 | 0.03 | 0.32 | novelty FPs hurt precision |

**Learning strategies (fair, prequential, identical data/compute):** incremental ARF recall
0.94 / precision 0.77 / FPR 0.0045; periodic batch RF recall 0.89 / precision 0.90 /
FPR 0.0016, slightly cheaper, can defer labels. **No winner.** The deployed system is a
**governed hybrid by design** — a frozen batch champion + an incremental shadow challenger +
a human-gated promotion with probation/rollback — and this comparison **justifies** that
choice (neither pure strategy dominates), rather than preferring "online" for its own sake.

## 3. Shadow integration / governance (#6)

- The **network-novelty detector runs live in shadow** (verified) and influences no decision.
- The **promotion gate runs live and correctly refuses** an unqualified challenger.
- A **supervised classifier is NOT wired into live shadow**, and should not be: none is
  validated for the **lab domain** (CIC-domain models do not transfer; benign populations
  differ). Doing so would add complexity with no validated value — contrary to the
  directive. Poisoning-resistant admission, versioning, probation and rollback are preserved
  and unit-tested.

## 4. What is uncertain

- All attack-side numbers are **CIC-domain** and do not transfer to the lab without
  re-training/re-calibration.
- Self-learning tested with **one run per family** (within-run holdout); independent
  *repeat* runs of the same family are not available in CIC Tuesday/Friday.
- The brute-force behavioural signal is partly **tool-shaped** ("no DNS + repetitive
  connections").
- Scan-threshold tuning (50–100 ports) is offline-validated on CIC benign; the lab benign
  population differs and must be re-checked (#7).

## 5. Remaining BLOCKED acceptance gates

| Gate | Status | Why |
|---|---|---|
| B Detection (live GNS3) | **BLOCKED** | needs in-lab attack traffic (safety boundary) |
| E Independent value (live GNS3) | **BLOCKED** | needs the in-lab five-way comparison |
| C Adaptation (promotion) | **PARTIAL** | gate refuses live; no qualifying candidate (needs attack recall) |
| G Academic (demo) | **PARTIAL** | team demo + in-lab attack evidence missing |

Live GNS3 attack detection stays **BLOCKED**; no live attack test has been claimed or run.

---

## 6. Does the final architecture meet the original vision?

**Partially, and now measured with independent scrutiny — not met in full, and not
declared complete.**

- **Learns useful behavioural patterns:** **yes** for benign (lab) and brute force (offline,
  audited); **family-specific**, not general.
- **Improves from independently-verified new evidence:** **yes, offline, on independent
  data** (0 → ≈0.68 over 10 seeds, old family retained at 0.999 *only with rehearsal*) — but
  **only for genuinely novel families**.
- **Measurable value beyond static rules:** **yes on brute-force-style activity** (ML 0.90 vs
  static 0.43; Thursday web attacks 0.88 vs 0.28), **complementary** to static (union is
  best), **marginal on harder families** — see `engineering/ERRATUM_STATIC_BASELINE.md`.
- **Reliable network protection + governance:** **yes, fully** (verified enforcement, guards,
  live governed refusal, recovery, OOM fix persistent across reboots).
- **Live attack effectiveness:** **unproven, blocked** by the one safety-gated step.

The honest net: the project **demonstrates real, independently-measured, but narrow and
conditional** self-learning value, on top of a **fully working, safety-first, governed
enforcement platform**. It is a credible research system with defensible positive and
negative results — **not** a finished, general, live-proven self-learning network firewall.
The gap to the full vision is (a) broader attack-family coverage (better features for
low-and-slow/distributed), and (b) the in-lab attack evidence that only the authorised team
can produce.
