# Independent-run / cross-dataset validation of the offline results

Written 2026-10-29, to answer: **does the Tuesday brute-force result generalise to
independent runs, families and conditions, or is it dataset/tool/family specific?**
Evidence: `artifacts/evidence/offline-cic-friday-2026-10-29/` (CIC-IDS2017 **Friday** —
different day, families PortScan/Botnet/DDoS, different attacker sessions) and
`offline-cic-2026-10-29/cic-batch-vs-incremental.json`. Behaviour-only features throughout.
**Separate gate from live GNS3.**

## 1. Cross-dataset generalisation — the model is FAMILY-SPECIFIC (honest)

A RandomForest **trained on Tuesday brute force**, tested on **Friday** attacks:

| Metric | Value |
|---|---|
| Recall on Friday attacks | **0.114** (95% CI [0.06, 0.20]) |
| Precision | 1.0 |
| FPR | 0.0 |

**The brute-force model does not generalise to Friday's families.** This is the correct and
expected outcome — a brute-force detector *should not* fire on port scans, botnet C2 or
DDoS. It directly refutes any idea that the model learned a "universal attack" signature:
it learned **brute-force behaviour specifically**.

## 2. Even trained on Friday, detection is WEAK — these families are hard

Train on Friday (first 60% by time), test on Friday (last 40%):

| Metric | Value |
|---|---|
| Recall | **0.267** (95% CI [0.17, 0.39]) |
| Precision | 0.889 |
| FPR | 0.0005 |

Our window-level residual-behaviour features capture brute force well (0.85) but **capture
Friday's families poorly (0.27)**. The attacker's Friday activity is bursty — a few
high-signal windows (up to 3320 flows / 997 ports) and many quiet ones (botnet beacons,
slow-scan steps) that look benign per window. Honest limitation: the feature set is not a
general attack detector.

## 3. Fixed scan ceiling MISSES a slow scan — real limitation

The shipped network-novelty scan detector flags a window "strong" at a fixed ceiling of
**15 distinct ports / 60 s** (ADR-042). On Friday's real NMAP scan (997 distinct ports, but
**spread across the afternoon**):

| Metric | Value |
|---|---|
| Friday attack windows | 79 |
| Windows reaching the 15-port/60 s ceiling | **1** |
| Attack windows flagged "strong" | 0.038 |
| Benign false-strong rate | 0.0087 |

**The fixed-ceiling scan detector misses most of a slow/spread scan**, and still has a
~0.9 % benign false-strong rate on CIC benign. Fixed ceilings catch fast scans; a slow
scan (few ports per minute) evades them. This argues for calibrated/multi-horizon scan
thresholds, not a fixed per-60 s ceiling, if scan detection is a goal.

## 4. Self-learning on a GENUINELY INDEPENDENT family — works, modestly

Challenger trained on Tuesday brute force (knows it: recall 1.0), **withhold Friday
attacks** (different day, families, tool), learn them incrementally, test on **untouched
held-out Friday windows**:

| | Withheld Friday recall | Tuesday brute-force recall (forgetting) |
|---|---|---|
| Before learning | 0.000 | 1.0 |
| After learning | **0.625** | 1.0 (no forgetting) |

This is the **strongest adaptation evidence** so far: on a **genuinely independent** capture
(different day, attack family and tool), the challenger learns the new pattern (0 → 0.625)
and does **not** forget the old one. It is **modest** (0.625, and the test holdout is within
one Friday run, not a second independent Friday run), but it is real and cross-dataset.

## 5. Batch vs incremental — comparable, no winner

Prequential stream, behaviour-only, attack oversampled (fair):

| Strategy | Recall | Precision | FPR | Train time | Memory | Labels |
|---|---|---|---|---|---|---|
| Incremental ARF | 0.942 | 0.773 | 0.0045 | 4.05 s (13,784 updates) | 382 KB | needs one per window |
| Periodic batch RF (retrain ×12) | 0.894 | 0.903 | 0.0016 | 3.41 s | 403 KB | can defer |

**No clear winner:** incremental has higher recall but lower precision / higher FPR;
periodic batch has higher precision, lower FPR, was slightly cheaper to train here, and can
defer labels. **No claim that continuous learning is superior.**

## 6. What the independent validation changes

- **Strengthened:** self-learning is real on genuinely independent data (0 → 0.625, no
  forgetting) — not a single-capture artefact.
- **Tempered:** the models are **family-specific** (cross-family 0.11); detection quality is
  **family-dependent** (brute force 0.85, Friday families 0.27); the **fixed scan ceiling
  misses slow scans**. The offline evidence is real but **narrow and modest**, and still
  CIC-domain — it does not transfer to the lab or imply universal detection.
