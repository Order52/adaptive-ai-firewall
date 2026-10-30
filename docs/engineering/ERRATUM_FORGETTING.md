# Erratum: "no forgetting" was not demonstrated

Written 2026-10-30. **Several earlier documents said the incremental learner learns a new
attack family "without forgetting" the old one. That claim was not supported. This page
states what was wrong, what the controlled measurement shows, and what changes.**

Evidence: `artifacts/evidence/offline-cic-2026-10-29/cic-forgetting-seeds.json`
(`cic_forgetting_seeds.py`) and `cic-poison-rollback.json` (`cic_poison_rollback.py`).
Separate offline gate; nothing here concerns the live GNS3 lab.

## 1. What was wrong

The earlier self-learning demos (`cic_selflearn.py`, `cic_selflearn_matrix.py`,
`cic_friday_eval.py`) reported "retention" of the old family (SSH 0.94 → 0.98; Tuesday
brute force 1.0 → 1.0). Two flaws:

1. **Measured on training data.** The base model had been trained on those same windows
   (attack windows oversampled ×20). High recall on windows a model has memorised is not
   retention; it says nothing about unseen examples of the old family.
2. **One seed, one stream order.** An incremental forest is order-sensitive. A single run
   cannot show that forgetting does not occur.

## 2. Controlled measurement

Setup: the old family (Tuesday brute force) and the new family (Friday attacks) are each
split in time; learn = past, test = future. An **immutable anchor** (3,000 benign windows,
114 held-out old-family attack windows, 32 held-out new-family attack windows) is fixed
before any learning and never used for it. Behaviour-only features. **10 seeds** (stream
order and forest seed). Mean ± sd [min, max]:

| Strategy | Benign FPR | Old-family recall (held-out) | New-family recall (held-out) |
|---|---|---|---|
| Champion (before learning) | 0.000 | 0.925 ± 0.035 | 0.009 ± 0.030 |
| Incremental ARF, **no rehearsal** | 0.007 | **0.776 ± 0.357** [**0.08**, 1.00] | 0.659 ± 0.145 |
| Incremental ARF, **with rehearsal** | 0.008 | **0.999 ± 0.003** | 0.678 ± 0.132 |
| Periodic batch RF (refit from scratch) | 0.000 | 0.917 ± 0.006 | 0.450 ± 0.047 |

Cost (mean wall-clock to learn / refit; model size): incremental no rehearsal 0.47 s,
incremental with rehearsal 1.79 s, batch RF 0.29 s; ARF 3.0 MB, batch RF 0.44 MB.

## 3. What this shows

- **Incremental learning without rehearsal is unsafe.** Across seeds the old-family recall
  ranges from 1.00 down to **0.08**: catastrophic forgetting happens in some orderings and
  not others. The earlier single run happened to be on the benign side of that spread (and
  was measured on training data anyway).
- **Rehearsal controls it.** Replaying old-family windows while learning the new family
  keeps old-family recall at 0.999 and still reaches 0.68 on the new family.
- **It is a trade-off, not a win over batch.** Rehearsal gives a higher new-family recall
  than batch retraining (0.68 vs 0.45) but with a small false-positive cost (0.8 % vs
  0.0 %), about 6× the compute and 7× the memory. Batch retraining is more stable and
  cheaper here. **No claim that online learning is superior.**
- **The new-family gain is still real but modest and conditional**: ≈ 0.66–0.68 mean on 32
  held-out windows from one Friday session, i.e. a handful of independent bursts.

## 4. What the production system already does
**Third capture confirms it** (`OFFLINE_THIRD_CAPTURE.md`, 10 seeds, new family = Thursday, 130 held-out windows): without rehearsal the Friday family falls 0.375 → 0.097; with rehearsal 0.572; batch RF 0.406. New-family recall 0.88 / 0.92 / 0.86 (no rehearsal / rehearsal / batch); benign FPR 0.0092 / 0.0112 / 0.0007; learn time 1.9 / 3.6 / 0.24 s.


`src/afw/ml/incremental.py` already implements the safeguard this measurement justifies:
a bounded per-family **rehearsal reservoir is on by default** (`Rehearsal`), and the
lifecycle gate **rejects a challenger whose recall on any known family drops by more than
0.05** (`max_recall_drop`) or whose benign FPR is too high. In this study the same gate
rule, applied on the immutable anchor, **rejected** the clean no-rehearsal challenger
(old-family recall 0.91 → 0.16). So the design was right; the offline demo that omitted
rehearsal and mis-measured retention was wrong.

## 5. Safeguards exercised on real windows (same experiment family)

| Safeguard | Result |
|---|---|
| Immutable evaluation anchor | fixed and hashed before learning (sha256 `37e34074…`) |
| Challenger isolation | champion unchanged after all challengers (verified) |
| Persistence | checkpoint (sha256 `a8577a33…`) reloads with identical predictions on 600 probe windows |
| Rollback | after a deliberately destroyed challenger (benign FPR 1.0), reloading the verified checkpoint restores the champion's metrics exactly |
| Provenance gate vs false-positive injection | 100 / 400 benign windows injected labelled attack from an unverified source: naive admit-all → benign FPR **0.72 / 0.98**; with the provenance gate the injected labels are dropped and FPR returns to the clean value (0.019); the anchor gate also rejects the naive challengers |
| Label-flip poisoning (attack → benign) | **not** stopped by provenance when the flipped labels carry verified provenance (insider/mislabel case); it is only caught if the anchor gate sees a regression. Residual risk, stated |

## 6. Corrections applied

Every document that claimed "no forgetting" now points here:
`FINAL_REPORT.md`, `ARCHITECTURE_VS_GOALS.md`, `COMPLETE_DOSSIER.md`, `RESULTS.md` §3h,
`STATUS_LIMITATIONS_FIXES.md`, `engineering/GATE_STATES.md`,
`engineering/REVISED_ASSESSMENT.md`, `engineering/OFFLINE_INDEPENDENCE.md`.
