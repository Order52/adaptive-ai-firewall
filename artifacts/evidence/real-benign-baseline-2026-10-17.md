# Real-data evidence — benign baseline (2026-10-17)

First AI model/profile trained on **genuine lab traffic** (not synthetic fixtures),
with live inference verified on CTRL01. Benign-only: attack recall is out of scope
until team-supplied attack traces exist (see `docs/EXPERIMENTS.md`).

## Traffic (real)

- Generator: `traffic/benign_personas.py` — legitimate user journeys (browse, read
  reviews, valid login with occasional corrected typo, view/make booking, review,
  logout) from real client source IPs on USR01 → WAF (OWASP CRS) → APP01.
- Sources: 10.77.20.10–15 (6 real client IPs in the USERS zone).
- Pipeline verified: WAF/app/IDS telemetry → CTRL01 → correlated feature windows.

## Datasets (captured on CTRL01, SHA-256 integrity-checked)

| dataset | purpose | observations | windows |
|---|---|---|---|
| real-benign-train2 | train | 2464 | 361 |
| real-benign-val | validation | 1049 | 154 |
| real-benign-train | held-out test (benign) | 1306 | 191 |

## Trained profile (real)

- Trusted profile **v2** (`b4a83e64fc22`), 361 real training windows, 6 sources.
- Promoted over the earlier synthetic demo profile; controller reloaded; strategy=ml.
- Models (fit on real train, thresholds chosen on real validation at 1% FP budget):

| detector | threshold | validation FPR | scoring latency | size |
|---|---|---|---|---|
| robust_stats (M1) | 3.5278 | 1.30% | ~14 µs | 510 B |
| isolation_forest (M2) | 0.6273 | 1.30% | ~11.4 ms | 566 KB |
| half_space_trees | 0.8065 | 1.30% | ~57 µs | 391 KB |

Gate checks: train_windows 361 ✓, train_sources 6 ✓, validation_benign_windows 154 ✓,
per-detector validation FPR ≤ 2× budget ✓. recall = null (no attack data — honest).

## Live inference verification (post-promotion, held-out fresh benign)

Fresh benign traffic scored against the real profile v2 on CTRL01:

| source | risk | band | robust_stats | isolation_forest |
|---|---|---|---|---|
| 10.77.20.10 | 0.0 | none | 1.449 / 3.528 | 0.456 / 0.627 |
| 10.77.20.11 | 0.0 | none | 0.417 / 3.528 | 0.375 / 0.627 |
| 10.77.20.12 | 0.0 | none | 2.023 / 3.528 | 0.506 / 0.627 |
| 10.77.20.13 | 0.0 | none | 1.390 / 3.528 | 0.505 / 0.627 |

**Zero false positives** — every detector score below threshold (vs the synthetic
profile, which falsely flagged this same real traffic as "elevated").

## M0/M1/M2 replay on held-out real benign run (real-benign-train, 191 windows)

| arm | FPR | legit success | detect latency | scoring latency |
|---|---|---|---|---|
| M0 static | 0 | 100% | — | — |
| M1 statistical | 0 | 100% | — | ~63 µs |
| M2 ML-assisted | 0 | 100% | — | ~11.9 ms |

No benign source was ever restricted by any arm; the honest cost difference is M2's
Isolation-Forest scoring (~11.9 ms) vs M1 (~63 µs). Attack recall across arms is
**BLOCKED** on attack traces; the runner produces those numbers unchanged once the
data exists.

## Scenario C (legitimate drift → controlled learning) — partially demonstrated

A genuine drift→adapt→recover cycle was observed live during this work:

1. **Baseline**: synthetic profile v1 was trusted.
2. **Legitimate behaviour change**: real users exercised routes the v1 baseline
   lacked (`/cars/{id}/reviews`, `/logout`, `/reviews`) at different rates.
3. **Drift detected**: the controller raised drift reports
   `new_endpoint, feature_shift · population (6 sources)` — population-level, i.e.
   consistent with legitimate change, not a concentrated/suspicious source.
4. **Candidate + anti-poisoning gate**: candidate profile v2 was built from the
   reputation-gated benign traffic; the evaluation gate passed (6 independent
   sources, no single source dominating — attacker traffic could not define normal).
5. **Reviewed promotion**: v2 promoted via the admin API (human-in-the-loop).
6. **Recovery**: the same legitimate users now score risk 0 / band none.

This exercises the real adaptation lifecycle. The textbook variant (an explicit app
`/booking` **v1→v2** change) would re-run multi-source benign traffic under the new
app version; the mechanism is identical and already verified above.

## Reproduce

Benign generation + capture + train + promote + replay commands are in
`docs/SESSION_HANDOFF.md` and `docs/EXPERIMENTS.md`.
