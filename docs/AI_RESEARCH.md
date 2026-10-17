# AI research notes

## Status

No experimental results exist yet. Everything below is method; numbers will be
added only from captured GNS3 lab runs.

The **offline replay runner that will produce those numbers is now built**
(`src/afw/ml/experiments.py`, `afw experiment replay`). It consumes a labeled
`DatasetManifest` + observations and compares the three arms below through the
same live pipeline, at the same trained false-positive budget, on the identical
replayed stream. It is correctness-tested on the synthetic fixture only; it has
not been run on real data because none has been supplied. See
`docs/IMPLEMENTATION_STATUS.md` item 3.

### Evaluation arms and what the runner measures

| Arm | Strategy | Detectors | Models |
|---|---|---|---|
| M0 | static | none (firewall + WAF + IDS only) | — |
| M1 | statistical | robust-stats (M1) | behavioural |
| M2 | ml | robust-stats + Isolation Forest | behavioural |

Per arm: window-level precision / recall / FPR / F1 on the controller's
traffic-affecting action; source-level containment (incl. the WAF-inline floor
every arm inherits); legitimate-request success; first-observation→first-action
detection latency; and mean/p95 detector scoring latency (the M1-vs-M2 cost
trade-off). Ground-truth labels are read only here, never by the detectors.

## Features (per source × application, 30 s window, 5 s hop)

13 behavioral features (`src/afw/domain/features.py`): request rate, route count/entropy,
unknown-route share, novel-method share, write share, 4xx/5xx shares, login rate,
login failure share, distinct usernames, p95 request size, inter-arrival CV.
WAF/IDS outputs are **evidence for correlation**, never ML inputs.

## Detectors

| Arm | Detector | Training | Threshold |
|---|---|---|---|
| M1 | Robust z (median/MAD with floors), mean of 2 largest directed deviations | profile only | benign-validation quantile at target FPR (1 %) |
| M2 | M1 + Isolation Forest (200 trees, ≤256 samples, log1p + RobustScaler) | benign TRAIN runs | same |
| comparator | River Half-Space Trees | benign TRAIN runs; shadow copy keeps learning | same |

Attributions: occlusion (score drop when a feature is reset to the profile median) — faithful to the model actually used.

## Leakage controls (enforced in code)

- Splits by whole run (`assert_disjoint`); purposes checked (`train`/`validation`/…).
- Labels only in dataset manifests; read only by `ml/evaluation.py` and `services/learning.py` gates.
- Thresholds chosen on benign validation windows; attack windows only reported.
- Live candidate builds use a time split with a one-window guard gap.

## Functional check on SYNTHETIC fixture (not a result)

`tests/integration/test_closed_loop.py` shows the loop works end to end (brute force → verified block; benign sources only got WATCH). AUC = 1.0 there reflects a trivially separable synthetic attack and must not be cited.

## Open questions for the lab evaluation

- Does IF improve on robust stats at equal FPR on held-out runs?
- Low-and-slow / distributed behaviour falls below `min_requests` per window by design — expected miss; an application-level aggregate detector may be needed.
- Single-row IF latency (~10 ms on host) vs the 5 s enforcement target.
