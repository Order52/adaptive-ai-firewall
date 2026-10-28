# P1: benign generalization of the detectors

Status: **protocol predeclared 2026-10-28 07:10Z, before the test data existed.** Sections
1–3 are fixed from here on; results are appended in §4 without changing §3.

## 1. Correction to the earlier "new users" result

`RESULTS.md` §3, `M4_ADAPTATION_EXPERIMENTS.md` §1 and several summaries said the v2
profile was tested on "six new benign client addresses" and was trained on "three runs of
about 5 minutes" (about 15 minutes). Both statements are wrong. The dataset manifests on
CTRL01 show:

| Dataset | Purpose | Time (UTC) | Sources |
|---|---|---|---|
| `real-benign-train2` (the only v2 training run) | train | 2026-10-17 19:00:50–19:06:14 (5.4 min) | 10.77.20.10–15 |
| `real-benign-val` | validation | 2026-10-17 18:56:23–19:00:03 | 10.77.20.10–13 |
| `real-benign-train` | train (unused by v2; held out) | 2026-10-17 18:51:23–18:55:58 | 10.77.20.10–13 |
| `real-drift-learn-20261027` | drift | 2026-10-27 18:03:09–18:48:09 | 10.77.20.11–16 |
| `real-drift-hold-20261027` | test | 2026-10-27 18:48:39–19:18:09 | 10.77.20.11–16 |

Five of the six "new" addresses were in the training run. The trusted v2 profile was
trained on **one 5.4-minute run, 6 addresses, 361 windows**. What did differ is the
time (ten days later) and, decisively, the workload:

| | 10-17 runs | 10-27 runs |
|---|---|---|
| generator | one process per address | one shared process cycling 6 addresses |
| requests per source per minute | 71–76 | 13 |

So the 10-27 result is a **workload shift on the same population**, not evidence about
unseen users. Unseen-user generalization had not been measured at all. The numbers
themselves (FPR 0.13 / 0.72 / 0.64) stand; only their interpretation changes.

## 2. Diagnosis of the 10-27 false positives

Evidence: `artifacts/evidence/p1-2026-10-28/p1-fp-diagnosis.json` (script
`p1_diag_fp.py`; frozen v2 detectors, all hopped windows, so these rates are per hopped
window, not the tumbling rates of `RESULTS.md`).

| Dataset | Req/source/min | Robust | IF | HST |
|---|---|---|---|---|
| real-benign-train2 (training) | 76 | 0.000 | 0.017 | 0.031 |
| real-benign-val | 72 | 0.013 | 0.013 | 0.013 |
| real-benign-train (held out, same day) | 71 | 0.010 | 0.026 | 0.021 |
| real-drift-learn (10-27) | 13 | 0.165 | 0.557 | 0.493 |
| real-drift-hold (10-27) | 13 | 0.131 | 0.546 | 0.500 |

Occlusion (which single feature, reset to the training median, removes most of the
score) on the flagged 10-27 windows: robust stats `interarrival_cv`, `auth_fail_frac`;
IF `interarrival_cv`, `distinct_usernames`, `req_rate`; HST `route_count`. These are all
rate- and timing-shaped features that a slower request cadence changes (fewer routes per
window, burstier inter-arrival times, fewer usernames per window).

Decision-level replay under the current code: on `real-benign-val` and
`real-benign-train` no benign source is restricted (no pipeline regression); on
`real-drift-hold` the M2 arm restricts benign sources (FPR 0.156, legitimate request
success 0.865) and M1 none.

Conclusion, tested in §3: the cause is **training data that covers one workload
intensity**, exposed through rate and timing features. It is not a threshold that is
merely too tight: the rates on the 10-17 held-out run are at target. The robust
statistics degrade far less than the two ML detectors.

## 3. Predeclared protocol

Nothing below changes after the test data has been looked at. Thresholds come only from
the existing bootstrap calibration on validation data (`target_fpr` 0.01).

### Data (all real, benign, authenticated telemetry from USR01; one process per user)

Generator: `traffic/benign_personas.py`, `AFW_MODE=personas`. Each user is one thread
with a persona drawn from its seed: think-time multiplier, browsing depth 1–4, login
probability 0.2–0.95, typo rate 0–0.15, booking and review propensity, inter-session gap
in {2, 8, 30, 90} s, and its own account.

| Dataset | Users (addresses) | Seed | When | Role |
|---|---|---|---|---|
| `p1-train` | 16 (10.77.20.21–36) | 101 | Phase A, 45 min | training |
| `p1-val` | 8 (10.77.20.37–44) | 202 | Phase A, same period | threshold calibration |
| `p1-test` | 16 **unseen** (10.77.20.45–60) | 303 | Phase B, later, 30 min | primary test |
| `p1-shift` | 6 (10.77.20.61–66), `AFW_MODE=shared` (the 10-27 workload) | 404 | Phase B, same period | workload-shift test |
| `real-drift-hold-20261027` | 6 | — | 2026-10-27 | second shift test |
| `real-benign-train` | 4 | — | 2026-10-17 | old-regime regression test |

Addresses never overlap between train, validation and test. Test runs are later in time
than training. Holdout windows are tumbling (non-overlapping) per source.
`real-drift-hold` was inspected for the §2 diagnosis of **v2**; it is never used for any
v3 decision.

A first Phase A attempt (06:31–06:36Z) was cut short when an unattended host package
upgrade restarted the GNS3 server and stopped every VM. Its data is not used
(`phaseA-attempt1-aborted-times.txt`, `lab-outage-2026-10-28.log`).

### Models

* **v2**: the trusted profile (frozen, as deployed).
* **v3**: `afw train bootstrap --train real-benign-train2,p1-train --val real-benign-val,p1-val`
  (seed 42). A CANDIDATE only; it is **not promoted** by this work, because bootstrap has
  no attack-recall check and no labelled attack runs exist (Gate B).
* **v3-6u** (data-size ablation): the same, with `p1-train` restricted to 6 users
  (10.77.20.21–26) at the same duration.

`real-drift-learn` is deliberately **not** in v3's training data, so `p1-shift` and
`real-drift-hold` remain true workload-shift tests.

### Measurements

`afw experiment benign-generalization` (`src/afw/ml/benign_generalization.py`), per
profile version, detector and dataset, each with its denominator:

* window FPR on tumbling windows, 95 % bootstrap CI over sources;
* users with at least one flagged window / users; median and max per-user rate;
* requests inside flagged windows / requests;
* decision level (M0/M1/M2 replay): benign sources restricted, benign requests impacted,
  legitimate request success.

Sensitivity (no attack data exists, so probes only): per detector, per sensitive feature,
probe flag rate on `p1-test` windows that both v2 and v3 score normal
(`matched_sensitivity`, ADR-034).

### Success criteria for v3 (all on `p1-test` unless stated)

1. every detector: tumbling-window FPR ≤ 0.02 (2 × target) and upper 95 % CI ≤ 0.05;
2. M2 arm: no benign source restricted, legitimate request success ≥ 0.99;
3. old regime (`real-benign-train`): every detector FPR ≤ 0.02;
4. sensitivity: on matched windows, for every detector and sensitive feature, v3 probe
   flag rate ≥ v2 − 0.05, with at least 30 matched windows.

`p1-shift` and `real-drift-hold` are reported against the same thresholds, but they are
**secondary**: failing them means the workload-shift problem is not solved by user
diversity alone, and is reported as such.

Cause attribution:

* v3-6u vs v3 on `p1-test` → effect of the number of users at a fixed duration;
* occlusion drivers of any remaining v3 false positives → feature families;
* robust stats vs IF/HST → model family.

### Not done

* No threshold is tuned on any test set. If v3 fails a criterion, the failure is reported.
* The P2 question of capping a challenger's calibrated threshold at the champion's
  (`M4_ADAPTATION_EXPERIMENTS.md` §2) is not decided here.

## 4. Results

Pending (Phase B and evaluation).
