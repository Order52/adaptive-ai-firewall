# P1: benign generalization of the detectors

Status: protocol predeclared 2026-10-28 07:10Z, before the test data existed (commit
`db1153d`). Sections 1–3 are unchanged since; results in §4. **Outcome: the v3 candidate
removes almost all false positives on unseen users but fails the predeclared
sensitivity criterion, so it is not promoted.**

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
`real-drift-hold` the M2 arm restricts 5 of 6 benign sources (window FPR 0.156;
legitimate request success 0.861 with each request counted once, 0.865 under the
earlier per-window count, see §4) and M1 none.

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

## 4. Results (2026-10-28)

Data actually collected (one process per user, authenticated telemetry):

| Dataset | Users | Window (UTC) | Sessions | Observations |
|---|---|---|---|---|
| `p1-train` | 16 | 06:44:25–07:29:25 | 3809 | 28157 |
| `p1-val` | 8 | same | 961 | 7908 |
| `p1-test` | 16 unseen | 07:38:19–08:08:19 | 1426 | 10216 |
| `p1-shift` | 6, shared generator | same | 410 | 2393 |

Candidates (bootstrap, seed 42, thresholds at target FPR 0.01 on validation; **not
promoted**): **v3** = `real-benign-train2` + `p1-train` (22 sources, 4865 windows);
**v4** = the v3-6u ablation (`p1-train-6u`, 12 sources, 2255 windows).

Evidence: `artifacts/evidence/p1-2026-10-28/p1-eval.json` (full report),
`p1-eval-table.txt`, `p1-fp-drivers.json`, `p1-exploratory-sensitivity.json`.

### 4.1 Primary test: 16 unseen users (`p1-test`, 569 tumbling windows)

Detector false-positive rate per tumbling window (95 % CI over users); users with any
flagged window; requests inside flagged windows.

| Detector | v2 (trusted) | v3 | v4 (6 users) |
|---|---|---|---|
| Robust stats | 0.158 [0.079, 0.240]; 13/16 users; 1515/8775 req | **0.000**; 0/16; 0/8775 | 0.007 [0, 0.018]; 3/16 |
| Isolation Forest | 0.550 [0.412, 0.706]; 16/16; 2726/8775 | **0.044** [0.021, 0.078]; 11/16; 107/8775 | 0.037 [0.015, 0.067]; 9/16 |
| Half-Space Trees | 0.591 [0.442, 0.733]; 15/16; 3314/8775 | **0.021** [0.007, 0.041]; 7/16; 104/8775 | 0.023 [0.007, 0.045]; 7/16 |

Decision level (the controller's actual proposals in replay; requests counted once each):

| | v2 | v3 | v4 |
|---|---|---|---|
| M2: users rate-limited or blocked | **13/16** | **0/16** | 0/16 |
| M2: legitimate requests impacted | 2132/10216 (success 0.791) | 0/10216 (1.000) | 0/10216 (1.000) |
| M1 (statistical only) | 0/16 restricted | 0/16 | 0/16 |

### 4.2 Shift and regression sets

| Set | Detector | v2 | v3 | v4 |
|---|---|---|---|---|
| `p1-shift` (204 win.) | RS / IF / HST | 0.108 / 0.691 / 0.657 | 0.005 / 0.103 / 0.029 | 0.049 / 0.074 / 0.034 |
| | M2 users restricted | 6/6 (success 0.826) | 0/6 (1.000) | 1/6 (0.980) |
| `real-drift-hold` (193) | RS / IF / HST | 0.130 / 0.715 / 0.637 | 0.021 / 0.098 / 0.031 | 0.078 / 0.083 / 0.036 |
| | M2 users restricted | 5/6 (0.861) | 0/6 (1.000) | 2/6 (0.981) |
| `real-benign-train` (34, old regime) | RS / IF / HST | 0.029 / 0.088 / 0.059 | 0.176 / 0.029 / 0.029 | 0.118 / 0.029 / 0.000 |
| | M2 users restricted | 0/4 | 0/4 | 0/4 |

The old-regime set has only 34 tumbling windows (one window = 0.029), so criterion 3
is coarse. v2's own rates there are 0.03–0.09 per tumbling window; the earlier
"0 FPR" headline was decision-level, not detector-level.

### 4.3 Sensitivity (criterion 4, predeclared)

Probe flag rates on `p1-test` windows that v2 and v3 both score normal (probe values from
v2's profile, as predeclared):

| Detector (matched windows) | auth_fail | client_err | usernames | login_rate |
|---|---|---|---|---|
| Robust stats (479), v3 / v2 | 0.745 / 0.990 | **0.010 / 1.000** | 1.000 / 0.998 | 1.000 / 1.000 |
| Isolation Forest (256) | **0.016 / 0.606** | 0.000 / 0.152 | 0.004 / 0.039 | 0.000 / 0.039 |
| Half-Space Trees (232) | **0.013 / 0.608** | **0.000 / 0.746** | 0.035 / 0.099 | 0.043 / 0.272 |

### 4.4 Verdict against the predeclared criteria

| # | Criterion | v3 | |
|---|---|---|---|
| 1 | each detector FPR ≤ 0.02 and upper CI ≤ 0.05 on `p1-test` | RS 0.000 ✓; HST 0.021 (upper 0.041) ✗ by 0.001; IF 0.044 (upper 0.078) ✗ | **fail** |
| 2 | M2: no user restricted, success ≥ 0.99 | 0/16, 1.000 | **pass** |
| 3 | old regime: each detector ≤ 0.02 | RS 0.176, IF 0.029, HST 0.029 | **fail** |
| 4 | matched probe sensitivity ≥ v2 − 0.05 | fails for 8 of 12 detector-feature pairs | **fail** |

**v3 is not acceptable as a champion**, and the gate would not be asked: it stays a
CANDIDATE. Nothing was retuned after these results.

### 4.5 Cause attribution

* **Data, not thresholds.** The same detectors, thresholds chosen by the same
  procedure, go from 13/16 to 0/16 restricted users when trained on 45 minutes of
  varied personas instead of 5.4 minutes of one generator. Raising v2's thresholds
  would not have been equivalent: its IF/HST flag 55–59 % of unseen users' windows, so
  any threshold that cleared them would sit far above its validated operating point.
* **Diversity of behaviour, not head count.** v4 (6 users) and v3 (16 users) have
  nearly the same unseen-user FPR (IF 0.037 vs 0.044, HST 0.023 vs 0.021), so at a
  fixed duration the number of training users mattered little. What the personas add is
  variation in cadence, depth, login use and account use.
* **Features.** v2's false positives on unseen users are driven by `distinct_usernames`
  (IF: 151 of 313 flagged windows), `route_count` (HST: 262 of 336) and
  `interarrival_cv` (robust stats: 62 of 90). The v2 training generator logged into
  4–7 accounts per address per window, which no real single user does, so a normal
  one-account user looked anomalous. v3's few remaining false positives are driven by
  `client_err_frac` (IF 18 of 25, HST 10 of 12): legitimate typos and errors.
* **Model family.** Robust statistics degrade least everywhere (v2) and are 0 with v3;
  Isolation Forest is the most data-hungry detector in this feature space.
* **The sensitivity loss is the other side of the same coin.** v2 flags small changes
  in `client_err_frac` (training range 0.22–0.29) and `auth_fail_frac` because its
  training data barely varied; that is also why it flagged most real users. v3 learned
  that legitimate users range up to about 0.4 and 0.5, so the predeclared probes (0.58
  and 0.67) are no longer far outside normal for IF and HST.

### 4.6 Exploratory (post hoc, not a criterion)

To see what the sensitivity loss means for real attacks, the matched comparison was
repeated with attack-sized values fixed before looking: fractions 1.0, 20 usernames,
60 logins per window, and all four together (a credential-attack-shaped window).
Robust statistics flag 100 % of every probe for v2, v3 and v4. With all four features
together, IF and HST flag 100 % for v3 (v2: IF 0.754, HST 1.000). Single-feature probes
remain much weaker for v3's IF and HST (e.g. IF `auth_fail_frac`=1.0: 0.043 vs 0.606).
This suggests v3 would still catch credential attacks through robust statistics and
combined anomalies, but loses single-signal subtlety in the ML detectors. **Only real
labelled attack runs can settle this (Gate B, `P3_TEAM_ATTACK_RUNBOOK.md`).**

### 4.7 What this means

* The project's most important negative result (v2 harms legitimate users) is
  explained and, on the benign side, fixed by data: training on varied realistic users
  removes the harm on unseen users and under the workload shift.
* It is **not** fixed without cost: the ML detectors lose sensitivity to moderate
  single-feature changes. Whether that is acceptable depends on attack recall, which is
  BLOCKED-EXT.
* Next step, when attack runs exist: evaluate v2 and v3 on them with
  `afw experiment evaluate --version 3`; promote only through the reviewed path, with
  the regression gate.
