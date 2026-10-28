# M4: Adaptation experiments on recorded lab traffic

Date: 2026-10-27. Command (on CTRL01, temp state only, the live controller is untouched):

```bash
afw experiment adaptation --learn real-drift-learn-20261027 \
    --hold real-drift-hold-20261027 --out m4-adaptation.json
```

Evidence: `artifacts/evidence/m3-2026-10-27/m4-adaptation.json` (after the fix in §3) and
`m4-adaptation-v1-name-corroboration.json` (before the fix). Code:
`src/afw/ml/adaptation_experiment.py`; unit tests `tests/unit/test_adaptation_experiment.py`.

## 1. Data (real, benign)

One 75-minute live run on 2026-10-27, 18:03:09–19:18:09Z: `traffic/benign_personas.py`
(the same persona journeys used for the trusted v2 profile) from client IPs
10.77.20.11–16, over mTLS-authenticated telemetry. 992 sessions. The v2 champion was
trained on one 5.4-minute run from 10.77.20.10–15. **Correction (2026-10-28):** this
section first called these "six new client IPs" and said v2 had three training runs.
Five of the six addresses were in the training run; the drift is a workload change (one
shared generator process, about 13 instead of 71–76 requests per source per minute), not
new users (`P1_BENIGN_GENERALIZATION.md` §1).

* `real-drift-learn-20261027` (drift, 18:03:09–18:48:09, 3603 observations): learning stream
* `real-drift-hold-20261027` (test, 18:48:39–19:18:09, 2253 observations): disjoint later holdout

Live, the champion raised **89 proposals** (46 rate limit, 43 watch) against these benign
sources. The controller was in monitor mode, so none were enforced
(`artifacts/evidence/m2-2026-10-27/live-shadow-final.txt`).

**Units and uncertainty.** Holdout windows are tumbling (non-overlapping per source).
95 % CIs are percentile bootstraps over the **6 sources** (2000 resamples), not over
windows. This is one run of six sources: the CIs describe source-to-source variation
within this run, not run-to-run variation.

## 2. Scenario A: legitimate drift

Frozen champion detectors on the whole holdout (193 tumbling windows, 6 sources), at their
trusted thresholds:

| Detector | False-positive rate | 95 % CI (sources) |
|---|---|---|
| Robust statistics | 0.130 | 0.103 – 0.163 |
| Isolation Forest | 0.715 | 0.644 – 0.793 |
| HST (champion) | 0.637 | 0.560 – 0.717 |

Shadow learner on the learning stream (751 windows):

| Config | Learned | Pivots | Main exclusions |
|---|---|---|---|
| deployed default | 45 | 0 | overlap 353, tenure 182, sensitive 130, anomalous-uncorroborated 41 |
| experiment (rate cap and tenure lifted, labelled) | 227 (156 anomalous, corroborated) | 1 | overlap 353, sensitive 130, anomalous-uncorroborated 41 |

Challenger (experiment config) vs champion HST on the holdout **test half** (97 windows):

| Model / threshold | FPR | 95 % CI |
|---|---|---|
| champion HST @ champion threshold 0.806 | 0.650 | 0.566 – 0.726 |
| challenger @ champion threshold | 0.062 | 0.021 – 0.109 |
| challenger @ calibrated threshold 0.837 (first half, target 1 %) | 0.031 | 0.000 – 0.067 |

**Interpretation.** On this drift the online HST adapts: after one reference pivot its
false-alarm rate on unseen later traffic from the same population falls from about 65 %
to about 3–6 %. Two caveats:

1. Only the HST arm adapts. Isolation Forest (72 % FPR) and robust statistics, which
   produced the live proposals, are unchanged until a reviewed batch profile rebuild.
   Online HST adaptation alone would **not** have stopped the live proposals.
2. Under the deployed default caps (tenure 30 min, 20 windows per source per hour) a
   45-minute run does not reach a pivot. Adaptation takes hours by design.

**Promotion gate on the adapted challenger: FAILED** (correct behaviour):

| Check | Result |
|---|---|
| min_learning 227 >= 180, holdout_not_learned, ledger_clean, holdout_size 96 >= 30, benign_fpr 0.031 <= 0.650 | pass |
| attack_recall_regression | **fail**: no labelled real attack runs exist |
| sensitive_invariance | **fail** (ADR-034 matched-window version, rerun 2026-10-28): on 32 test windows both models score normal, challenger vs champion probe flag rate: client_err_frac 0.438 vs 0.875, auth_fail_frac 0.281 vs 0.469 (limit: champion - 0.05); distinct_usernames 0.250 vs 0.063 and login_rate 0.469 vs 0.250 are higher |

This challenger must not be promoted, and the gate keeps it in shadow.

**Why it lost sensitivity (P2 investigation, 2026-10-28).** The original M4 write-up
called this "a real loss of sensitivity" based on an own-normal comparison (challenger
0.162 vs champion 0.419, each model on the windows *it* scores normal). The P2
investigation tested four hypotheses:

| Hypothesis | Test | Result |
|---|---|---|
| H1 population confound: own-normal sets differ (challenger normals include drifted windows the champion flags) | compare on windows both models score normal | confirmed as a confound: champion 70, challenger 184, common 64 normal windows on the full holdout |
| H2 learned state desensitized the model | matched windows, **both models at the champion threshold** | **rejected**: challenger at least as sensitive on every feature (auth 0.567 vs 0.433, client_err 1.000 vs 0.867, usernames 0.233 vs 0.067, login 0.767 vs 0.200; 30 windows) |
| H3 HST dilution: single-feature probes of deep-normal windows rarely cross the threshold | champion own-normal probe rates on in-distribution 10-17 data | confirmed, and it affects the champion too (auth 0.031, client_err 0.188, usernames 0, login 0.031) |
| H4 threshold calibration | same matched windows, challenger at its **calibrated** threshold (0.837 vs champion 0.806) | **confirmed as the mechanism**: client_err falls 1.000 → 0.438 and auth 0.567 → 0.281 |

So the learned model state is not what loses sensitivity. Recalibrating the threshold
to the target FPR on the drifted calibration half raises it just enough that
single-feature client-error and auth-failure probes of normal windows fall below it. The
gate evaluates the threshold that would actually be deployed, so rejecting is correct.
The check itself was revised (ADR-034) to compare on matched windows and per feature, so
a lost feature can neither hide behind the others nor be faked by a population shift.

Two caveats:

* The revised check was designed after seeing this holdout, so this rerun is not an
  independent test of the check. Its independent evidence is the regression benchmark
  in `test_challenger_lifecycle.py` (a deliberately desensitized challenger per feature
  fails; an unchanged copy passes).
* Calibration is **not** changed in response to this result: changing it after looking
  at this holdout would tune to it. Whether to cap the calibrated threshold at the
  champion's is an open, predeclared question for the next independent benign test
  (`P1_BENIGN_GENERALIZATION.md`).

Evidence: `artifacts/evidence/p1-2026-10-28/m4-adaptation-p2-gate.json`
(`gate_checks`, `gate_metrics`, `sensitivity_decomposition`),
`p2-sensitive-investigation.json`, `p2_sensitive.py`. The earlier own-normal metric is
still reported in `gate_metrics` for comparison.

## 3. Scenario B: poisoning, and a vulnerability this experiment found

Synthetic **feature-space** poison windows (no traffic sent; labelled in the report), injected
with CURATED provenance (worst case: the adversary owns authenticated sources), one per
30 s per source, sensitive features kept at the benign median. Experiment config (no
tenure or rate caps).

| Poison | Sources | Learned / offered **before fix** | Learned / offered **after fix** | Challenger flags fresh poison (after) |
|---|---|---|---|---|
| detectable (unknown routes, novel methods; champion flags 100 %) | 2 | 140 / 180, challenger blinded (0 %) | **0 / 180** | **100 %** |
| detectable | 4 | 280 / 360, blinded | 280 / 360, blinded (0 %) | 0 % |
| in-distribution (champion flags 0 %) | 2 | 140 / 180 | 128 / 180 (36 % of learned) | 0 % (as champion) |
| in-distribution | 4 | 280 / 360 | 280 / 360 (55 %) | 0 % (as champion) |

**Vulnerability found and fixed.** Anomalous windows were "corroborated" when peers
shared any anomaly-driver *feature name*. Here six legitimately drifting sources whose
anomalies involved `route_count` vouched for poison from two sources that also involved
`route_count`, so the challenger learned the poison and stopped detecting it.
Corroboration now requires **behavioural similarity**: peers must lie within L∞ 0.35 in the
champion HST's scaled feature space (`anomaly_max_distance`, chosen a priori; a benign
q01–q99 range spans about 1/3 of that space). Legitimate drift learning was unchanged by
the fix (227 learned, 156 corroborated, before and after). Regression test:
`test_benign_drift_cannot_vouch_for_poison_sharing_a_driver_name` (mutation-checked).

**Residual risks (not solved):**

* **Collusion by at least `anomaly_min_sources` (3) authenticated sources** with consistent
  behaviour is indistinguishable from a population-level change and is learned
  (4-source row). The defences are the deployed tenure and rate caps (lifted in this
  worst case), the promotion gate (attack recall on labelled runs, sensitive invariance)
  and human review. The poisoned challenger stays in shadow and cannot affect enforcement
  without passing them.
* **In-distribution poison** (traffic the champion already calls normal) is bounded only by
  the per-source share cap (25 %). k colluding sources can supply about k x 25 % of
  learned windows. It cannot teach the model that something *anomalous* is normal, but it
  does shift the reference mass.

## 4. Scenario C: injected regression and automatic rollback

A deliberately regressed model (the champion HST with its threshold set to the holdout's
benign median, so it alarms on about half of benign traffic) is promoted in a temporary
registry. The gate is bypassed for this experiment only, and the report says so. The real
holdout windows are then fed in event-time order. Probation rolled back automatically
after **100 windows** (the minimum sample; 945 s of event time): anomalous rate 0.500 >
limit 0.060. The champion was re-activated and the regressed model marked `rejected`, with
audit `challenger.promote` → `challenger.auto_rollback`.

## 5. Limits of these results

* One drift run, six sources, one application; the CIs are within-run.
* No attack runs: nothing here measures detection of real attacks. The attack-recall gate
  check fails for exactly that reason.
* The poison is synthetic feature vectors, not traffic, and is labelled as such. It tests
  the learning gate, not the sensors.
* The experiment config lifts the deployed caps; it is reported separately from the
  default config.
