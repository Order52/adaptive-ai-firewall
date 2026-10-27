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
(the same persona journeys used for the trusted v2 profile) from **six new client IPs**
10.77.20.11–16, over mTLS-authenticated telemetry. 992 sessions. The v2 champion was
trained on 3 runs of about 5 min each from other IPs.

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
| sensitive_invariance | **fail**: challenger flags 0.162 of attack-like probes on windows it scores normal, champion 0.419 (limit 0.369) |

The sensitive-invariance failure is a real loss of sensitivity to high-auth-failure and
high-login-rate variants of the drifted traffic, so this challenger must not be promoted.

The metric was revised once, before this result. The first version compared raw probe
flag rates (challenger 0.188 vs champion 0.794). Those rates were confounded: the
champion flags 65 % of the *unperturbed* drifted windows, so it "flags" their probes
regardless of sensitivity. The revised check uses only probes whose base window the same
model scores normal, and falls back to the stricter raw champion rate when the champion
has too few normal bases. Both versions reject this challenger; both numbers are in the
check detail.

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
