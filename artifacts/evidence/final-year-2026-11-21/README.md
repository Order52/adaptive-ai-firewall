# Final-year gates, 2026-11-21

Gates and thresholds: `docs/FINAL_YEAR_PLAN.md` (committed before any number below existed).
Nothing here was tuned after being seen. Attack data is the team's own runs from 2026-11-07
(`atk-bruteforce-*`, 3 test + 1 validation) and 2026-11-09 (`atk-sqli-*`, 1 run); nothing was sent
by this work, the evaluation is an offline replay of recorded windows.

## Correction to earlier statements

Earlier in this project (and in answers to "is it production ready") I said no labelled attack run
exists. That was wrong. The team's brute-force and SQL-injection runs were on CTRL01 since 7 and 9
November; the status documents had not been updated and I did not check the dataset list. Their
real results are below.

## A: adaptive (live, benign traffic only)

| Gate | Result | Evidence |
|---|---|---|
| **A1** live correction of a false positive | **FAIL** | `ad1-report.json`, `ad1-shadow-windows.jsonl` |
| A2 poisoning not worse | PASS | `adaptation-experiment-ad2.json` |
| A3 governance evaluates and decides | **gate ran, FAILED one check** (not promoted) | `gate-evaluation.txt` |
| A4 restart safe | PASS: `n_learned` 1182 before and after, nothing unflushed | restart 08:52:35Z |

**A1 numbers.** Six vouched users, 100 minutes, challenger `n_learned` 607 to 1182. Unseen user
`10.77.20.254` (a "power" persona, not vouched), first 10 minutes, 94 windows:

| | Champion | Challenger |
|---|---|---|
| windows flagged | **100 %** | **74.5 %** |
| mean score (threshold 0.806) | 0.927 | 0.816 |

Predeclared pass: challenger flags at most half the champion's rate. 74.5 % is not half of 100 %,
so A1 **fails**. The challenger did move most of the way (mean score 0.927 to 0.816, threshold
0.806), but not across. On the vouched users themselves (in-sample) the challenger's flag rate fell
from 93 % to 27 to 32 % while the champion stayed at 88 to 94 %. So live learning works and
generalises only partly to a user unlike the ones it learned from. This is not a measurement fault
(94 windows, champion rate 100 %, test informative), so the plan allows no repeat to chase it.

**A2.** Poisoning counts equal the 18 November run and the October M4 baseline; only
`ms_per_window` differs. Residual risk unchanged: in-distribution poison and 4 colluding sources
are still learned (280 of 360).

**A3, first run of the gate with real attack data.** `ceval-3a86f992c900`, benign holdout
`p7-sel,p7-sel-shift,a3-sel` (2 379 windows), attack validation `atk-bruteforce-20261107-validation`:

| Check | Value | Result |
|---|---|---|
| min_learning, holdout_not_learned, ledger_clean, holdout_size | 1182 learned, 0 overlap, 0 tainted, 1189 windows per half | PASS |
| benign_fpr_not_worse | challenger **0.0017** vs champion **0.9462** | PASS |
| attack_recall_regression | 1.0 on 30 attack windows (champion 1.0) | PASS |
| **sensitive_invariance** | worst probe flag-rate change **-1.0** on `auth_fail_frac` (limit -0.05) | **FAIL** |

Six of seven pass. The one failure is the P2 mechanism doing its job: after learning from benign
users with mistyped passwords, the challenger no longer flags a synthetic high-`auth_fail_frac`
probe that the champion flags. Real brute-force recall did not drop (other features carry it), but
the gate does not accept that as a substitute. Not promoted; the live detector is unchanged.

## D: detection, brute force only (`eval-bruteforce-test-runs.json`, `scorecard-bruteforce.json`)

Offline replay of the 3 test runs, ML strategy (arm M2), thresholds from the plan:

| Gate | Result | Detail |
|---|---|---|
| D1 containment | **PASS** | attacker contained in 3 of 3 runs |
| D2 speed | **PASS** | first action after 2.8, 2.4 and 5.2 s (limit 180 s) |
| D3 no collateral harm | **FAIL** | both legitimate background users restricted in all 3 runs; legitimate request success 0.46 (limit 0.98) |
| D4 value over baselines | **PASS** | contained 3/3 vs static rules 0/3, equal to the statistical arm |
| other 3 families | NOT_RUN | SQL injection has 1 run (needs 3); port scan and SSH guessing have none |

Overall scorecard: **FAIL** (D3). Arms side by side, same runs: static rules (M0) contained 0 of 3
attackers; statistical profile (M1) contained 3 of 3 with **0** legitimate users flagged; ML (M2)
and hybrid contained 3 of 3 but flagged **6 of 6** legitimate users (the known new-user false
positive); streaming ML flagged 2 of 6. For this family the statistical arm did better than the ML
arm on harm. Choosing the strategy is the owner's decision; nothing was changed.

## What this means

* Detection of **brute force** is real and fast (3 of 3, under 6 seconds). It was unmeasured before.
* The weakness is no longer unknown: the ML strategy restricts new legitimate users while an attack
  is running, and live learning narrows but does not close that gap (A1).
* Remaining gates need more runs from the team: 2 more SQL-injection runs, 3 each of port scan and
  SSH guessing, content discovery for D5, then the scorecard on all of them.
