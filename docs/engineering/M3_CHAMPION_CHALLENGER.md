# M3: Champion/challenger lifecycle (ADR-030)

Status: implemented and unit-tested; live promotion gate **blocked externally** on
labelled real attack runs (see §6). Builds on M2 (ADR-028 online shadow challenger,
ADR-029 authenticated telemetry).

## 1. Problem

M2 produces a challenger that learns online from gated live traffic, but nothing
decides whether it is better than the champion, nothing calibrates its threshold,
and nothing can safely put it into service or take it out again. The challenger
learns only from traffic the champion did not police (M2 taint rule), so it must
never be trusted just because it disagrees with the champion.

## 2. Lifecycle

```
 shadow learner ──checkpoint──► evaluate (gate) ──pass──► CANDIDATE model record
                                    │ fail                    │ human admin promote
                                    ▼                         ▼
                              evaluation record        ACTIVE (parent RETIRED)
                              (no model)                      │ probation
                                                    ┌─────────┴──────────┐
                                           breach (auto)            period elapses
                                                    ▼                    ▼
                                parent ACTIVE, promoted REJECTED     PASSED
                                                          (manual rollback still possible)
```

* **Evaluate** (`afw challenger evaluate`, `POST /api/learning/challenger/evaluate`,
  admin): restores the newest valid checkpoint of the active HST champion, runs the
  gate on recorded holdout datasets, and only if *every* check passes freezes the
  snapshot into the model registry as a `CANDIDATE` with its calibrated threshold and
  benign score quantiles. The registry copy is what gets promoted, so later learning
  or checkpoint pruning cannot change what was evaluated.
* **Promote** (`POST /api/learning/challenger/{evaluation_id}/promote`, admin only;
  there is **no automatic promotion** and no MCP tool for it). Refused unless the
  evaluation passed, is younger than `max_evaluation_age_s` (24 h), the candidate's
  sha256 still verifies, the champion it was compared with is still `ACTIVE`, and no
  other promotion is on probation. The parent is set `RETIRED` (kept for rollback).
  The controller reloads; the shadow learner then starts a fresh challenger lineage
  from the new champion.
* **Probation** (default 24 h). The controller counts the promoted HST's live
  verdicts. It rolls back **automatically** to the parent when either
  * live anomalous-window rate > max(2 x baseline, baseline + 0.05) over at least
    100 windows (baseline = the challenger's holdout FPR, at least the target FPR), or
  * at least 3 operator `FALSE_POSITIVE` feedback items arrive during probation.

  An automatic rollback marks the promoted model `REJECTED` so it can never be
  re-activated by accident. Rollback always returns to a previously trusted model,
  so automating it does not widen trust. Probation counts are persisted (at most
  every 30 s), so they survive a restart.
* **Manual rollback** (`POST /api/learning/challenger/rollback`, admin) works during
  or after probation and marks the promoted model `RETIRED`.

## 3. The promotion gate (`afw.ml.challenger_gate`)

| Check | Passes when | Why |
|---|---|---|
| `min_learning` | n_learned >= HST window size | River HST predictions only change at a reference pivot; before that the challenger is the champion |
| `holdout_not_learned` | no learned window overlaps a holdout source's labelled activity | leakage would make the holdout meaningless |
| `ledger_clean` | no learned source is tainted *now* | late evidence after admission = possible poisoning; the lineage must be discarded |
| `holdout_size` | >= 30 non-overlapping benign windows in each half | small or overlapping samples overstate confidence (Phase 0 finding) |
| `benign_fpr_not_worse` | challenger FPR (calibrated threshold) <= max(champion FPR, 2 x target) on the test half | adaptation must not add false alarms |
| `attack_recall_regression` | challenger recall >= champion recall - 0.05 on labelled **real** attack runs | **fails** with no attack runs, and **fails** if any attack run is synthetic |
| `sensitive_invariance` | on holdout windows that **both** models score normal (champion at its threshold, challenger at its calibrated threshold), for **each** sensitive feature: challenger probe flag rate >= champion rate - 0.05; fails if fewer than `min_holdout_windows` matched windows (ADR-034, revised 2026-10-28) | learning must never make high auth failure, login rate, usernames or client errors normal. Matched windows remove the population/margin confound of the earlier own-normal version; per feature so one lost feature cannot hide behind three intact ones |

Calibration: threshold = (1 - target_fpr) quantile of challenger scores on the
chronologically first half of the benign holdout; FPR is measured on the second half.
The holdout must be disjoint from the champion's training datasets
(`assert_disjoint`). Holdout windows are tumbling-subsampled per source.

## 4. Tests (`tests/unit/test_challenger_lifecycle.py`, 20 tests)

Synthetic feature vectors that prove the mechanism, not detection quality:

* gate passes an adapted challenger and reports lower holdout FPR than the champion
  on the drifted pattern;
* gate fails with no attack runs or synthetic ones, below a full window, on holdout
  leakage, on a later-tainted ledger source, on a too-small holdout;
* a challenger deliberately poisoned toward attack-like sensitive features fails
  `sensitive_invariance` with a real deficit on at least `min_holdout_windows` matched
  windows (not merely for lack of evidence);
* sensitivity regression benchmark (ADR-034): for each of the four sensitive features,
  a challenger that learned that feature's probe perturbation alongside normal traffic
  fails, and the detail names that feature; an unchanged champion copy passes in its
  own regime; the same copy recalibrated on a drift holdout (threshold raised to absorb
  drift) fails; a drift-only holdout with no matched windows fails closed; the adapted
  challenger whose own-normal rate is lower than the champion's passes on matched
  windows (the earlier confound);
* a passing evaluation freezes a CANDIDATE and changes nothing active; a failing one
  registers nothing and cannot be promoted;
* promotion activates exactly the evaluated snapshot; it is refused when stale,
  tampered, after a champion change, or during another probation;
* a probation breach (rate, or operator FP reports) rolls back automatically and
  marks the model REJECTED; a quiet probation passes and manual rollback still works;
  probation counts survive a restart; the controller reloads after an automatic rollback.

Mutation check: disabling each guard (probation exclusivity, sensitive invariance,
ledger taint, holdout leakage, rate rollback, champion-changed, probation persistence)
makes the corresponding test fail (evidence:
`artifacts/evidence/m3-2026-10-27/mutation-check.txt`). The ADR-034 revision has its own
check: 6/6 mutants caught (no matched-window minimum, challenger-normal bases only, best
instead of worst feature, champion threshold for the challenger, widened tolerance,
feature mix-up; `artifacts/evidence/p1-2026-10-28/p2-mutation-check.txt`).

## 5. Interfaces

* REST: `GET /api/learning/challenger` (viewer), `POST .../evaluate`,
  `POST .../{evaluation_id}/promote`, `POST .../rollback` (admin; 409 on refusal).
* CLI: `afw challenger evaluate --benign ... [--attack ...]`, `afw challenger status`.
  The CLI does not promote: only the API path reloads the running controller.
* MCP: read-only `challenger_lifecycle`.

## 6. Limits and blocked items (stated, not hidden)

* **Blocked externally: no labelled real attack runs exist.** The only attack-labelled
  datasets on CTRL01 are `demo-*` (synthetic, `tests/fixtures/synthetic.py`), which
  the gate refuses by design. So the live gate cannot pass, and no live promotion has
  been or will be performed until the team supplies attack scenarios (DatasetManifest
  with `role: attack` sources). This is the intended safe behaviour, not a defect.
* The probation rate rule detects a promoted model that alarms too much; it cannot
  detect one that misses attacks (no live ground truth). The pre-promotion recall
  gate is the only protection against that, which is why it cannot be waived.
* Sensitive probes are counterfactual single-feature perturbations of benign
  windows, a necessary but not sufficient check of attack sensitivity.
* Only the HST arm adapts online. Isolation Forest and robust statistics change only
  through the reviewed batch profile pipeline (ADR-019).
