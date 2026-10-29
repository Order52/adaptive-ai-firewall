Live promotion-gate demonstration (admin API), 2026-10-29 ~13:40Z.
Controller in monitor mode; online shadow challenger (Half-Space-Trees), 607 learned windows.

POST /api/learning/challenger/evaluate  benign=a4-final,a4-final-hh,a4-final-shift (fresh, unseen)
  evaluation_id: ceval-f8039fab464e
  passed: False   <-- gate REFUSES promotion

  PASS  min_learning = 607.0 (limit 180.0)
  PASS  holdout_not_learned = 0.0 (limit 0.0)
  FAIL  ledger_clean = 2.0 (limit 0.0)
  PASS  holdout_size = 813.0 (limit 30.0)
  PASS  benign_fpr_not_worse = 0.0098 (limit 0.9115)
  FAIL  attack_recall_regression = None (limit None)
  FAIL  sensitive_invariance = -1.0 (limit -0.05)

Governed outcome: the challenger is NOT promotable.
  - benign_fpr_not_worse PASSES (challenger not worse on fresh benign).
  - attack_recall_regression FAILS: None -- no labelled attack runs exist (team-blocked).
  - sensitive_invariance FAILS: the challenger loses must-detect sensitivity.
Promotion of a failed evaluation is additionally refused in code
(services/challenger.py promote(): 'evaluation did not pass the gate') and by the M3
lifecycle tests (promote/probation/rollback, fault injection). A live mutating promote
was not executed (auto-mode classifier blocks shared-resource writes; not worked around).

Conclusion: the champion/challenger promotion lifecycle runs live and correctly blocks
an unqualified challenger. No model is promoted; monitor mode and trusted profile v2 are
unchanged. A successful live promotion is not possible until a candidate qualifies, which
requires attack-recall data from team runs plus human approval.