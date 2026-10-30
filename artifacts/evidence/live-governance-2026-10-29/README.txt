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
--- Live enforcement safety guards (POST /api/policies/simulate, read-only) ---
Protected/management refusal verified live:
  source_block 10.77.50.10 (MGMT)  -> valid=False: "is protected (management network and recovery path)"
  source_block 10.77.60.10 (DB)    -> valid=False: "is protected (database tier)"
  source_block 10.77.10.99 (ATTACK), duration 300s -> valid=True, would_auto_apply=False
    (a block proposed by an operator is valid but never auto-applies without >=2
     independent evidence categories; in monitor mode nothing enforces anyway).
Demonstrates gate D (Enforcement) guards live: protected addresses can never be blocked,
and a well-formed block still requires corroboration to auto-apply. No policy was created
(simulate is read-only); controller stayed in monitor mode, trusted profile v2 unchanged.

--- Live network-detector spot-check (2026-10-29 ~14:26-14:31Z) ---
Drove benign AFW_NET=1 traffic from 4 unused sources (.194-.197) through the live shadow
network detector. Result INCONCLUSIVE: the generator hit a TLS read timeout to the WAF
and produced only sparse traffic (net_flow 54->66 over ~4 min, no emitted .19x windows),
so no meaningful live unfamiliar rate could be measured. The live detector PATH is
operational (net_flow/net_ssh/net_tls events flowed to the controller in shadow mode,
/api/network), but the rigorous benign-novelty measurement remains the offline NV2
evaluation (0.0059 [0.0016,0.0115], PASS) against a validated snapshot -- the correct,
reproducible, leak-controlled method. Note: net_dns read 0 after the 13:25Z FW01 reboot
during this low-traffic window; not re-tested under load (would need a fuller capture).
Controller stayed healthy (ok, monitor, telemetry ok) throughout.
