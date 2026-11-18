# Adaptation design

How the system learns, detects drift, filters training data, compares challengers,
promotes models and rolls back. This page is the overview. Details and evidence:

* `engineering/M2_ONLINE_LEARNING_DESIGN.md`: online learner, eligibility, provenance,
  persistence (ADR-028, ADR-029).
* `engineering/M3_CHAMPION_CHALLENGER.md`: promotion gate, human promotion, probation,
  rollback (ADR-030).
* `engineering/M4_ADAPTATION_EXPERIMENTS.md`: drift, poisoning and regression
  experiments on recorded lab traffic.

## 1. Two adaptation paths

| Path | What changes | Trigger | Who decides |
|---|---|---|---|
| **Batch profile rebuild** (pre-existing, ADR-012) | Trusted profile and all detectors (robust stats, Isolation Forest, HST) | Drift report → candidate profile built from reputation-gated, multi-source benign windows → candidate gates | Human promotion (`POST /api/profiles/{app}/{v}/promote`) |
| **Online challenger** (M2–M4) | HST only: a shadow copy of the champion learns incrementally | Every eligible live window | Gate evaluation, then human admin promotion; automatic rollback only |

Phase 0 found that the original claim "HST keeps learning" was false: HST was never
updated at runtime. M2 made online learning real. M3 made its output promotable under
a gate. M4 measured it on real drift.

## 2. Drift vs adaptation (kept distinguishable)

* **Drift** is observed by the drift monitor: new routes, new app versions, feature
  shift and shadow anomaly rate, at population level (several sources). It produces a
  `DriftReport` (dashboard "Controlled adaptation"). A report changes nothing by itself.
* **Adaptation** is a model change. The online challenger changes continuously in
  shadow, with no effect on decisions. Champion changes happen only by promotion and
  are recorded with lineage (`parent_model_id`), evaluation id, probation and audit
  entries.

## 3. Online challenger in one paragraph

A River Half-Space-Trees challenger, deep-copied from the trusted champion, learns
prequentially: it scores each window, then calls `learn_one`. It learns from tumbling
(non-overlapping) per-source windows that pass two eligibility stages.

* **Stage 1, at window time:** mTLS-authenticated provenance, well-formed values, not a
  protected address, no WAF/IDS/auth evidence, security-sensitive features within the
  profile's q99, no taint.
* **Stage 2, after a 10 min quarantine:** late evidence, source tenure, per-source rate
  and share caps, minimum population. Windows the champion finds anomalous also need
  corroboration from 3 or more *behaviourally similar* sources.

A source is tainted (persistently, 24 h) by late evidence (IDS, WAF, auth), by operator
"true positive" feedback, and by a policy that is **actually changing its traffic**. A
proposal that was never applied (monitor mode, or waiting for approval) does not taint it,
and a proposal that rests on behaviour-model evidence alone does not either. Before
2026-11-18 any proposal tainted the source, which made a false positive on a new legitimate
user permanent: the champion's proposal stopped the learning that would have fixed it (the
live learner learned 0 windows because of this). State is checkpointed atomically with
watermarks and a fingerprinted ledger, so restarts and replays cannot double-learn.

**Operator vouching (fast, human-driven learning).** `POST /api/feedback` (operator role, audited;
MCP tool `feedback`) with label `benign_change` or `false_positive` on a source makes its windows
learnable within the quarantine time (about 3 minutes) instead of waiting for tenure, a
population of similar sources and corroboration. It overrides only the taint a *policy* left.
It never overrides evidence taint, operator "true positive" marks, negative evidence in a
window, the sensitive-feature ranges, malformed or unverified telemetry, or the per-source
rate and share caps. The latest label for a source wins. Switch off with
`learning.operator_vouching: false`.

## 4. Comparing and promoting

* `afw challenger evaluate` restores the latest valid checkpoint and runs the gate on
  recorded holdout datasets that are disjoint from training. Checks:
  * minimum learning;
  * no holdout leakage;
  * clean ledger;
  * holdout size;
  * benign FPR not worse at a calibrated threshold;
  * attack recall not regressed on **real labelled** attack runs (synthetic refused);
  * sensitive-feature invariance.
* Only a fully passing evaluation freezes a `CANDIDATE`. Promotion is a human admin
  API action with freshness, integrity and champion-unchanged checks. There is no
  automatic promotion and no MCP promotion tool.
* **Probation** (24 h) rolls back automatically to the parent when the live
  anomalous-window rate exceeds max(2 × baseline, baseline + 0.05) over 100 or more
  windows, or when 3 operator false-positive reports arrive. The rolled-back model is
  marked `REJECTED`.

## 5. Poisoning resistance (what is and is not covered)

| Attack on learning | Defence | Evidence |
|---|---|---|
| Forged telemetry | Only mTLS role-checked channels are eligible; IDS (plaintext) is never learned | `test_provenance.py`, ADR-029 |
| Replay / duplicate events | Request-id UNIQUE, content-hash IDS ids, watermarks, fingerprint ledger | `test_online_learning.py`, `test_telemetry_v2.py` |
| An operator vouch for an attacker (stolen operator token) | Operator role and audit log; evidence, range and rate checks still apply to the windows; learning is shadow-only, so a vouch can change no decision without the gate and an admin promotion | `test_online_learning.py` |
| One or two sources pushing malicious "normal" | Tenure, per-source rate and share caps, taint from any negative evidence, corroboration across 3 or more similar sources | M4 §3: before the fix, 140/180 poison windows learned; after it, 0/180 |
| Gradual evasion of sensitive features | Sensitive features capped at profile q99; gate invariance check | M4: gate correctly fails the adapted challenger on invariance |
| Regressed or poisoned challenger promoted | Gate, human promotion, probation with automatic rollback | M4 scenario C: rollback after 100 windows |
| **Not covered** | Four or more colluding, tenured, behaviourally similar sources can corroborate each other | Documented residual risk (M4, ADR-028) |

## 6. Measured status

* **Learning works on real drift (offline replay).** One pivot after 227 learned
  windows cut held-out HST FPR from about 0.65 to about 0.03–0.06.
* **Online HST adaptation alone would not have stopped the live false proposals.**
  Isolation Forest and robust stats drove most of them, and they adapt only through a
  batch rebuild.
* **Live, the challenger learned 0 windows** during the 75 min run (2026-10-27). The champion's
  own proposals tainted every new source. That was a deadlock, not a safeguard, and it is fixed
  (§3): on 2026-11-18 a live test learned 12 vouched windows with none excluded as tainted. The
  fast settings reach a pivot on the recorded drift run (190 windows) where the old defaults did
  not (45). Evidence: `artifacts/evidence/fast-learning-2026-11-18/README.md`.
* **The gate currently refuses promotion,** for two reasons:
  * no real labelled attack runs exist (BLOCKED-EXT);
  * the adapted challenger lost sensitivity to auth-abuse-like variants (a real
    finding).
