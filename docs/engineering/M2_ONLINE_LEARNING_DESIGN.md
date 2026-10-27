# M2: online shadow challenger (design review)

_Status: design accepted 2026-10-27; implementation tracked in
`docs/engineering/AUTONOMOUS_PROGRESS.md`. ADR-028 (online learning), ADR-029
(authenticated telemetry provenance)._

## 1. Problem

The Phase 0 audit found that nothing learns at runtime. The Half-Space-Trees (HST)
model is batch-trained once and `learn_one` is never called. M2 adds a genuine
incremental learner. It must not:

- (a) learn from untrusted telemetry,
- (b) be poisonable by an attacker who keeps traffic just under the thresholds,
- (c) influence enforcement before M3 provides validated promotion and rollback.

## 2. Algorithm choice

**River `HalfSpaceTrees`** (Tan, Ting & Liu, 2011), already in the stack (ADR "River
ADOPT") and already batch-trained per profile as a comparator. Alternatives:

| Option | Why not (for M2) |
|---|---|
| Periodic batch refit of IF | That is what exists; it is not incremental and has no prequential record |
| River `OneClassSVM` (SGD) | Sensitive to scaling and learning rate; harder to explain; no mass-based interpretation |
| River `ILOF` | Memory grows with the stream; unsuitable for a long-running controller |
| Adaptive thresholds on robust-z | Moves a threshold only; the directive explicitly rejects this as "adaptation" |

**Properties of River HST that the design must respect** (read from River 0.26.1 source):

1. **Cold start.** `score_one` returns **0 (normal) until the first `window_size`
   samples have been learned**. A cold challenger would call everything benign, so the
   wrapper tracks `warm` and shadow predictions made while cold are flagged invalid.
2. **Step changes.** Scores come from the *reference* mass (`r_mass`), which pivots to
   the latest mass (`l_mass`) every `window_size` learns. **Predictions change in steps
   at pivots**, while internal state (`l_mass`, `counter`) changes on every learn.
3. **Short memory.** After a pivot the reference is the most recent `window_size`
   samples only. Whoever controls one window of admitted samples defines "normal".
   Per-source caps, population diversity and champion isolation are therefore
   **load-bearing**, not cosmetic.
4. **Scaling.** Features are scaled to [0, 1] with the trusted profile's q01/q99 (plus
   headroom) and clipped. This reuses the existing `HalfSpaceTreesDetector._dict`, so
   champion and challenger see identical inputs.
5. **Determinism.** Tree structure comes from `seed`. Learning order is deterministic
   (admission order sorted by `window_end`, then source). Replaying the same admitted
   windows from the same checkpoint gives a byte-identical state.

**Warm start.** The challenger starts as a deep copy of the trusted profile's
registered HST artifact (hash-verified), so it is warm at generation 0 and isolates the
effect of online learning. The frozen HST is the **champion of the same family**,
giving a clean frozen-vs-adaptive ablation for M4. The live enforcing detectors
(robust-z, Isolation Forest) are untouched.

## 3. Learning unit, dedup and overlap

- **Unit = one per-source feature window.**
- **Overlap.** Live windows overlap (30 s length, 5 s hop), so one request appears in
  about 6 windows. The learner samples **tumbling** windows per source: a window is a
  learning candidate only if `window_start >= last_candidate_end[source]`. Each request
  can therefore enter at most one learned window.
- **Replay and restart.** A persisted **per-source event-time watermark**, committed
  atomically with the checkpoint, rejects any window ending at or before the watermark.
  A **fingerprint** of each learned window has a UNIQUE constraint in the
  `learned_windows` ledger: sha256 of app, source, window bounds and request ids.
- **Event dedup.** The WAF `unique_id` (`request_id`) is the stable event identity and
  is UNIQUE in `observations`. The runtime now feeds the windows **only observations
  the database accepted**. Previously a request id replayed after it left the
  correlator's in-memory cache was windowed twice.

## 4. Provenance (ADR-029)

`HttpObservation.provenance` is one of:

| Value | Meaning |
|---|---|
| `unverified` (default) | plaintext syslog; sender identified by IP only |
| `authenticated` | WAF access, audit and app records all arrived over **mutually authenticated TLS**, each from the sensor role allowed to emit that record kind (WAF lines only from the WAF cert, app lines only from the APP cert) |
| `curated` | operator-curated dataset replay; the operator's assertion is audited |

**Rule: only `authenticated` or `curated` windows, where every observation is
app-joined, can ever be learned.** The plaintext listener stays for Suricata and FW
syslog. Those feed *exclusion* (taint), which is the safe direction: forging them can
only stop learning, not poison it. **Until the mTLS transport is deployed, live online
learning admits nothing.** That is the required safe default.

## 5. Eligibility and quarantine (two stages, delayed admission)

**Stage 1, at window time (cheap, immediate):**
1. provenance authenticated or curated, and all observations joined: else `unverified` / `unjoined`
2. values present, finite and in range (ratios in [0, 1], non-negative): else `malformed`
3. source not protected, sensor or probe: else `protected`
4. no positive WAF, IDS or AUTH evidence in this window's assessment: else
   `negative_evidence` (and the source is **tainted**)
5. *(revised during implementation)* a window that a trusted detector flags as
   anomalous is **not** excluded here and does **not** taint its source; it is marked
   `anomalous` with its top-2 driver features and must pass the multi-source
   corroboration check in stage 2. Excluding every champion-anomalous window would make
   the challenger structurally unable to adapt to exactly the drift the champion
   mis-scores. Traffic-affecting *policies* (not WATCH) still taint the source.
6. security-sensitive features (`auth_fail_frac`, `client_err_frac`,
   `distinct_usernames`, `login_rate`) at or below the trusted profile q99: else
   `sensitive_range`
7. tumbling and watermark checks: else `overlap` / `duplicate`
8. source has **no** taint: else `tainted`

**Passing windows enter quarantine** with `release_at = window_end + admission_delay`
(default 10 min). Late-arriving evidence therefore still counts: IDS alerts, WAF
blocks, policies, operator feedback.

**Stage 2, at release:**
1. re-check taint and active or recent policies against the source, and negative
   feedback: else `late_taint`
2. **tenure**: the source was first seen at least `min_source_tenure` ago (default 30 min): else `tenure`
3. **per-source rate cap**: at most `max_windows_per_source_per_hour` admitted: else `source_rate`
4. **per-source share cap**: at most `max_source_share` of the last `share_window`
   admitted windows: else `source_share`
5. **population**: at least `min_distinct_sources` distinct sources released in the
   last hour: else held back (`population`)
6. **anomalous windows need corroboration**: at least `anomaly_min_sources` (default 3)
   distinct ready sources showing the same anomaly drivers, with no source above
   `2 x max_source_share` of them; else held until quarantine expiry, then
   `champion_anomalous`. A concentrated attack from one or two sources therefore never
   becomes "normal" (tested).

Admitted windows are learned prequentially: **score the window with the challenger
(and the frozen champion HST) first, then `learn_one`**. The pre-learning scores are
stored in the ledger.

**Reputation (taint) is persisted** in `source_reputation` with an expiry
(`taint_until`) and bounded retention (rows purged 7 days after `last_seen` and taint
expiry). It survives restarts, closing the Phase 0 finding that taint was lost on
restart.

### Known limitations of the eligibility strategy (stated, not hidden)

- **Low-and-slow mimicry.** A patient adversary with several clean, tenured sources
  whose traffic stays inside the champion's normal and sensitive ranges can still move
  the challenger, because HST's reference is the last window. Mitigations: caps,
  population requirement, champion isolation, and (M3) promotion only after
  validation against an independent attack benchmark and benign holdout. This is a
  residual risk, not solved.
- **Absence of evidence.** No WAF, IDS or AUTH evidence and a low champion score do
  **not** prove benign. The gate only removes what is demonstrably suspicious.
- **Sensor compromise.** A compromised WAF01 or APP01 host holds a valid TLS key and can
  emit authenticated but false telemetry. mTLS authenticates the channel, not the
  truth of its content.
- **Champion false positives lock out learning (observed live, 2026-10-27).** The
  champion flagged benign personas on new source IPs; its traffic-affecting proposals
  (monitor mode, not enforced) tainted those sources, so the live challenger learned 0
  windows from them. The gate is fail-closed by design; lifting taint needs a human
  `FALSE_POSITIVE` decision (M3). Evidence: `artifacts/evidence/m2-2026-10-27/live-shadow-midrun.txt`.
- **IP identity.** Sources are IPs; a NAT shared by legitimate and malicious users
  mixes them. In the lab each client IP is one host.

## 6. Persistence and crash safety

- **Checkpoint** = joblib blob of the challenger, written to a temp file in the same
  directory, `fsync`, `os.replace`, then directory `fsync`. Then **one DB
  transaction** inserts:
  - the checkpoint row (sequence, parent champion model id and sha, format version,
    feature names, sha256, `n_learned`, per-source watermarks), and
  - the ledger rows learned since the previous checkpoint.

  The file without its DB row is ignored (orphan). A DB row whose file is missing or
  whose hash mismatches is marked `corrupt` and skipped.
- **Restore** = newest checkpoint for this app whose parent equals the current trusted
  HST model and whose format and feature names match, **sha256-verified before
  unpickling**, then type-checked. Otherwise try older checkpoints (keep the last 3),
  then fall back to a fresh copy of the champion. Every fallback is audited.
- **Crash between checkpoints.** Windows learned since the last checkpoint are lost
  from **both** the model and the ledger, so state stays consistent. They are not
  re-learned because live windows are not re-emitted after a restart.
- The champion artifact is never written. The challenger lives in a separate directory
  and table.

## 7. Isolation from enforcement

- The learner runs on its **own thread fed by a bounded queue** (drop-and-count when
  full). The processor thread never waits for it.
- Shadow scores (champion HST vs challenger) are recorded for every live window.
  **Nothing the learner produces is read by correlation, decision or policy code.**
  A test asserts that enforcement outcomes are identical with the learner on or off.
- There is no promotion path in M2. `LearningService.promote` is unchanged and still
  gated; M3 adds challenger promotion and rollback.

## 8. Acceptance criteria (tested)

1. State changes on learn (`counter`, `l_mass` totals, digest).
2. Predictions change after a pivot on a shifted benign pattern: scores of the new
   pattern drop. Cold-model predictions are flagged invalid.
3. Score-before-learn is recorded and equals the pre-learn score.
4. Each exclusion reason is triggered by a test.
5. Overlapping, duplicate and replayed windows are not learned twice, including across
   a restart.
6. Concentrated poisoning (one or two sources, or a burst) stays quarantined; a clean
   population change from tenured sources is eventually admitted.
7. Restart restores the exact checkpoint, watermarks and `n_learned`; a corrupted,
   incompatible or wrong-parent checkpoint is rejected with a fallback.
8. Enforcement outcomes are identical with the learner on or off; the full existing
   suite and the live-lab suite pass.
9. Resources: learner memory and per-window cost are measured and reported.

**Outstanding security validation (from M1 review).** ADR-027's occlusion test shows
that the model is anomalous without the correlated features. It does **not** prove
causal independence of the remaining evidence: remaining features can still be
statistically coupled to the same events, for example `req_rate` during a login burst.
This is tracked as open item SV-1 in the progress file.
