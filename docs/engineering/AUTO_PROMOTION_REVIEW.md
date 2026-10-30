# Review: can bounded automatic champion promotion be supported safely?

Status: review, 2026-10-28. **Nothing here is enabled.** Automatic promotion does not
exist in the code (ADR-030), and this review does not add it. It states what would have
to be true first, and which decisions belong to a human.

## 1. What "promotion" means in this system

| What is promoted | Effect on traffic | Today |
|---|---|---|
| Trusted behaviour profile + its robust-statistics and Isolation Forest models | **Enforcing**: they drive rate limits and blocks through correlation | Human only (`afw train promote`, admin API), after the bootstrap gate; atomic switch (ADR-040) |
| Online Half-Space-Trees challenger → HST champion | **None directly**: HST is shadow-only, a comparator and the learner's anchor | Human only, after the challenger gate (ADR-030, ADR-034); 24 h probation with automatic rollback |

Automatic **rollback** exists and is safe because it only returns to a previously
human-approved model (now crash-consistent, ADR-040). Automatic **promotion** would be
the first path by which the system changes its own trusted state without a person.

## 2. Verdict

* **Enforcing models and profiles: no, not under any bound considered here.** A
  promoted enforcing model changes who gets blocked. The evidence that would justify
  that without a human, attack recall on real labelled runs, does not exist yet
  (Gate B: blocked on the team's runs), and P1/P6 show that more benign data alone
  can reduce sensitivity while improving false positives.
* **HST champion: not now; possibly later, under the bounds in §4**, once the evidence
  in §3 exists. HST does not enforce, so a bad automatic HST promotion harms the
  comparator and the learner's anchor, not traffic. Even that needs the bounds,
  because the champion is what later challengers are compared with.

## 3. Evidence missing today (each blocks enabling)

1. **Real attack recall in the gate.** The challenger gate's recall check refuses
   synthetic attack data by design. Without labelled team runs it cannot pass, so an
   automatic path would either never fire or would have to weaken the gate.
2. **A live learner that learns.** In the live deployment the challenger learned 0
   windows: proposals tainted every new source (fail-closed). Automatic promotion of a
   learner that has never been observed learning live would be untested.
3. **The P6 sensitivity results.** The synthetic must-detect suite and the A1
   adaptation stress test (§7 of `P6_GENERALIZATION_AND_SENSITIVITY.md`) are designed
   to catch silent desensitization. Their selection and final results are pending.
4. **Cumulative drift.** Every gate today compares a challenger with its **parent**.
   A chain of automatic promotions, each within tolerance of its parent (recall −0.05,
   sensitive features −0.05), can drift arbitrarily far from the last human-approved
   model ("boiling frog"). No anchor comparison exists yet.

## 4. Bounds an automatic HST promotion would need (design, not implemented)

| Bound | Why |
|---|---|
| Only the HST slot; the profile, robust statistics and IF never | they enforce |
| Every challenger gate check passes, **including real attack recall** | no synthetic evidence substitutes |
| Compared with a fixed **anchor** (the last human-approved champion), not only the parent: recall and per-feature sensitivity within the same tolerances of the anchor | stops cumulative drift |
| P6 must-detect suite at ≥ 0.95 per family, nominal and under the A1 stress | sensitivity floor that adaptation cannot lower |
| Security-path ceilings unchanged (configuration, reviewed commits only) | they bound what "normal" can grow into |
| At most one automatic promotion per 7 days; at most 3 between two human reviews | bounds the rate of change and forces periodic review |
| Probation as today (24 h, rate and false-positive triggers), crash-consistent rollback (ADR-040) | fast undo |
| Learned sources bounded as today (taint, tenure, rate and share caps); refuse if any learned source is tainted later | poisoning (M4 residual: ≥ 4 colluding tenured sources) |
| Disabled whenever evidence is degraded (sensor heartbeat stale) or the mode is not `auto` | no change on partial information |
| Every automatic promotion audited, shown on the dashboard, and revertible by one admin action | accountability |

## 5. Decisions that need human authorization

1. Whether to build automatic HST promotion at all (this review recommends: not before
   §3 items 1–3 exist).
2. The anchor model, and when it is renewed (only by a human promotion).
3. The tolerances, the promotion rate and the review interval in §4.
4. The P6 must-detect families, levels and the stress design used as the floor.
5. Any change to the security-path ceilings.
6. Enabling it in the lab, and separately in any other deployment.

## 6. What was done instead

* Rollback reliability, which any automatic promotion would rely on, was tested by
  fault injection and fixed (ADR-040): interrupted switches no longer leave no active
  model, no trusted profile, or a partial model set, and a failed automatic rollback
  fails closed.
* The evaluation harness can now compare the frozen, streaming and hybrid designs on
  the team's runs (runbook §4.1), which is the evidence §3 asks for.
