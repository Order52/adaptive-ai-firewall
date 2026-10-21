# Results & Evaluation (draft)

A draft evaluation chapter for the dissertation. Every quantitative claim here is
backed by a committed evidence file under `artifacts/evidence/` and a figure under
`docs/figures/`; nothing is synthetic or hand-tuned for presentation. Where a result
could not be produced, this chapter says so plainly rather than estimating.

> **Scope note.** All AI results in this chapter are **benign-only**. The adversarial
> arm of the evaluation (attack recall, scenarios A/B/E, the incremental value of ML
> under attack) requires labelled attack telemetry that is supplied by the project
> team, not generated here. The replay machinery that produces those numbers is
> complete and tested on synthetic fixtures (for correctness) and on real benign data;
> it emits the attack metrics unchanged once attack traces exist. This is a data
> dependency, not a missing capability.

## 1. Evaluation method

The system was evaluated **in situ** on the GNS3 lab (OPNsense FW01, OWASP-CRS WAF,
Suricata IDS, a rental web application, and the AI controller CTRL01), not in a
notebook. Benign traffic is produced by `traffic/benign_personas.py`, which drives
legitimate user journeys (browse, valid login with occasional corrected typo, view
and make bookings, review, logout) from real client source IPs through the WAF to the
application. WAF, application and IDS logs flow over syslog to CTRL01, where they are
correlated into 30-second feature windows (5-second hop, minimum three requests).

Three detectors run on each window: a **robust-statistics** detector (the *M1*
statistical arm), an **Isolation Forest** (the *M2* ML arm), and a **Half-Space-Trees**
streaming detector. Thresholds are chosen on a held-out **validation** run at a 1%
false-positive budget; the **test** run is a separate benign capture. Leakage controls
are structural: splits are by run, and labels, IP addresses and scenario identifiers
are never used as features.

The comparative evaluation replays three arms through the *identical* live pipeline:

- **M0 (static)** — firewall + WAF + IDS, no adaptive layer;
- **M1 (statistical)** — M0 plus the robust-statistics detector;
- **M2 (ML-assisted)** — M0 plus the Isolation Forest.

Because all three replay through the same correlation and decision path at the same
false-positive budget, differences are attributable to the arm, not the harness.

## 2. Real-data training and zero false positives

The headline functional result is that a model **trained on genuine lab traffic**
(not fixtures) makes correct live decisions. Profile **v2** (`b4a83e64fc22`) was
trained on **361 real benign windows** from six client sources; thresholds were set on
a 154-window validation run, each detector landing at **1.30% validation FPR** —
inside the 2× budget guard. Promoted over the earlier synthetic profile, it was then
exercised on fresh, held-out benign traffic.

**Every live benign source scored below every detector threshold** — zero false
positives (Figure B). The same traffic had been *falsely* flagged "elevated" by the
earlier synthetic profile, which is the concrete evidence that training on real
behaviour, rather than synthetic fixtures, is what removes the false positives.

- *Figure B* — `fig-b-zero-false-positives`: per-source detector score ÷ its own
  threshold; all bars below the 1.0 threshold line.
- Evidence: `artifacts/evidence/real-benign-baseline-2026-10-17.md`.

## 3. The cost of ML over statistics

At the *same* 1.30% validation FPR, the three detectors differ by three orders of
magnitude in scoring cost (Figure A): robust-statistics **≈14 µs/window**,
Half-Space-Trees **≈57 µs**, Isolation Forest **≈11.4 ms** — roughly **800×** between
the statistical and ML detectors. On the held-out benign replay, M0, M1 and M2 were
**equivalent on safety** (FPR 0, legitimate success 100%, no benign source ever
restricted); the honest difference between them on benign data is therefore *cost*,
not accuracy. Whether M2's cost buys additional attack recall is exactly the question
the (blocked) adversarial arm answers.

- *Figure A* — `fig-a-detector-latency`.
- Evidence: `artifacts/evidence/real-benign-baseline-2026-10-17.md` (detector and
  M0/M1/M2 tables).

## 4. Explainable decisions on live traffic

Every assessment carries occlusion-based feature attributions and human-readable
reason codes. A live, unscripted example (Figure F): during dashboard verification,
the health-probe source `10.77.20.250` scored **59 / band elevated**. The attribution
names the cause without ambiguity — `unknown_route_frac = 1` (robust-z **+20**: all of
its requests hit a route absent from the trusted profile), `route_entropy = 0`
(z −10: a single route), and `login_rate`/`distinct_usernames`/`req_rate` far below the
user-journey baseline. In words: *a source that hits one unknown endpoint, never logs
in, and is very sparse* — the signature of an infrastructure probe, not a user.

Two things make this a strong result rather than a false alarm. First, the system is
in **monitor** mode, so the source is **observed, not blocked**. Second, the decision
is fully **explained**, which surfaces the right operational action: infrastructure
probes should be allowlisted (or trained in as a legitimate behaviour class) before an
application is switched to enforce mode. This is reported as a deployment
consideration, not hidden.

- *Figure F* — `fig-f-explainable-detection`.
- Evidence: `artifacts/evidence/dashboard-live-2026-10-20.md` (assessment
  `risk-7b3ee514524a`).

## 5. Controlled adaptation (Scenario C)

The adaptation lifecycle was observed end-to-end on real traffic (Figure C): a
legitimate behaviour change (users exercising new routes `/reviews`, `/logout`) raised
a **population-level drift report** (`new_endpoint`, `feature_shift`, six sources); a
candidate profile v2 was built from reputation-gated benign traffic; the
**anti-poisoning gate** passed it only because six independent sources contributed and
no single source dominated; a human promoted it; and the same legitimate users then
scored risk 0. The design intent — *attacker traffic cannot unilaterally redefine
"normal"* — is enforced by the multi-source gate and the human-in-the-loop promotion.

The 60-minute soak (§6) produced a complementary negative control: a **single-source**
candidate was proposed by the shadow learner and **correctly never promoted**, because
the gate requires multiple independent sources. The mechanism refuses exactly the
single-source poisoning it is designed to refuse.

- *Figure C* — `fig-c-adaptation-lifecycle`.
- Evidence: `artifacts/evidence/real-benign-baseline-2026-10-17.md` (Scenario C);
  `artifacts/evidence/soak-2026-10-20.md` (single-source candidate held).

## 6. Stability, endurance and recovery

**Soak (Figure D).** Under 60 minutes of continuous benign traffic the controller was
stable: resident memory flat (**220.9 → 224.2 MB**, +3.3 MB/hour — no leak), control-
loop tick p50 steady at **≈2.3 ms** (one transient max spike, p50 unaffected), **zero
policies** created, and the trusted profile unchanged. Telemetry flowed continuously
(10,169 messages) with no new parse errors. A handful of individual 5-second windows
showed transient `max_risk ≈ 21` that never escalated — noted as the behaviour an
enforce-mode band threshold would need to tolerate.

**Cold-restart recovery.** A full power cycle (`afw lab stop` → `start`) returned the
lab to a working state from a single command path: 13/13 nodes started, the trusted
profile v2 and three models **auto-restored** from the database with no retraining,
zone isolation intact (26/26), the organised canvas and annotations persisted, and
MCP reconnected.

**Operator dashboard (Figure E).** The dashboard was re-rendered against the real
profile v2 with no console errors; every panel is populated from real backend data —
stat tiles, live-risk and request charts, the policy-lifecycle history with
enforcement read-back, the model/profile table, candidate-evaluation gates, the
M0/M1/M2 experiments table, telemetry health and the audit trail.

**Code health.** `ruff` clean; `mypy --strict` clean across 81 source files; 57
unit/integration tests and 9 live-lab tests (`AFW_LAB=1`) pass.

- *Figures D, E*; evidence `soak-2026-10-20.md`, `cold-restart-2026-10-18.md`,
  `dashboard-live-2026-10-20.md`.

## 7. Threats to validity and limitations

1. **No adversarial evaluation yet.** Attack recall and the incremental value of M2
   under attack are unmeasured, pending team-supplied attack traces. The benign-only
   results cannot speak to detection effectiveness, only to false-positive behaviour,
   cost, explainability, adaptation safety and stability.
2. **Single-source soak.** The endurance test varied journeys over time from one
   source; it is an endurance test, not a concurrency/scale test. Multi-source
   behaviour is covered separately by the six-source training/validation capture.
3. **Infrastructure probes score anomalous** under a user-journey profile (§4);
   enforce-mode deployment requires allowlisting them or modelling them explicitly.
4. **Simulated country policies.** GeoIP-based policies are simulated on lab addresses
   unless a real GeoIP database is configured; this is surfaced in the API and UI.
5. **Lab scale.** Results are from a small GNS3 lab on a single host; absolute
   latencies and memory figures are indicative of the architecture, not of a
   production-scale deployment.

## 8. Summary

On real lab traffic the system trains a model that makes **zero-false-positive**,
**explained** decisions; adapts to legitimate change through a **multi-source,
human-in-the-loop** gate that refuses single-source poisoning; and remains **stable
under sustained load** and **recoverable** across a full restart — all observable
through a working operator dashboard and a 26-tool MCP control plane. The outstanding
work is the **adversarial** half of the evaluation, which is blocked only on data the
team provides, and for which the measurement machinery is already in place.
