# Results and evaluation

The evaluation chapter for the dissertation, updated 2026-10-27 with the M2–M7 results
(§3, §6b, §7b). Every quantitative claim is backed by a committed evidence file under
`artifacts/evidence/`, and figures are under `docs/figures/`. Nothing is synthetic or
hand-tuned for presentation. The measurement index is in §10. Where a result
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

## 3. The zero-FP result does not survive a workload shift (2026-10-27)

§2 holds for the conditions the profile was trained on. It was then tested on a run
ten days later from 10.77.20.11–16. **Correction (2026-10-28):** this section first
called these "six new benign client addresses"; five of them (.11–.15) were in the
training run. What changed was the time and the workload: one shared generator process
at about 13 requests per source per minute, instead of one process per address at
71–76 (`engineering/P1_BENIGN_GENERALIZATION.md` §1). Unseen-user generalization is
measured separately in P1. The run used the same persona journeys
for 75 minutes (992 sessions) over authenticated telemetry. The frozen champion
detectors, at their trusted thresholds, on the later 30 minutes (193 tumbling windows;
95 % CIs bootstrapped over the 6 sources):

| Detector | False-positive rate | 95 % CI |
|---|---|---|
| Robust statistics | 0.130 | 0.103–0.163 |
| Isolation Forest | 0.715 | 0.644–0.793 |
| Half-Space-Trees | 0.637 | 0.560–0.717 |

Live, the controller raised **89 proposals** (46 rate limit, 43 watch) against these
benign sources. It was in monitor mode, so none was enforced. The training set was
**one 5.4-minute run** from six addresses (361 windows) at a single workload intensity,
and it under-represents legitimate variation. **This is the most important negative
result of the project.** In enforce mode, the v2 profile would have harmed legitimate
users whose request cadence differs from the training run. The statistical
detector degrades far less than the ML detectors. The headline in §2 must always be
quoted together with this section.

- Evidence: `artifacts/evidence/m3-2026-10-27/m4-adaptation.json` (scenario A),
  `artifacts/evidence/m2-2026-10-27/live-shadow-final.txt`;
  `docs/engineering/M4_ADAPTATION_EXPERIMENTS.md` §1–2.

## 3a. Unseen users, and what more varied training data buys (P1, 2026-10-28)

The protocol was predeclared and committed before the test data existed
(`engineering/P1_BENIGN_GENERALIZATION.md`). 16 **unseen** users, each with its own
seeded persona (cadence, depth, login use, typos, own account), ran in a later period
from addresses never used in training (10.77.20.45–60). Tumbling windows; 95 % CIs over
users; requests counted once each.

| On 16 unseen users | v2 (trusted, 5.4 min, 6 addresses) | v3 candidate (+ 45 min, 16 persona users) |
|---|---|---|
| Robust stats / IF / HST window FPR | 0.158 / 0.550 / 0.591 | 0.000 / 0.044 / 0.021 |
| Users rate-limited by M2 (replay) | **13 of 16** | **0 of 16** |
| Legitimate requests impacted | 2132 of 10216 | 0 of 10216 |

On the workload-shift sets, v3 also restricts 0 users (v2: 6/6 and 5/6). v4, trained
with only 6 of the 16 users, performs almost the same as v3: behavioural variety matters
more than head count. v2's errors were driven by its generator's unrealistic
multi-account logins (`distinct_usernames`), route counts and timing.

**The improvement is not free.** On windows both models score normal, v3's ML detectors
flag far fewer moderate single-feature probes (e.g. HST `client_err_frac` 0.000 vs
0.746; IF `auth_fail_frac` 0.016 vs 0.606). v3 therefore **fails** the predeclared
sensitivity criterion, as well as the old-regime and IF FPR criteria, and is **not
promoted**. An exploratory check with attack-sized values (labelled post hoc) shows that
robust statistics keep 100 % sensitivity, and that a combined credential-attack-shaped
window is flagged by every v3 detector. Whether the loss matters is decided only by real
attack runs (BLOCKED-EXT).

- Evidence: `artifacts/evidence/p1-2026-10-28/p1-eval.json`, `p1-eval-table.txt`,
  `p1-fp-drivers.json`, `p1-exploratory-sensitivity.json`.

## 3b. Generalization without sensitivity loss (P6, 2026-10-28)

Predeclared protocol and amendment A1 committed before the data
(`engineering/P6_GENERALIZATION_AND_SENSITIVITY.md`). Seven candidates were trained on
120,282 observations (28 users) and calibrated on 39,517 (12 users), then compared on
**new** selection users: `p6-sel`, 16 users, 1,085 tumbling windows; `p6-sel-shift`,
6 users, 307 windows. Every dataset count equals the WAF access log (zero loss).
Sensitivity is measured with **synthetic feature-level** malicious-behaviour cases
added to real benign windows (no traffic sent; not attack detection), nominally and
after an adaptation stress (recalibration with 3 % attack-shaped windows labelled
benign).

**Result: no candidate met the predeclared eligibility rule, so none was selected and
the final test was not run.**

| Candidate | Worst enforcing FPR on p6-sel | Users restricted (M2) sel / shift | Must-detect min nominal / stressed |
|---|---|---|---|
| R2 (trusted v2) | 0.430 (IF) | 12/16, 6/6 | 1.00 / 0.35 |
| R3 (v3) | 0.104 (RS) | 5/16, 3/6 | 1.00 / 0.55 |
| D (more data) | 0.021 (IF) | 5/16, 2/6 | 0.51 / 0.17 |
| F (Wilson fractions) | 0.015 (IF) | 1/16, 5/6 | 0.60 / 0.37 |
| C (cohort thresholds) | 0.020 (IF) | 7/16, 4/6 | 0.56 / 0.02 |
| S (D + security path) | 0.068 (security) | 5/16, 2/6 | 0.91 / 0.63 |
| FS (F + security path) | 0.068 (security) | 1/16, 5/6 | 0.96 / 0.83 |

Separate contributions (S, IDOR at the must-detect level, the weakest family): ML only
0.51, security rules only 0.46, combined 0.91; under stress 0.17 / 0.46 / 0.63. The
fixed security path does not hide weak ML: neither part suffices alone.

Causes, diagnosed on the consumed selection data only:
* **Every legitimate user restricted by D, F, C and R3** was rate-limited on behaviour
  alone, because the statistical and ML detectors agreed. Both read the same features,
  so this contradicts the documented invariant that an anomaly alone never authorizes a
  traffic-affecting change. The one exception was a "forgetful" user whose failed
  logins met the brute-force rule (ADR-039 rate limit by design).
* **A generator/app mismatch in all legitimate data** (§8, item 8): the retrained
  candidates learned 404 bursts as normal (IDOR sensitivity 0.51–0.60 against 1.0 for
  R2/R3), and the security path flagged two power users on client errors.

Amendment A2 (generator fix, retraining on new clean data, behaviour-only evidence
observe-only in replay) was committed before any new data; its result is in §3c.

- Evidence: `artifacts/evidence/p6-2026-10-28/select/` (`p6-select.json`,
  `diagnosis-restrictions.json`), `phaseC-capture.txt`, `phaseD-capture.txt`.

## 3c. P7: the same question on clean data (A2, 2026-10-28)

New legitimate data without the generator defect: 74,510 training and 24,705
calibration observations (40 users), then 13,173 + 3,033 selection observations from
22 new users, all equal to the WAF log. Behaviour-only evidence observe-only in replay.

**Result: still no eligible candidate**, but for a different and much narrower reason.

| Candidate | Worst enforcing window FPR on p7-sel | Users restricted (M2) sel / shift | Must-detect min nominal / stressed |
|---|---|---|---|
| R2 (trusted v2) | 0.843 (IF) | 1/16, 0/6 | 1.00 / 0.79 |
| R3 (v3) | 0.456 (IF) | 1/16, 0/6 | 1.00 / 0.73 |
| D | 0.016 (IF) | 1/16, 0/6 | 0.81 / 0.49 |
| F | 0.009 (IF) | 1/16, 0/6 | 0.86 / 0.78 |
| C | 0.032 (RS) | 0/16, 0/6 | 0.82 / 0.52 |
| S | 0.016 (IF) | 1/16, 0/6 | 1.00 / 1.00 |
| FS | 0.009 (IF) | 1/16, 0/6 | 1.00 / 1.00 |

* Clean data fixed the false positives. Retrained candidates now have window FPR
  ≤ 0.016 (upper 95 % CI ≤ 0.048), against 0.02–0.10 in P6. Users restricted fell
  from up to 7/16 and 5/6 to at most 1/16 and 0/6.
* The single restriction for D, F, S and FS is one user, a "forgetful" persona (typo
  rate 0.65), and comes from the AUTH brute-force rule, not from ML. It was predicted
  before the data (A2). No candidate restricted anyone on behaviour alone.
* FS would have been selected: stressed must-detect 1.00, lowest FPR. On the weakest
  P6 family (IDOR@20): ML 0.86, rules 1.00, combined 1.00 (P6: 0.51 / 0.46 / 0.91).
* Sensitivity here is measured with **synthetic feature-level** cases on real benign
  windows, not attacks.

Phase E (final sets) remains uncollected. Choosing between accepting that rate limit,
changing the AUTH rule or changing the criterion is a human decision. Any of them needs a
new predeclared amendment and new selection data.

- Evidence: `artifacts/evidence/p7-2026-10-28/` (`phaseC-capture.txt`,
  `phaseD-capture.txt`, `select/summary.txt`, `select/select.json`,
  `select/diagnosis-restrictions.json`); protocol §8.4.

## 3d. A3: resolving the AUTH conflict (2026-10-29)

The window brute-force rule was replaced by two things, predeclared before any data
(`engineering/A3_AUTH_CONTROLS.md`, ADR-044):
- **per-account failure streaks**, so a success clears the account;
- **login-route-only graduated controls**: throttle (3 r/min), then deny, then a longer
  deny for repeat offenders. A deny on a shared address needs a human.

**Selection data.** 22 new users: 17 503 + 4 179 requests, of which 1 837 were
legitimate logins.

**Selection result (run once).** D, F, C, S and FS are all eligible. **S** is selected
(stressed must-detect 1.0; simpler than FS).

| Measure | S | Criterion |
|---|---|---|
| Enforcing window FPR on `a3-sel` | ≤ 0.0031 (upper CI ≤ 0.0069); security path 0 | ≤ 0.02 / ≤ 0.05 |
| Site-wide restriction of a legitimate user | 0 (both sets) | 0 |
| Legitimate logins refused | 0 / 1 837 | ≤ 0.5 % |
| Legitimate users with a login control | 0 | ≤ 1 per set |
| Legitimate request success | 1.0 | ≥ 0.99 |

R2 and R3, the stored v2/v3 models, still fail on FPR (IF 0.93 and 0.56).

**Attack resistance (SYNTHETIC: scripted attempt sequences through the real decision
code and nginx `limit_req` arithmetic; no traffic, no attack tool).**

| Family | Accepted (A3) | Accepted (A2 rule) |
|---|---|---|
| 1 guess/s, one account | 25 of 3 600 | 3 600 of 3 600 |
| 1 guess/20 s, one account | 25 of 180 | 180 of 180 |
| 1 guess/s, spraying | 25 of 3 600 | 3 600 of 3 600 |
| 1 guess/min, spraying | 20 of 60 | 60 of 60 |

- A user who mistypes 4, 6 or 8 times is never refused.
- The A2 site-wide limit (1 r/s) never binds against a 1 r/s guesser. This is a real
  weakness of the old rule, found by this arithmetic.

**Limits.**
- The generated users never came near the thresholds: at most 3 failures in a row on one
  account. So the benign result does not test real users who fail 5 or more times.
- Distributed guessing and slow multi-source spraying are outside a per-source rule.
- Real attack runs remain BLOCKED-EXT.

**Final evaluation (Phase E, run once): FAIL, so S is not promoted.**

- *What passed.*
  - The login controls passed on all three sets (2 418 legitimate logins, 0 refused, no
    restriction, success 1.0).
  - Synthetic must-detect was 1.0, nominal and stressed.
- *What failed.* S's one-sided security path flagged 4.75 % of windows on `p6-final`
  [0, 14 %] (criterion ≤ 2 %). All 47 flags were from the 2 "household" users (several
  accounts behind one address): its `distinct_usernames` level had been calibrated at 1.
- *Why selection missed it.* The selection set contained no household user. The
  shared-address sets showed the same effect (13–18 %), but the FPR criterion covers
  only the main set.

So the AUTH-control redesign met its friction and resistance criteria, but the selected
ML candidate did not generalise to multi-account addresses. A further attempt needs a
new amendment and new data (A3 §8.2).

- Evidence: `artifacts/evidence/a3-2026-10-29/`.

## 3e. NV1: network novelty on unseen legitimate users (2026-10-29)

The benign users now also generate ordinary non-web activity:
- DNS through their resolver;
- NTP;
- occasional pings;
- typed-URL visits.

They are split into light, normal and heavy habits. Calibration used 24 users
(109 615 network events). Development on 12 users gave an unfamiliar rate of 0.0102.

**The one-shot test on 22 unseen users failed.**
- Unfamiliar window rate 0.0678 [0.0088, 0.1575], against a criterion of ≤ 0.02 with
  upper CI ≤ 0.05.
- One legitimate heavy user reached a fixed ceiling: 11 distinct hosts in 60 s, against
  the host-sweep ceiling of 10.

Almost all unfamiliar verdicts come from heavy users (mean share 0.24, against ≤ 0.006
for light and normal). Training had 3 heavy users, at 3.3–4.7 DNS lookups/min; the test
had 6, at up to 5.7.

The detector stays in shadow. A further attempt needs a new predeclared protocol and
fresh data. Network attack recall is still unmeasured.

- Evidence: `artifacts/evidence/nv1-2026-10-29/`;
  `engineering/NV1_NETWORK_NOVELTY_VALIDATION.md` §7.

## 3f. NV2: network novelty revalidated on fresh unseen users (2026-10-29)

A new protocol was predeclared before any new data. It made two changes:
- calibration includes a stratified group of 8 heavy-habit users (13 heavy users in
  training, 32 users in all);
- the host-sweep ceiling counts only internal or unanswered destinations, not answered
  internet hosts.

The test users had new seeds and addresses unseen in training.

| | Unfamiliar window rate | Users with a strong verdict |
|---|---|---|
| Development (12 users) | 0.0145 [0, 0.0406] | 0 |
| **Test, run once (22 users, 2 530 emissions)** | **0.0059 [0.0016, 0.0115]** | **0** |

The test passes both criteria (≤ 0.02 with upper CI ≤ 0.05; no strong verdict). Light,
normal and heavy users all stay at ≤ 1 % on average.

Limits:
- The old host-sweep ceiling would also have fired on 0 test windows, so the ceiling
  change was not exercised.
- One lab population with generator-modelled habits. A heavy validation user just
  above the trained range gave 14 % unfamiliar windows.
- No attack recall: that needs team runs. The detector stays in shadow.

- Evidence: `artifacts/evidence/nv2-2026-10-29/`;
  `engineering/NV2_NETWORK_NOVELTY_REVALIDATION.md` §7.

## 3g. A4: AUTH household correction, revalidated on fresh unseen users (2026-10-29)

A3's one-shot final failed F1: candidate S's security path flagged 4.75 % of Phase E
windows, all legitimate multi-account ("household") addresses that were absent from the
selection set, because the `distinct_usernames` quantity was calibrated at 1. A4 makes
two predeclared changes: `distinct_usernames` is **ceiling-only** (fires at >= 5 accounts,
robust to calibration coverage), and benign FPR is a criterion on household and shared
sets too.

On fresh unseen data with household and shared-address coverage (disjoint from the
candidates' training), S passed selection and the one-shot final:

| Set | S security-path window FPR (final) |
|---|---|
| `a4-final` (16 natural users) | 0.0112 [0, 0.0343] |
| `a4-final-hh` (6 households) | 0.0 |
| `a4-final-shift` (5 shared addresses) | 0.0 |
| union | 0.0068 [0, 0.0207] |

0 of 2 791 legitimate logins refused; no login controls; no site restriction. SYNTHETIC
must-detect sensitivity stayed 1.0 (nominal and stressed) on brute_force, stuffing,
enumeration and idor. The A3 household failure is resolved.

Limits: the sensitivity numbers are SYNTHETIC (no attack traffic); a 3-4 account spray is
now caught by the live `credential_spraying` rule rather than this quantity; nothing is
promoted (monitor mode); real attack recall still needs the team's runs.

- Evidence: `artifacts/evidence/a4-2026-10-29/`;
  `engineering/A4_AUTH_HOUSEHOLD_REVALIDATION.md` §8.

## 3h. Offline evaluation on recorded real attack traffic (CIC-IDS2017, 2026-10-29)

**Separate gate from live GNS3** (`engineering/GATE_STATES.md`): external recorded PCAP,
processed offline with Suricata, through our production feature pipeline. NOT an in-lab
attack; cannot advance the live GNS3 gate.

CIC-IDS2017 Tuesday (FTP-Patator + SSH-Patator brute force; 294,866 flows; attacker
172.16.0.1), 13,784 windows (285 attack), labelled by attacker IP (defect-resistant vs
the CICFlowMeter label errors of Engelen et al.):

| Model | Recall | Precision | FPR |
|---|---|---|---|
| RandomForest (batch, time-split) | **0.846** | 1.00 | **0.00** |
| River ARF (prequential, predict-before-learn) | 0.775 | 1.00 | 0.00 |
| NetworkNovelty (unsupervised, CIC-calibrated) | 0.937 | 0.39 | 0.038 |
| Held-out family: train FTP → test **SSH** (withheld) | **0.992** | — | 0.00 |
| Held-out family: train SSH → test FTP | 0.000 | — | 0.00 |

**Audited** (`engineering/OFFLINE_CIC_AUDIT.md`), with corrections: detection is
behaviour-driven, **not** host/port-identity leakage (behaviour-only features recall 0.895,
identity-only 0.0; a 300 s anti-overlap gap leaves 0.846 unchanged). The RF 0 FPR is **0 FP
on 13,499 benign windows** (CI upper ~0.0003), not "zero FP" in general. The ARF "frozen
0.0" was a **data-ordering artifact** (shuffled → 0.976 ≈ RF): **no claim that continuous
learning is superior.** SSH→FTP "0.0" was a port-feature artifact (behaviour-only 0.66);
FTP→SSH 0.99 is **cross-protocol generalisation within brute force, not universal zero-day.**
Domain adaptation is required before any of this transfers to the lab. Evidence:
`artifacts/evidence/offline-cic-2026-10-29/`.

**Independent validation** (`engineering/OFFLINE_INDEPENDENCE.md`, CIC-IDS2017 Friday —
different day/families/tool): the model is **family-specific** (Tuesday brute force → Friday
attacks recall **0.11**; within-Friday only 0.27 — port-scan/botnet/DDoS are hard for window
features); the **fixed scan ceiling misses the real slow NMAP scan** (1/79 windows,
0.9 % benign false-strong); **self-learning works on the independent family** (0.0 → 0.625 in one run; ≈0.68 over 10 seeds;
old-family retention needs rehearsal — see `engineering/ERRATUM_FORGETTING.md`); batch vs incremental **comparable** (no superiority claim).

## 4. The cost of ML over statistics

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

## 5. Explainable decisions on live traffic

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

## 6. Controlled adaptation (Scenario C)

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

### 6b. Online adaptation on real drift (M2–M4, 2026-10-27)

The online HST challenger (`ADAPTATION_DESIGN.md`) was replayed over the first 45
minutes of the §3 run (`real-drift-learn-20261027`) and evaluated on the disjoint later
holdout (`real-drift-hold-20261027`).

| Setting | Windows learned | Pivots | Holdout test-half FPR (95 % CI) |
|---|---|---|---|
| Champion HST (frozen) | — | — | 0.650 (0.566–0.726) |
| Deployed default caps | 45 | 0 | unchanged (no pivot) |
| Rate cap and tenure lifted (labelled experiment) | 227 | 1 | 0.062 at champion threshold; **0.031** (0.000–0.067) at calibrated threshold |

* **Benefit.** One reference pivot reduces the HST arm's false alarms on unseen later
  traffic from about 65 % to about 3 %. Only the HST arm adapts online. Isolation
  Forest and robust statistics, which drove most live proposals, change only through a
  reviewed batch rebuild. Under the deployed caps, adaptation takes hours.
* **Poisoning.** Before the M4 fix, two attacker sources sharing anomaly-driver *names*
  with drifting benign users got **140/180** poison windows learned and blinded the
  challenger. With similarity-based corroboration: **0/180**, and drift learning was
  unchanged.
* **Regression.** A deliberately degraded promoted model was rolled back automatically
  after 100 windows (945 s of event time).
* **The gate refuses promotion** of the adapted challenger, for two reasons:
  * attack recall cannot be checked (no real labelled attack runs);
  * sensitive invariance fails: the challenger flags 0.162 of auth-abuse-like probes
    against the champion's 0.419 (limit 0.369).

  Adaptation reduced sensitivity to those variants. This is a real trade-off, and the
  gate exists to catch it.
* **Live,** the shadow challenger learned **0** windows during the run. The champion's
  own proposals tainted every new source (fail-closed by design).

Evidence: `m3-2026-10-27/m4-adaptation.json`, `m4-adaptation-v1-name-corroboration.json`,
`m2-2026-10-27/m2-replay-*.json`; `docs/engineering/M4_ADAPTATION_EXPERIMENTS.md`.

## 7. Stability, endurance and recovery

**Soak (Figure D).** Under 60 minutes of continuous benign traffic the controller was
stable: resident memory flat (**220.9 → 224.2 MB**, +3.3 MB/hour — no leak), control-
loop tick p50 steady at **≈2.3 ms** (one transient max spike, p50 unaffected), **zero
policies** created, and the trusted profile unchanged. Telemetry flowed continuously
(10,169 messages) with no new parse errors. A handful of individual 5-second windows
showed transient `max_risk ≈ 21` that never escalated — noted as the behaviour an
enforce-mode band threshold would need to tolerate.

**Cold-restart recovery.** A full power cycle (`afw lab stop` → `start`) returned the
lab to a working state from a single command path: 13/13 nodes started (2026-10-18,
before DESK01 was added; 7 VMs + 6 switches), the trusted
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

### 7b. Telemetry recovery (M5, 2026-10-27)

Verification found a real failure. After a controller restart, sensors kept writing into
a dead TLS session that FW01 silently dropped, and HTTP telemetry stopped for **about
55 minutes** without any alarm. After the fixes (bounded TCP retries, rsyslog rebind,
30 s mTLS heartbeats, per-sensor staleness), recovery was measured live:

| Case | Recovery |
|---|---|
| Controller restart under traffic | about 12 s |
| Restart, sensors idle 17 min, then traffic (before heartbeat) | about 120 s; lines written meanwhile lost |
| Restart with heartbeat, no client traffic | both sensors back in 59 s |
| One sensor silenced | flagged stale and evidence degraded at 148 s (limit 150 s); cleared 2 s after it resumed |

Evidence: `m5-2026-10-27/reconnect.txt`, `heartbeat-liveness.txt`;
`docs/engineering/M5_TELEMETRY_V2.md`.

## 8. Threats to validity and limitations

1. **No adversarial evaluation yet.** Attack recall and the incremental value of M2
   under attack are unmeasured, pending team-supplied attack traces. The benign-only
   results cannot speak to detection effectiveness, only to false-positive behaviour,
   cost, explainability, adaptation safety and stability.
2. **Single-source soak.** The endurance test varied journeys over time from one
   source; it is an endurance test, not a concurrency/scale test. Multi-source
   behaviour is covered separately by the six-source training/validation capture.
3. **Infrastructure probes score anomalous** under a user-journey profile (§5);
   enforce-mode deployment requires allowlisting them or modelling them explicitly.
4. **Country policies.** Real-country enforcement on FW01 was added on 2026-10-28
   (ADR-036). Outbound was proven live with an egress probe and independent connects.
   Inbound can only be verified by read-back, because no real-country traffic reaches
   the lab.
5. **Lab scale.** Results are from a small GNS3 lab on a single host; absolute
   latencies and memory figures are indicative of the architecture, not of a
   production-scale deployment.
6. **Small training population.** The trusted profile came from one 5.4-minute run from
   six addresses; §3 and §3a show this is not enough. Broader data fixes the false
   positives at a measured sensitivity cost (§3a).
7. **One drift run.** The adaptation CIs are over six sources in one run, not over runs.
8. **Legitimate traffic carried 22–29 % client errors** (found 2026-10-28). The
   generator requested review endpoints that the deployed v1 application does not
   serve (404), and v1 personas sent bookings without a required field (422). This
   holds for every generated benign dataset before P7, including the data behind the
   trusted v2 profile and every FPR above. Comparisons between models on the same data
   remain fair, but the lab's "legitimate" baseline was noisier than real users, and
   404-driven behaviours (IDOR, enumeration) were learned against an inflated baseline.
   Fixed in the generator (P6 amendment A2); not retroactively.

## 9. Summary

On real lab traffic the system:

* trains models that make explained decisions with no false positives **on the
  population they were trained on**, but with high false-positive rates on new
  legitimate users (§3);
* adapts online on recorded real drift (HST false alarms about 65 % → 3 %), while
  refusing poisoning and regressions and refusing its own promotion when sensitivity
  is lost (§6b);
* enforces through the real firewall and WAF with verification;
* recovers from controller and sensor failures with bounded, measured delays (§7, §7b).

The adversarial half of the evaluation (attack recall, incremental value under attack)
is blocked on team-run attack scenarios. The harness for it (M6) is complete.

## 10. Measurement index

| Measurement | Command | Dataset / run | Time (UTC) | Evidence |
|---|---|---|---|---|
| Profile v2 validation FPR, live 0-FP | `afw train bootstrap`; live controller | `real-benign-train2`, `real-benign-val`, `real-benign-train` | 2026-10-17 | `real-benign-baseline-2026-10-17.md` |
| Detector latency, M0/M1/M2 benign replay | `afw experiment replay` | held-out real benign | 2026-10-17 | same |
| Soak | live, 60 min | — | 2026-10-20 | `soak-2026-10-20.md` |
| Cold restart | `afw lab stop/start` | — | 2026-10-18 | `cold-restart-2026-10-18.md` |
| Workload-shift FPR, online adaptation, poisoning, rollback | `afw experiment adaptation --learn real-drift-learn-20261027 --hold real-drift-hold-20261027` | 75-min run, 10.77.20.11–16 | 2026-10-27 18:03–19:18 | `m3-2026-10-27/m4-adaptation*.json` |
| Online replay (pivot, restore) | `afw experiment online-replay` | real-benign and drift datasets | 2026-10-27 | `m2-2026-10-27/m2-replay-*.json` |
| Telemetry recovery | scripted restarts (see file) | live | 2026-10-27 20:15–20:48 | `m5-2026-10-27/reconnect.txt`, `heartbeat-liveness.txt` |
| Isolation, live-lab suite | `afw lab verify`; `AFW_LAB=1 pytest tests/lab` | live | 2026-10-27 20:59–21:00 | `m9-2026-10-27/` |
| A3 selection (run once) | `a3_run.py <snap> select …` | `a3-sel`, `a3-sel-shift` (+ `p7-train`/`p7-val` for training) | capture 2026-10-29 03:11–04:13; run ~05:30 | `a3-2026-10-29/select/` |
| NV1 calibration and test (once) | `nv1_eval.py <snap> dev …`, then `test …` | `nv1-train`, `nv1-val`; test `a3-sel`, `a3-sel-shift` | same capture; test ~05:40 | `nv1-2026-10-29/` |
| NV2 calibration and test (once) | `nv2_eval.py <snap> dev …`, then `test … nv2-dev1.calibration.json c311aeeb…` | `nv2-train`, `nv2-val`; test `nv2-test`, `nv2-test-shift` | capture 2026-10-29 07:32–08:35; test ~08:45 | `nv2-2026-10-29/` |
| A3 final evaluation (once) | `a3_run.py <snap> final … cand-S.pkl` | `p6-final`, `p6-final-shift`, `p6-final-v1` (+ preserved P1 sets) | capture 2026-10-29 05:42–06:29; run ~06:35 | `a3-2026-10-29/final/a3-final.json` |
| Telemetry latency | `a3-2026-10-29/tools/latency.sh` | live, marked benign requests | 2026-10-29 ~05:35 | `a3-2026-10-29/telemetry-latency.txt` |
