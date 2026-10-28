# P6: a model that generalizes to unseen users and stays sensitive

Status: protocol written 2026-10-28 ~13:15Z, while the Phase C development data was
being collected and **before any P6 data was analysed**. Results are added in later
sections; nothing in §1–§6 changes after analysis starts (amendments, if any, are
dated and listed in §7 with their reason).

## 1. Question

P1 showed a trade-off. v2 (one 5.4-minute training run) restricts 13/16 unseen
legitimate users. v3 (plus 45 minutes of varied personas) restricts none, but its ML
detectors lose sensitivity to single security-relevant changes, because benign variety
widens what counts as normal. Can a better training and validation strategy, and/or
model structure, give low false positives on unseen users and workload shifts
**without** that sensitivity loss? And can sensitivity be protected so that online
adaptation can never silently weaken it?

## 2. Data

All benign, real lab traffic from USR01 through FW01 and the WAF, authenticated
telemetry, one thread per user. Generator `traffic/benign_personas.py`.
`AFW_PERSONA_SET=v2` adds legitimate archetypes: casual, regular, forgetful (up to 3
mistyped passwords before the right one), power, household (2–4 accounts behind one
address), stale (outdated car links, 404), slow, city (filtered listing). Weights are
3:3:1:1:1:1:1:1.

**Generator finding (recorded before analysis).** The v1 generator omits the required
`city` field, so every v1 booking request returns 422. In addition the deployed app is
v1, so every `GET /cars/{id}/reviews` returns 404. Both are legitimate-looking client
errors present in **all earlier benign data** (P1, the 10-17 runs). v2 sends a valid
booking body; the reviews 404s remain, since that is how the deployed app behaves. So
the v1 and v2 data differ in their client-error mix, which is a real workload
difference and is kept.

Addresses never overlap between datasets, nor with any earlier dataset (P1 used
.10–.82; the generator smoke tests used .90–.97 and are discarded).

| Dataset | Users (10.77.20.x) | Seed | Phase / time | Role |
|---|---|---|---|---|
| `p6-train` | 24 (.100–.123) + 4 stratified (.136–.139: forgetful, slow, power only, seed 605) | 601 | C, 13:07:45Z + 90 min | training |
| `p6-val` | 12 (.124–.135) | 602 | C, same period | calibration (thresholds) |
| `p6-sel` | 16 unseen (.140–.155) | 603 | D, after C, 45 min | model selection |
| `p6-sel-shift` | 6 (.156–.161), `AFW_MODE=shared` (the 10-27 workload) | 604 | D, same period | selection, workload shift |
| `p6-final` | 16 unseen (.170–.185) | 701 | E, **after selection is frozen**, 45 min | final test |
| `p6-final-shift` | 6 (.186–.191), shared | 702 | E | final, workload shift |
| `p6-final-v1` | 6 (.192–.197), P1 v1 personas | 703 | E | final, earlier persona population |

Phase C's random archetype draw gave `p6-train` no forgetful user and one slow user. The
4 stratified users were added 20 s after the start, so every archetype appears in
training. This is a design choice about coverage, made before analysis.

**Preserved sets, not used for selection.** `p1-test`, `p1-shift`, `real-drift-hold`
and `real-benign-train` (old regime) keep their P1 role. They are evaluated **once**,
for the final selected model only, and reported against the P1 criteria.

**Training and calibration unions.** Training uses `real-benign-train2`, `p1-train` and
`p6-train`; calibration uses `real-benign-val`, `p1-val` and `p6-val`. A candidate may
use a subset if that is its design (stated in §3).

## 3. Candidates (compared on the selection sets only)

| Id | Design | Purpose |
|---|---|---|
| R2 | v2, frozen as trusted | reference |
| R3 | v3, frozen P1 candidate | reference |
| D | current detectors (robust stats, IF, HST), bootstrap recipe, P6 unions | effect of more and more diverse data |
| F | D with evidence-weighted features: each fraction replaced by its one-sided 95 % Wilson lower bound given its count (`auth_fail_frac` given login outcomes; `client_err_frac`, `server_err_frac`, `unknown_route_frac`, `novel_method_frac` given requests) | a single typo or 404 in a 3-request window is weak evidence; 20 of 20 is strong. Volume-aware fractions should cut FPs without hiding sustained attacks |
| S | D plus an independently calibrated, one-sided **security path** (§4) | sensitivity that does not depend on the learned benign spread |
| FS | F + S | combination |
| C | D with per-cohort thresholds (windows with login attempts vs without), same target FPR per cohort | cohort-specific baselines |

The current pipeline, unchanged, is used for everything else: windows (30 s length, 5 s
hop, at least 3 requests), the target FPR of 0.01 on calibration windows, and seed 42.
Simpler wins ties.

## 4. Security path (candidate S)

A detector over the security-relevant quantities. It is **one-sided**: only higher
values than benign are suspicious. Its thresholds can only be tightened by data, never
loosened past fixed ceilings.

* **Quantities.** Per window:
  * `auth_failures` (count);
  * `auth_fail_frac` (Wilson lower bound);
  * `distinct_usernames`;
  * `login_rate`;
  * `client_errors` (plain count of 4xx; legitimate windows include the reviews
    404s, so this one is calibrated, not assumed zero);
  * `unknown_route_frac` (Wilson LB);
  * `novel_method_frac` (Wilson LB).
* **Calibration.** Per quantity, the threshold is the (1 − α/k) quantile of the
  calibration windows, with k = 7 quantities and α = the target FPR. This bounds the
  path's window FPR at about α on calibration data.
* **Ceilings.** Each threshold is then capped by a fixed, human-set ceiling that marks
  an unambiguous attack-sized value:

  | quantity | ceiling |
  |---|---|
  | auth_failures | 6 |
  | distinct_usernames | 5 |
  | login_rate (per min) | 24 |
  | client_errors | 25 |
  | auth_fail_frac LB | 0.6 |
  | unknown_route_frac LB | 0.5 |
  | novel_method_frac LB | 0.5 |

  The threshold used is min(calibrated, ceiling). A broader benign population can
  therefore never make, for example, 6 failed logins in 30 s look normal.
* **Score and flag.** Score = max over quantities of value / threshold. A window is
  flagged when the score is ≥ 1.
* **Online adaptation.** The ceilings are configuration, not learned state. Online
  learning never updates this path. A change to a ceiling needs a reviewed commit.

The ceilings were chosen from the application's semantics, not from data: the AUTH
evidence rule already treats 5 failures at ≥ 50 % as attack evidence; 5 usernames
from one address exceeds the household archetype's maximum of 4; 24 logins/min is
12 in a 30 s window; 25 errors in 30 s is about 0.8 per second; and half of all
requests to unknown routes or methods is enumeration-shaped. Legitimate archetypes
that can reach a ceiling (e.g. a large office NAT) are a known limitation (§6).

## 5. Measurements

On every evaluated benign set, with denominators (as in P1):

* tumbling-window FPR per detector, with a 95 % bootstrap CI over users;
* users with any flagged window; requests inside flagged windows;
* the same broken down per archetype (hard benign cases);
* decision level (M0/M1/M2 replay): users restricted, legitimate request success. This
  applies to candidates expressible as the current detector kinds; for S/FS, the
  security path's decision effect is reported as the union of its flags with M2's
  restrictions, which is a conservative upper bound on extra harm.

**Malicious-behaviour regression suite (synthetic, labelled as such).** No network
traffic is sent. Real benign base windows from the evaluated set (tumbling, at most one
per user per 5 minutes) receive synthetic observations spread uniformly over the
window. Features are then recomputed by each candidate's own feature function. Families
and intensities, with the must-detect level in bold:

| Family | Added to the window | Intensities |
|---|---|---|
| brute_force | k failed `POST /login`, one username | 3, 5, **10**, 20 |
| stuffing | k failed logins, k usernames | 3, 5, **10**, 20 |
| enumeration | k `GET` to unknown routes, 404 | 5, 10, **20**, 40 |
| idor | k `GET /booking/{id}`, 404 | 5, 10, **20**, 40 |
| scraping | k `GET /cars/{id}`, 200, evenly spaced | 20, 40, 80, 160 (no must level: behavioural, reported) |

These cases measure **sensitivity regression only**. They are not attack-detection
results and are never reported as such; those need the team's runs
(`P3_TEAM_ATTACK_RUNBOOK.md`).

**Sensitivity of a candidate** = the flag rate of its enforcing detectors (robust stats
OR IF, plus S where present), and of each detector separately, per family and intensity.

## 6. Selection rule and final criteria

**Selection, on `p6-sel` and `p6-sel-shift`; may be run repeatedly.**

1. Eligible: every enforcing detector has FPR ≤ 0.02 on `p6-sel` (upper CI ≤ 0.05);
   M2 restricts no user on `p6-sel` and `p6-sel-shift`.
2. Among eligible candidates, maximise the minimum enforcing-detector flag rate over the
   must-detect cases.
3. If that minimum is equal within 0.02, prefer the simpler design (R/D < F, C < S <
   FS).

The selected candidate, its training and calibration data and its code are frozen in
a commit **before** Phase E data is collected.

**Final criteria, evaluated once on Phase E.**

1. `p6-final`: every enforcing detector FPR ≤ 0.02 and upper CI ≤ 0.05.
2. M2 restricts no user on `p6-final`, `p6-final-shift` and `p6-final-v1`; legitimate
   request success ≥ 0.99 on each.
3. Must-detect regression cases on `p6-final` bases: enforcing flag rate ≥ 0.95 for each
   family.
4. Not worse than v2 on the must-detect cases (difference ≥ −0.05 per family).

The preserved P1 sets are reported for the selected model against the P1 criteria.
Failures are reported, not tuned away.

**Known limitations, stated before the results.**

* The regression suite is synthetic and feature-shaped. It cannot show recall on real
  attacks.
* All "users" are generated personas on one host, and the archetypes are our model of
  legitimate variety.
* A large legitimate NAT can exceed the username ceiling.

## 7. Amendments

**A1 (2026-10-28 ~13:55Z, before any selection or final data existed).**

*Why.* A smoke check of the harness, on P1 training and calibration data only, showed
every candidate at 1.0 on the must-detect cases. The selection rule therefore could
not separate candidates on the question in §1: sensitivity that does not *silently
weaken under adaptation*. That needs an adaptation stress test.

*Adaptation stress.* Each candidate's adaptable thresholds are recalibrated at the
same target FPR on its calibration windows plus a stress set:
* the detector thresholds;
* for S/FS, the calibrated part of the security path (its ceilings are fixed).

The stress set is sub-must attack-shaped windows labelled "benign", amounting to 3 %
of the calibration windows. They are built on `p6-val` bases with the families at
their second intensity (brute_force 5, stuffing 5, enumeration 10, idor 10, in equal
shares).

This emulates retraining on drifted or poisoned data that the eligibility filters did
not catch. Profiles and fitted models are unchanged. The must-detect flag rates are
then re-measured on the selection bases.

*Selection rule, step 2, replaced by:* maximise the minimum, over the must-detect
cases, of the **lower** of the nominal and the stressed enforcing flag rate. Step 1
(benign eligibility) and step 3 (tie-break) are unchanged.

*Final criteria.* A fifth criterion is added: under the same stress, built on
`p6-val` bases and evaluated on `p6-final` bases, the must-detect enforcing flag rate
is ≥ 0.95 for each family.

**A2 (2026-10-28, committed 16:30:35Z in `a197a87`, after the Phase D selection failed (§8), before any P7
data existed; Phase E not collected).** Each change answers a cause demonstrated in §8
on the consumed selection data. No acceptance criterion changes.

1. *Generator.* Legitimate users no longer request routes the deployed application
   does not serve. `traffic/benign_personas.py` asks the app its version once
   (`GET /`) and requests the review endpoints only on app 2.x (`AFW_APP_REVIEWS=auto`).
   Every random draw is kept, so personas behave as before otherwise. Applies to all new
   data, including Phase E (same addresses and seeds as §2).
2. *Training data.* Candidates D, F, C, S, FS are trained on `p7-train` and calibrated
   on `p7-val` only. All earlier generated data carries the artifact (§8.3) and is not
   used for training. R2 and R3 are the stored v2/v3 profiles, unchanged.
3. *Decision rule.* Every candidate, references included, is replayed with
   `safety.behavior_only_rate_limit = False`: behaviour-only evidence is observe-only,
   as the documented invariant says. The setting stays `True` on the live controller;
   switching it there needs human authorization.
4. *Unchanged:* candidate definitions, selection rule, final criteria 1–5, A1 stress,
   the AUTH evidence rule and ADR-039, the Phase E sets.

P7 data (USR01, same lab path; addresses reused for the same roles with new persona
draws; no P6 data is used for training, and no P6/P7 training, calibration or
selection address is a Phase E address):

| Dataset | Users (10.77.20.x) | Seed | Phase | Role |
|---|---|---|---|---|
| `p7-train` | .100–.123 + .136–.139 (forgetful, slow, power) | 811, 815 | C′, 90 min | training |
| `p7-val` | .124–.135 | 812 | C′ | calibration |
| `p7-sel` | .140–.155 | 813 | D′, 45 min | selection |
| `p7-sel-shift` | .156–.161, shared | 814 | D′ | selection, workload shift |
| `p6-final`, `-shift`, `-v1` | .170–.197 | 701–703 | E, after the freeze | final, unchanged |

Driver: `artifacts/evidence/p7-2026-10-28/p7_run.py` (a copy of `p6_run.py` with only
the changes above).

*Predicted before data, not tuned away.* A forgetful user who fails ≥ 5 logins at ≥ 50 %
within 30 s meets the AUTH rule; ADR-039 then gives a rate limit by design (§8.2). If
that happens on `p7-sel`, every candidate is ineligible again, and the result is
reported as a conflict between the brute-force rule and that archetype. Resolving it
(the rule, the archetype or the criterion) is a human decision.

## 8. Results

### 8.1 Phase D selection (2026-10-28, run once)

Data: `p6-sel` 38,932 observations, 16 users, 1,085 tumbling windows; `p6-sel-shift`
3,607 observations, 6 users, 307 windows. All validation checks passed; both counts
equal the WAF01 access log (zero loss). Evidence: `artifacts/evidence/p6-2026-10-28/
select/` (report `p6-select.json`; candidate sha256 in `cand-*.json`, pickles not in Git).

**No candidate is eligible; nothing was selected or frozen; Phase E was not collected.**

| Cand. | RS FPR (CI) | IF FPR (CI) | Security FPR | M2 users restricted sel / shift | Must-detect min nominal / stressed |
|---|---|---|---|---|---|
| R2 (v2) | 0.261 (0.094–0.454) | 0.430 (0.281–0.594) | – | 12/16, 6/6 | 1.00 / 0.35 |
| R3 (v3) | 0.104 (0.010–0.228) | 0.018 | – | 5/16, 3/6 | 1.00 / 0.55 |
| D | 0.012 | 0.021 (0.008–0.041) | – | 5/16, 2/6 | 0.51 / 0.17 |
| F | 0.011 | 0.015 | – | 1/16, 5/6 | 0.60 / 0.37 |
| C | 0.012 | 0.020 (0.007–0.040) | – | 7/16, 4/6 | 0.56 / 0.02 |
| S | 0.012 | 0.021 | 0.068 (0–0.164) | 5/16, 2/6 | 0.91 / 0.63 |
| FS | 0.011 | 0.015 | 0.068 (0–0.164) | 1/16, 5/6 | 0.96 / 0.83 |

On the workload-shift set every retrained candidate's Isolation Forest flags 9–13 % of
windows (R2: 75 %).

Decomposition (S, `p6-sel` bases, IDOR@20, the limiting family): ML-only (RS or IF)
0.51, security-path-only 0.46, combined 0.91; under stress 0.17 / 0.46 / 0.63. The
security path does not hide weak ML here; neither part is sufficient alone.

### 8.2 Why every candidate failed (diagnosis on the consumed selection data)

* **Behaviour-only rate limits.** Every M2 restriction of a legitimate user, for D, F,
  C and R3 on both sets, was a MODERATE rate limit where the only corroboration was
  behaviour and the statistical and ML detectors agreed (`decision.py`,
  `detectors_agree`), except one forgetful user (below). This path dates from the first
  replay runner (`e35e4cd`), has no ADR or test, and contradicts the engine's own rule
  that both detectors are one corroboration category and the documented invariant that
  an anomaly alone never authorizes a traffic-affecting change. Restricted users had
  1–4 such decisions each (isolated windows). (`select/diagnosis-restrictions.json`)
* **Forgetful user and the brute-force rule.** User .155 (forgetful archetype, up to 3
  typos per login, frequent logins) reached ≥ 5 failed logins at ≥ 50 % in a window;
  AUTH plus the dependent behaviour points gave a rate limit, as ADR-039 intends for
  brute force.
* **A generator/app mismatch in all legitimate data (§8.3).** It explains the security
  path's false positives (`client_errors` ceiling: 70 of its 74 flags, all on two power
  users) and the retrained candidates' blindness to IDOR (they learned bursts of 404s as
  normal; R2/R3 detect IDOR@20 at 1.0, the retrained candidates at 0.51–0.60).

### 8.3 Data defect: 22–29 % of all generated legitimate requests were errors

Both persona journeys requested `/cars/{id}/reviews` (and posted `/reviews`), which the
deployed v1 application does not serve (404). Client-error share per dataset: p6-train
27.8 %, p6-val 25.0 %, p6-sel 27.2 %, p1-train 28.8 %, p1-val 29.4 %,
real-benign-train2 22.1 %, real-benign-val 23.8 % (plus 422 bookings in v1 data). §3.2
noted the 404s but not their size. Every earlier benign model and FPR in this project
was trained and measured on this population; that does not invalidate the comparisons
between them, but legitimate traffic in the lab looked less clean than real users, and
404-driven detections (IDOR, enumeration) were learned against an inflated baseline.
Fixed in the generator (A2.1).
