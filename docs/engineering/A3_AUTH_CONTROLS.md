# A3: account-aware, endpoint-scoped authentication protection (amendment to P6/P7)

Status: **protocol, written 2026-10-29 ~03:30Z, before any A3 data exists.** Authorized
by the project owner on 2026-10-29 ("I authorize developing a revised AUTH protection
design under a new predeclared amendment A3"). Results are added in §8 only. Nothing in
§1–§7 changes after the A3 selection data is collected. Any later change is a new, dated
amendment with its reason.

## 1. Problem

P7 (`P6_GENERALIZATION_AND_SENSITIVITY.md` §8.4) failed for D, F, S and FS on a single
cause. A legitimate "forgetful" user (10.77.20.155) failed ≥ 5 logins at ≥ 50 % within
30 s. The AUTH evidence rule fired, and ADR-039 then rate-limited the **whole address**
for 120 s.

The old rule has three weaknesses:

1. **It is account-blind.** Five typos spread over two quick logins of one person look
   the same as five guesses against a victim account.
2. **It is window-bound.** It needs 5 failures inside one 30 s window. A guesser at one
   attempt per 20 s never meets it. Windows need ≥ 3 requests, so a slow guesser is not
   even assessed.
3. **Its response is too broad and too weak.**
   - Too broad: a site-wide rate limit on the address affects everyone behind it,
     including everything they do besides logging in.
   - Too weak: the STRICT profile is 1 request/s with a burst of 5, which does not slow a
     1 guess/s attacker at all.

## 2. Design (fixed parameters)

### 2.1 Account-aware AUTH evidence

**Per-account failure streak.** The controller keeps, per source address and per account
(`username_hash`), the login outcomes reported by the application within a lookback of
**L = 900 s**.

The *streak* of an account is the number of failed logins from that source since that
account's most recent successful login from that source, counting only attempts inside
L.

**What counts as an attempt:**
- Only attempts the application answered count, i.e. those with an `auth_outcome`.
- Requests refused by the WAF (429/403) never reached the application. They are counted
  separately as *rejected login attempts*.
- Attempts with an outcome but no `username_hash` count under one pseudo-account, so
  missing telemetry cannot hide guessing.

**Evidence.** At an assessment time *t*, a source has AUTH evidence only if it had a
failed login in (t − 30 s, t], or a success in that interval (case iii). The rules:

| Code | Condition | Points |
|---|---|---|
| `account_guessing` | some account's streak ≥ **5** | 15 + min(10, streak − 5) |
| `credential_spraying` | ≥ **3** accounts with streak ≥ 1 and the sum of their streaks ≥ **5** | 20 + min(10, sum − 5) |
| `success_after_guessing` | a successful login in (t − 30 s, t] for an account whose streak just before was ≥ **5** | 25 |

- When several rules apply, the highest points count. The category is AUTH (cap 30, as
  before).
- References are the failed (or successful) login request ids, newest 10.
- A failure followed by a success of the same account clears that account's streak. A
  user who mistypes and then logs in therefore builds no evidence. A guesser who never
  succeeds keeps building it, at any speed slower than one attempt per 15 min × 5.
- The old window rule (≥ 5 failures at ≥ 50 % within the window) is **removed**.

Threshold 5 is the existing rule's number. It is kept, not tuned. NIST SP 800-63B
permits up to 100 consecutive failures before lockout, so 5 is conservative.

**AUTH-only view.** A source with new failed logins but no HTTP window (fewer than 3
requests in 30 s) is still assessed: on each controller tick, an assessment with only
AUTH evidence is produced, like the IDS-only view. Slow guessing is no longer invisible.

### 2.2 Graduated response for authentication evidence

| Situation | Response (new) | Before |
|---|---|---|
| AUTH evidence plus another independent category, score ≥ block band | SOURCE_BLOCK (unchanged; shared addresses: strict rate limit for human approval, ADR-043) | same |
| AUTH evidence, no login control active | **LOGIN_THROTTLE** on the source: the application's login routes only (`POST /login`), **3 requests per minute, burst 4** (nginx `limit_req`, nodelay), **900 s** | site-wide rate limit, 120 s |
| AUTH evidence while a LOGIN_THROTTLE is active, and ≥ **10** failed logins from the source since it started | **LOGIN_DENY**: 403 on the login routes for the source, 900 s | — |
| AUTH evidence and a login control on the source ended within the last hour (repeat) | LOGIN_DENY directly, duration doubled per repeat (900 → 1800 → 3600 s, cap 3600) | — |
| Shared address (≥ 3 accounts logged in successfully within 1 h, ADR-043) | LOGIN_THROTTLE automatic; LOGIN_DENY **always needs human approval** | — |
| Behaviour-only evidence | Observe only (A2.3 in replay; the live setting stays as a human set it) | same |
| WAF or IDS evidence below the block band | Site-wide rate limit as before | same |

A login control never touches anything except the login routes. A legitimate user behind
a throttled address can still browse, book and use an existing session.

**Automatic bounds.**
- LOGIN_THROTTLE is auto-eligible up to 900 s.
- LOGIN_DENY is auto-eligible up to 3600 s, except on shared addresses.
- The live controller stays in **monitor** mode, where nothing is applied. Changing the
  mode is a human decision.

### 2.3 Enforcement

The WAF helper gets a separate desired-state field, `login_controls`
(`{address: "throttle" | "deny"}`), rendered as an exact-match location for each login
route. That location repeats the site-wide rate zones (nginx does not inherit
`limit_req` into a location that sets its own) and adds:
- the login zone, keyed only for throttled addresses;
- a deny map, for denied addresses.

The usual read-back applies: served revision, plus the state echoed by the helper.

## 3. Data

- **Training and calibration:** `p7-train`, `p7-val`, unchanged. These are not selection
  data and may be reused. The candidates are retrained exactly as in P7 (seed 42); a
  sha256 match with the P7 pickles is checked and reported.
- **New selection data, collected after this protocol is committed.** Generator
  `traffic/benign_personas.py` at the commit that adds this file. Its web journeys are
  identical to the A2 generator for the same seeds; this is checked by a recorded
  equivalence test.

| Dataset | Users (10.77.20.x) | Seed | Mode | Role |
|---|---|---|---|---|
| `a3-sel` | .140–.155 (16) | 913 | v2 personas | A3 selection |
| `a3-sel-shift` | .156–.161 (6) | 914 | shared | A3 selection, workload shift |

- The users also run the NV1 network activity (`AFW_NET=1`, separate random stream). It
  adds no HTTP requests.
- Duration 60 min.
- Phase E (`p6-final*`, .170–.197, seeds 701–703) stays untouched until a candidate is
  frozen.

The P6/P7 selection sets are consumed and are not used for anything in A3.

## 4. Measurements

### 4.1 Benign: on `a3-sel` and `a3-sel-shift`, per candidate (R2, R3, D, F, C, S, FS), replayed with A3

- **B1.** Enforcing-detector window FPR on `a3-sel`, with a 95 % bootstrap CI over
  users. This is the P6 §6 measure, unchanged.
- **B2.** Legitimate users who receive a **site-wide** restriction (SOURCE_BLOCK or
  RATE_LIMIT).
- **B3.** Login controls on legitimate users:
  - users with any LOGIN_THROTTLE or LOGIN_DENY;
  - legitimate login requests that would have been refused (429 or 403). These are
    computed with nginx's exact `limit_req` semantics on the recorded request times:
    ```
    excess ← max(excess − rate·Δt, 0) + 1
    refuse if excess > burst
    ```
  - as a share of all legitimate login requests.
- **B4.** Legitimate request success: 1 − (requests inside a site-wide restriction +
  refused login requests) / legitimate requests.

### 4.2 Attack resistance: SYNTHETIC sequence level, no traffic sent, never a detection claim

A closed-loop simulation of one guessing source (10.77.10.250, ATTACK zone) against the
A3 AUTH logic and the enforcement it produces:
- **Rejected attempts.** Attempts that a control in force refuses (limiter or deny)
  never reach the application and do not count as failures.
- **Timing.** Decisions run every 5 s (the live tick) with the AUTH-only view. The
  attacker never succeeds.
- **Baseline.** A2's response, modelled at its **most favourable**: a 1 r/s, burst 5,
  site-wide limit for 120 s, imposed at the first 30 s window with ≥ 5 failures at
  ≥ 50 %, re-imposed whenever that recurs.
- **What it measures.** ML block paths are left out of both arms, since they can only
  add protection. A3's result is therefore a lower bound on its protection, and the
  baseline an upper bound on A2's.

| Family | Attempt pattern, 60 min | Raw attempts |
|---|---|---|
| AR1 fast single-account guessing | 1 per s, one account | 3600 |
| AR2 slow single-account guessing | 1 per 20 s, one account | 180 |
| AR3 fast credential spraying | 1 per s, a new account each | 3600 |
| AR4 slow spraying | 1 per 60 s, a new account each | 60 |

Measured per family:
- guesses that reach the application in 60 min;
- time from the first attempt to the first control.

Also reported, but not a criterion, as **SYNTHETIC** legitimate-friction stress:
- a user who mistypes k = 4, 6 or 8 times (1–4 s apart) and then logs in;
- measured: the refused requests and the delay until the successful login, under A3 and
  under the A2 baseline.

## 5. Acceptance criteria (selection, run once)

A candidate is eligible if:

1. **B1** as before: every enforcing detector FPR ≤ 0.02 with upper CI ≤ 0.05 on
   `a3-sel`.
2. **B2:** no legitimate user receives a site-wide restriction on `a3-sel` or
   `a3-sel-shift`.
3. **B3:**
   - refused legitimate login requests ≤ **0.5 %** of legitimate login requests on each
     set;
   - at most **1** legitimate user per set receives any login control.
4. **B4:** legitimate request success ≥ **0.99** on each set.
5. **Attack resistance** (rule-based, the same for every candidate; evaluated once):
   - accepted guesses ≤ **25 %** of raw attempts for AR1, AR2 and AR3, and ≤ **50 %**
     for AR4;
   - accepted guesses ≤ the A2 baseline for every family;
   - time to first control ≤ **60 s** (AR1, AR3), ≤ **300 s** (AR2) and ≤ **600 s**
     (AR4).

If criterion 5 fails, A3 fails for every candidate, and that is reported.

**Selection among eligible candidates:** unchanged (P6 §6 step 2 with A1, and step 3).

**Freeze and final evaluation:** the selected candidate, the A3 code and this protocol
are frozen in a commit. Phase E data (`p6-final`, `p6-final-shift`, `p6-final-v1`, as
predeclared in P6 §2) is then collected and the final evaluation runs **once**:
- P6 final criteria 1, 3, 4 and 5 (A1), unchanged;
- criterion 2 replaced by B2 + B3 + B4 on each Phase E set;
- criterion 5 re-checked on Phase E bases.

## 6. Promotion

- A candidate that passes the final evaluation is **eligible** for promotion. Promotion
  itself is a human action through the existing gate (ADR-030/040) with probation and
  automatic rollback.
- Passing does not switch the controller out of monitor mode.
- If no candidate is eligible, nothing is frozen, Phase E is not collected, and v2
  remains the trusted profile.

## 7. Known limitations, stated before the results

- **The legitimate population is generated.**
  - The forgetful archetype mistypes at most 3 times, so on generated data the
    account-aware rule is expected to give it no evidence.
  - A real user who fails 5 times in a row on one account does get a login throttle.
    The friction stress in §4.2 reports what that costs them.
- **Compromised accounts.** An attacker who has the right password for some accounts
  can clear only those accounts' streaks, not the streak of an account being guessed.
  Distributed guessing (many sources, few attempts each) remains outside a per-source
  rule.
- **Password spraying.** Spraying one password across many accounts from many
  addresses, slowly, is not detected by a per-source rule.
- **Synthetic attack resistance.** It measures the controls' arithmetic and the decision
  logic, not real attack tools. Real guessing runs from ATK01
  (`TEAM_ATTACK_QUICKSTART.md`, `web-bruteforce-login`, `low-and-slow-bruteforce`) are
  the independent check.

## 8. Results

### 8.1 Selection (2026-10-29, run once ~05:30Z)

*Data.* Capture 03:11:16–04:13:00Z (commit `a7d10e7`):
- `a3-sel`: 16 users, 17 503 requests, 1 242 legitimate logins;
- `a3-sel-shift`: 6 shared addresses, 4 179 requests, 595 logins.

All validation checks passed, and observation counts equal the WAF01 access-log lines.
Driver: `artifacts/evidence/a3-2026-10-29/a3_run.py`. Report: `select/a3-select.json`
(470 s).

*Reproducibility.* The retrained candidates' byte sha256 differ from the P7 pickles. The
causes are:
- random model and profile ids;
- artifact paths in the snapshot;
- measured latency in the validation metrics;
- sklearn pickles, which are not byte-deterministic.

Functionally they are identical: every fitted array is equal, and the score difference
on 3 000 random inputs is 0.0 for every detector of every candidate
(`repro_check.py`, `select/repro-check.txt`).

*Eligibility (§5).*

| Candidate | B1 FPR (`a3-sel`) | B2 | B3 refused logins / controlled users | B4 | Must-detect min (nominal / stressed) | Eligible |
|---|---|---|---|---|---|---|
| R2 | robust 0.330, IF 0.931 | 0 | 0 / 0 | 1.0 | 1.0 / 0.82 | no (B1) |
| R3 | robust 0.033, IF 0.561 | 0 | 0 / 0 | 1.0 | 1.0 / 0.70 | no (B1) |
| D | ≤ 0.0031 (CI ≤ 0.0069) | 0 | 0 / 0 | 1.0 | 0.75 / 0.43 | yes |
| F | ≤ 0.0008 | 0 | 0 / 0 | 1.0 | 0.94 / 0.71 | yes |
| C | ≤ 0.0039 (CI ≤ 0.0084) | 0 | 0 / 0 | 1.0 | 0.83 / 0.46 | yes |
| **S** | ≤ 0.0031 (CI ≤ 0.0069); security 0 | 0 | 0 / 0 | 1.0 | **1.0 / 1.0** | yes, **selected** |
| FS | ≤ 0.0008; security 0 | 0 | 0 / 0 | 1.0 | 1.0 / 1.0 | yes |

B2–B4 hold on both sets for every candidate: no site-wide restriction, 0 of 1 837
legitimate logins refused, no legitimate user with a login control. S and FS tie at
1.0, and step 3 prefers the simpler S.

*Criterion 5 (SYNTHETIC, rule-based, no traffic sent): pass.*

| Family | Raw | A3 accepted (share) | A3 first control | A2 baseline accepted | A2 first control |
|---|---|---|---|---|---|
| AR1 1/s, one account | 3 600 | 25 (0.007) | 5 s | 3 600 | 5 s (limit never binds at 1 r/s) |
| AR2 1/20 s, one account | 180 | 25 (0.139) | 85 s | 180 | none |
| AR3 1/s spraying | 3 600 | 25 (0.007) | 5 s | 3 600 | 5 s |
| AR4 1/min spraying | 60 | 20 (0.333) | 245 s | 60 | none |

Friction (a user mistyping k = 4, 6 or 8 times, then entering the right password): 0
refused attempts under A3. The user logs in at the same moment as without controls (6.7,
15.1 and 18.7 s).

*How strong the benign result is (§7, as predicted).* Neither set came near the AUTH
thresholds (`auth_profile.py`, `select/auth-profile.txt`):
- The longest legitimate per-account failure run was 3.
- The most open streaks on one source at any time was 1 account with 3 failures.
- On the shared addresses (up to 44 accounts each), every mistyped account succeeded
  before another failed. The most there was 1 open account with 1 failure.

So B3 shows that the generated population is untouched. It is not evidence about real
users who fail 5 or more times; the friction runs above are the evidence for that case.

*Decision.* Candidate **S** is frozen with:
- `select/cand-S.pkl`, sha256 `8994dfe8…ec70`, recorded in `select/cand-S.json`;
- a backup outside the repository;
- the A3 code at this commit;
- the final stage of `a3_run.py`, whose criteria F1–F5 are written in its docstring
  before any Phase E data exists.

Next steps under §5: collect Phase E (`p6-final*`, .170–.197, seeds 701–703), then run
the final evaluation once. Nothing is promoted by this result; the controller stays in
monitor mode.

*Note added 2026-10-29 ~06:45Z, after the final evaluation (factual omission in §8.1, no
criterion change).* On `a3-sel-shift`, S's security path flagged **0.1756** of windows
(72 of 410, shared addresses). B1 is measured on `a3-sel` only, so this was not a
criterion, but §8.1 should have reported it as a warning sign. It had no decision
effect: 0 requests impacted.

### 8.2 Final evaluation on Phase E (2026-10-29, run once ~06:35Z): **FAIL (F1)**

*Data.* Phase E capture 05:42:35–06:29:00Z (commit `58d7ad1`), under the predeclared P6
script with the A3 generator:
- `p6-final`: 16 users, 19 400 requests;
- `p6-final-shift`: 6 shared addresses, 2 944 requests;
- `p6-final-v1`: 6 v1 users, 1 670 requests.

All 48 validation checks passed, and counts equal the WAF01 log. Frozen S was verified
by sha256 `8994dfe8…ec70`. Report: `final/a3-final.json` (206 s).

| Criterion | Result | |
|---|---|---|
| F1 enforcing FPR on `p6-final` | robust 0.004, IF 0.007, **security 0.0475 [0.0, 0.1402]** | **fail** |
| F2 B2/B3/B4 on each Phase E set | no site-wide restriction; 0 of 2 418 legitimate logins refused; no login control; success 1.0, 1.0, 1.0 | pass |
| F3 nominal must-detect | 1.0 for every family | pass |
| F4 versus R2 | equal (1.0) | pass |
| F5 stressed must-detect | 1.0 for every family (R2 stressed: 0.63–1.0) | pass |
| A3 criterion 5 (SYNTHETIC) | unchanged, pass | pass |

**S is not eligible for promotion.** v2 remains the trusted profile, and the controller
stays in monitor mode.

*Diagnosis (post-hoc, no re-test):*
- All 47 flagged `p6-final` windows come from the 2 **household** users (2–4 accounts
  behind one address: 47 of their 133 windows). Every other archetype has 0.
- The security path's calibrated `distinct_usernames` level is 1.0: no window in
  `p7-val` had two usernames. So any legitimate multi-account address flags.
- Selection could not see this. `a3-sel`'s random archetype draw contained no
  household user. The shared-address sets showed it (0.176 and 0.135), but B1/F1
  measure the main set only.

*Preserved sets (reported, P1 criteria).* S's robust and IF FPR are ≤ 0.011 on all four.
Its security path flags 82–100 % of windows there (old-regime data, multi-account
generator and 404 artifacts), against R2's enforcing 0.09–0.73.

*What the result shows.*
- The **A3 controls** resolved the conflict they were built for. Across 4 255 legitimate
  logins on 5 unseen sets, including shared addresses, none was refused, no user got a
  login control, and nobody was restricted site-wide.
- The SYNTHETIC attack-resistance arithmetic holds.
- What failed is the ML candidate's **security path**, on legitimate multi-account
  addresses.

A further attempt needs:
- a new predeclared amendment (for example, `distinct_usernames` calibrated on data
  that includes household users, or that quantity scored only together with failures);
- stratified archetype coverage in selection;
- B1/F1 on the shared sets too;
- **new** selection and final data. Phase E is now consumed.

That choice is left to the owner.

