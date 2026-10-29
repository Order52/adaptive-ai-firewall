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

(Empty until the selection has run.)
