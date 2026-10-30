# NV2: network novelty, second predeclared validation

Written 2026-10-29 ~07:20Z, **before any NV2 data exists**. It follows NV1
(`NV1_NETWORK_NOVELTY_VALIDATION.md`), which failed its one-shot test (§7). §1–§6 do
not change after the data is collected. Results are added in §7.

## 1. What NV1 showed, and the two changes

NV1's test on 22 unseen users gave two findings:
- **unfamiliar 0.0678** [0.0088, 0.1575];
- **one legitimate user with a strong verdict**.

Its post-hoc diagnosis, on consumed data, found two causes. Each change below answers
one of them; nothing else changes.

1. **Host-sweep ceiling on the wrong quantity.**
   - *Diagnosis.* The strong verdict was 1 DNS resolver plus 11 *answered* internet web
     servers on TCP 443 (CDN hosts) within 60 s. That is ordinary browsing, yet it met
     the `dst_hosts_60` ceiling of 10 (`nv1_dst.py` diagnosis, recorded in §7 of NV1
     and here).
   - *Change.* A new quantity, `sweep_hosts`: distinct destinations of residual flows
     that are internal (private address) or failed (no answer or reset before data).
     The ceiling of 10 per 60 s moves from `dst_hosts_60` to `sweep_hosts_60`.
     `dst_hosts` stays a calibrated quantity, with no ceiling.
   - *Cost, stated now.* A fan-out to more than 10 internet hosts that all answer is no
     longer a strong verdict; it can still be unfamiliar. Scans of lab addresses and
     unanswered fan-out anywhere still hit the ceiling. Other unchanged ceilings
     (`failed_60` 20, `dst_ports_60` 15, …) still apply.
   - *Code.* `features/network.py`, `ml/network_detector.py`; tests
     `test_browsing_many_internet_hosts_is_not_a_sweep`,
     `test_many_answered_internet_hosts_are_at_most_unfamiliar`.
2. **Habit coverage in calibration.**
   - *Diagnosis.* The unfamiliar verdicts came almost entirely from heavy-habit users.
     Their DNS rate is drawn from 2.5–6.0 lookups/min, but NV1's calibration happened to
     contain 3 heavy users, at 3.3–4.7.
   - *Change.* Training adds a **stratified** group of 8 heavy-habit users
     (`AFW_NET_HABITS=heavy`, new generator option). Every part of the habit range the
     generator models for legitimate users is then represented. This is coverage
     design, as P6 did for archetypes.
   - The detector's calibration method is unchanged: the per-quantity benign quantile
     at 1 − α/k, with α = 0.01 and Bonferroni over k = 28 quantities.

## 2. Data (new, collected after this file is committed)

Generator: `traffic/benign_personas.py` at the commit that adds this file, with
`AFW_NET=1`. Duration 60 min, all sets concurrently. The test users have **new seeds**,
so new persona and habit draws. They are unseen by the calibration: no NV2 test address
is in NV2 training or validation.

| Dataset | Users (10.77.20.x) | Seed | Mode | Role |
|---|---|---|---|---|
| `nv2-train` | .100–.123 (24, natural habit mix) + .162–.169 (8, `AFW_NET_HABITS=heavy`) | 941, 945 | v2 personas | calibration |
| `nv2-val` | .124–.135 (12) | 942 | v2 personas | development |
| `nv2-test` | .140–.155 (16) | 943 | v2 personas | **test, evaluated once** |
| `nv2-test-shift` | .156–.161 (6) | 944 | shared | **test, evaluated once** |

- The test sets have the natural habit mix (weights 2:3:1). They are not stratified.
- .200–.249 stay reserved for the team (`TEAM_ATTACK_QUICKSTART.md`).

## 3. Development rules and freeze

- As NV1 §4: development on `nv2-val` only. A change needs a demonstrated cause there
  and must be committed with its reason before the test. Ceilings are never raised.
- **Freeze.** The calibration (sha256) and the code are committed; then the test runs
  once. Driver: `artifacts/evidence/nv2-2026-10-29/nv2_eval.py`.

## 4. Measurements

As NV1 §5, on `nv2-val` and on the test users (once):
- unfamiliar and strong window rates, with a bootstrap CI over users;
- users with a strong verdict;
- per-user shares, by habit;
- drivers;
- calibration content.

In addition: the share of test windows that would have been strong under the NV1
`dst_hosts_60` ceiling. This is reported only, so the effect of change 1 is visible.

## 5. Criteria (test users, evaluated once)

1. Unfamiliar window FPR ≤ **0.02**, with upper CI ≤ **0.05**.
2. **No** legitimate user receives a strong verdict.

These are the same as NV1 §6.1, as is what a pass allows. Passing allows only the claim
that the detector has learned normal network use for this lab population, at a measured
false-unfamiliar rate. It allows **no** attack-detection claim: that needs the team's
`net-portscan`, `net-slow-scan` and `net-ssh-guessing` runs.

## 6. Mode

The detector stays in **shadow** whatever the result (NV1 §6.2). After the test, the
live shadow calibration is replaced by the NV2 calibration, which the new feature schema
requires. Its validation status is recorded in §7.

## 7. Results

*Recorded 2026-10-29 ~08:55Z. Evidence: `artifacts/evidence/nv2-2026-10-29/`.*

### 7.1 Data

Capture 07:32:58–08:35:00Z (commit `bfe8ce9`). All four datasets validated (every check
PASS, including `benign_users_unseen` on both test sets). Observation counts equal the
WAF01 access-log lines for the same sources:

| Dataset | Users | Observations | Network events |
|---|---|---|---|
| `nv2-train` | 32 (13 heavy: 5 natural + 8 stratified) | 86 034 (74 722 + 11 312) | 187 773 |
| `nv2-val` | 12 (1 heavy) | 12 527 | 29 840 |
| `nv2-test` | 16 | 30 904 | 68 630 |
| `nv2-test-shift` | 6 | 4 075 | 11 691 |

The training heavy users drew 2.68–5.23 DNS lookups/min.

### 7.2 Development (`nv2-val`) and freeze

- Calibration: 3 680 emissions, of which 3 638 are non-zero.
- On `nv2-val` (1 380 emissions): unfamiliar **0.0145** [0, 0.0406], strong 0, no user
  with a strong verdict.
  - Most of it comes from the one heavy user, .132, at 13.9 % of emissions. That user
    drew 5.30 lookups/min, above the training heavy maximum of 5.23.
  - The criteria would be met, so §3 gives no cause for a change, and none was made.
- Frozen: `dev/nv2-dev1.calibration.json`, sha256 `c311aeeb…5710`, commit `c7aee42`.
- **Disclosure.** While checking .132, a command also printed the generator's habit-draw
  parameters for the test users. These are parameters only, with no detector output on
  test data. Nothing was changed after that point.

### 7.3 Test (unseen users `nv2-test` + `nv2-test-shift`, run once): **PASS**

Commit `e304425`; `test/nv2-test.json`.

| Measure | Result | Criterion |
|---|---|---|
| Unfamiliar window FPR (22 users, 2 530 emissions) | **0.0059**, CI [0.0016, 0.0115] | ≤ 0.02, upper CI ≤ 0.05 — **pass** |
| Strong window FPR | 0 [0, 0] | — |
| Users with a strong verdict | **0** | 0 — **pass** |
| Mean unfamiliar share by habit | light 0.010 (5 users), normal 0.004 (10), heavy 0.005 (7) | — |
| Highest per-user share | 0.0435 (.151, normal) | — |
| Windows strong under the NV1 `dst_hosts_60` ceiling (reported only) | 0 | — |

- Drivers: `median_duration_s_60` (8), `median_duration_s_300` (5), and one each for
  `dns_nxdomain_60`, `flows_60` and `bytes_out_log_60`.
- No DNS-rate quantity drives a test verdict. That is unlike NV1, where heavy users
  dominated.

### 7.4 What this allows, and what it does not

The claim of §5 is allowed: **for this lab population, the network detector has learned
normal network use, with a measured false-unfamiliar rate of 0.6 % [0.2, 1.2] on 22
unseen users.** Limits:

- **Change 1 did not decide this result.** The old ceiling would have fired on 0 test
  windows. The pass comes from calibration coverage, from change 2 and from this draw of
  users.
  - NV1's strong verdict came from one user's fan-out. A comparable fan-out did not
    occur here.
  - So the cost of change 1 stated in §1 is real, and its benefit on this data is
    unmeasured.
- **One population, one generator.** The habits are modelled ranges, with 22 test users
  and 7 heavy. Validation shows that a heavy user just above the trained range still
  gives about 14 % unfamiliar windows. Real users outside the modelled habits are untested.
- **No attack recall.** Nothing here measures detection. That needs the team's
  `net-portscan`, `net-slow-scan` and `net-ssh-guessing` runs.
- **Coverage.** Visibility is still only the ATTACK and USERS segments (NV1 §2).

### 7.5 Mode (as §6)

- The live shadow calibration was replaced at ~08:50Z: `network-calibrate --datasets
  nv2-train --write`, then a controller restart.
- The live file is field-for-field identical to the frozen calibration (its canonical
  JSON is byte-identical to `c311aeeb…`).
- Live state: `calibrated_on` 3 680, no calibration error, detector `shadow (not used
  for decisions)`, controller mode `monitor`.
- Its status is **validated for benign false-unfamiliar rate (NV2)**; it is **not
  validated for detection**. It stays in shadow (NV1 §6.2: attack recall and a human
  decision are still needed).
