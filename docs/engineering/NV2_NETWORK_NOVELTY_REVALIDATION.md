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

(Empty until the test has run.)
