# A4: account-aware AUTH protection, household-robust security path (amendment to A3)

Status: **protocol, written 2026-10-29 ~11:20Z, before any A4 selection/final data
exists.** Authorized by the project owner on 2026-10-29 ("Implement the A4 correction if
justified, with newly predeclared criteria and new independent datasets. Never reuse
consumed final evaluation data for tuning."). Results go in §8 only. §1–§7 do not change
after the A4 selection data is collected.

A4 inherits **everything** from A3 (`A3_AUTH_CONTROLS.md`) — the account-aware AUTH
evidence (§2.1), the login-scoped graduated controls, the candidates, the SYNTHETIC
attack-resistance criterion — and changes exactly two things, each stated below with its
reason. It is the NV1→NV2 pattern applied to A3.

## 1. What A3 showed, and the two changes

A3's selection chose candidate **S**; its one-shot final on Phase E **failed F1**
(`A3_AUTH_CONTROLS.md` §8.2): S's security path flagged 4.75 % of p6-final windows, all
from legitimate multi-account ("household") addresses that were absent from the
selection set.

Development diagnosis on the **consumed** Phase E sets (diagnosis only, no re-test;
`artifacts/evidence/a4-2026-10-29/a4-diagnosis.txt`):

- S's security path calibrated the `distinct_usernames` quantity at **1.0**, because its
  calibration (p7-val) had no household coverage.
- Of 293 flagged `p6-final` windows, **287 were `distinct_usernames` alone** (value 2 —
  two people logging in from one address); on `p6-final-shift`, all 216 flags were this
  quantity (values up to 4). The fixed ceiling (5) was never reached.

### Change 1 — `distinct_usernames` is ceiling-only (committed before this file)

`distinct_usernames` joins a `CEILING_ONLY` set in `ml/security_path.py`: it is assessed
by its fixed ceiling (**≥ 5 accounts in a window**) alone, never by a calibrated benign
quantile. The Bonferroni divisor drops to the calibrated quantities (now 6).

- *Reason.* A legitimate shared address (household, office NAT) has 2–4 active accounts
  in a window; that is normal, not evidence. Multi-account **guessing** is still caught:
  the ceiling fires at ≥ 5 accounts, and the live account-aware AUTH rule
  (`credential_spraying`, ADR-044: ≥ 3 accounts with failing streaks) is unchanged and
  is the real multi-account-guessing detector. The security path's per-account quantities
  (`auth_failures`, `auth_fail_lb`) still catch single-account guessing.
- *Cost, stated now.* A spray spread over exactly 3–4 victim accounts, each probed
  below the per-account streak, no longer raises the `distinct_usernames` quantity; it is
  caught by `credential_spraying` and `auth_fail_lb` instead, not by this quantity.
- *Committed* at `9904021` (code + regression test + diagnosis), before any A4 data.
- *Robustness.* Because the quantity no longer calibrates, the result no longer depends
  on how many households happen to be in the calibration set.

### Change 2 — benign FPR is a criterion on shared/household sets too

A3 §8.1 measured B1 on `a3-sel` only and merely *reported* the shared set. The omission
hid the household sensitivity until the final. A4 makes the benign-FPR criteria (B1 at
selection, F1 at final) hold on **every** benign set, including the household-stratified
and shared-address sets (§5).

Nothing else changes: the AUTH evidence rules, the controls, the candidate set, the
sensitivity method and the SYNTHETIC attack-resistance criterion are all as in A3.

## 2. Data (new, collected after this file and the driver are committed)

Generator `traffic/benign_personas.py` at the committing commit (sha256 in the launch
record), `AFW_NET=0` (web only, as A3). The candidates are **trained and calibrated on
the reusable A3 sets `p7-train` / `p7-val`** (training/calibration data, never a consumed
one-shot test). All A4 datasets below are **new**; selection and final addresses and
seeds are disjoint, so no final user is seen during selection.

| Dataset | Users (10.77.20.x) | Seed | Generator mode | Role |
|---|---|---|---|---|
| `a4-sel` | .140–.155 (16) | 1001 | personas v2, natural mix | selection |
| `a4-sel-hh` | .156–.161 (6) | 1002 | personas v2, `AFW_ARCHETYPES=household` | selection (stratified households) |
| `a4-sel-shift` | .162–.166 (5) | 1003 | shared addresses | selection (shared) |
| `a4-final` | .167–.182 (16) | 1004 | personas v2, natural mix | **final, once** |
| `a4-final-hh` | .183–.188 (6) | 1005 | personas v2, `AFW_ARCHETYPES=household` | **final, once** |
| `a4-final-shift` | .189–.193 (5) | 1006 | shared addresses | **final, once** |

*Correction, 2026-10-29 ~11:55Z (before any A4 data was used; dataset validation caught
it).* A first capture used addresses .100–.167 and seeds 811–816. Those collide with the
candidates' training/calibration sets `p7-train`/`p7-val` (addresses .100–.139, seeds
811/812), so the selection/final users would have been the **same personas the candidates
train on** — training-set leakage, not an unseen-user test (`dataset validate`
`benign_users_unseen` WARN). The addresses and seeds above are disjoint from the training
range (.100–.139) and use a fresh seed block, so the A4 selection and final users are
genuinely unseen. The first capture is discarded, not used.

- Duration 45 min, all concurrently.
- .200–.249 stay reserved for the team.
- Validation (`afw dataset validate`) must pass for every set, with observation counts
  equal to the WAF01 access-log lines.

## 3. Candidates, training and freeze

As A3 §3/§5, unchanged:
- Candidates R2, R3 (references) and D, F, C, S, FS (retrained on `p7-train`/`p7-val`).
- Selection runs once on the A4 selection sets; the chosen candidate is frozen (pickle
  sha256 recorded and committed) before any final set is read.
- Driver: `artifacts/evidence/a4-2026-10-29/a4_run.py` (adapted from `a3_run.py`; the
  only differences are the A4 datasets and that the benign-FPR criteria span the
  household and shared sets).

## 4. Measurements

As A3, on the selection sets (B-criteria) and once on the final sets (F-criteria):
- per-detector benign window FPR with a per-source 95 % bootstrap CI, on each benign set
  and on their union;
- legitimate logins refused and legitimate users given any login control;
- site-wide restrictions (must be none);
- must-detect sensitivity, nominal and stressed (SYNTHETIC);
- SYNTHETIC attack resistance AR1–AR4.

In addition, reported: the `distinct_usernames` distribution on the household and shared
sets, to show the ceiling (5) is not reached by legitimate multi-account use.

## 5. Criteria

### 5.1 Selection (B1–B4, on the A4 selection sets, run once)

1. **B1.** Every enforcing detector's benign window FPR ≤ **0.02**, upper CI ≤ **0.05**,
   on **each** of `a4-sel`, `a4-sel-hh`, `a4-sel-shift` and their union. For candidates
   with a security path, this includes the security detector. *(A3 measured this on the
   main set only; change 2.)*
2. **B2.** No site-wide restriction on any benign set.
3. **B3.** 0 legitimate logins refused; no legitimate user receives a login control.
4. **B4.** Must-detect sensitivity (nominal) = 1.0 on the predeclared families.
5. **Criterion 5 (SYNTHETIC, rule-based, no traffic):** AR1–AR4 as A3 §8.1.

A candidate is eligible iff B1–B4 and criterion 5 hold. Selection prefers, among
eligible candidates, the highest stressed must-detect minimum, then the simpler model
(as A3 step 3).

### 5.2 Final (F1–F5, on the A4 final sets, run once)

1. **F1.** Every enforcing detector's benign window FPR ≤ **0.02**, upper CI ≤ **0.05**,
   on **each** of `a4-final`, `a4-final-hh`, `a4-final-shift` and their union.
2. **F2.** 0 legitimate logins refused; no login control on a legitimate user.
3. **F3–F5.** As A3 (no site-wide restriction; sensitivity preserved; SYNTHETIC
   resistance holds).

What a pass allows: the claim that the A4 AUTH design generalises to unseen legitimate
users **including households and shared addresses**, at the measured login-friction and
window-FPR rates, in monitor mode. It allows **no** attack-detection claim: that needs
the team's runs.

## 6. Mode

The controller stays in **monitor** mode whatever the result. A pass makes the A4 design
a candidate for a future human-authorised promotion; it does not promote anything. A3's
candidate S is not promoted; A4 is a fresh selection.

## 7. Honesty

- `p7-train`/`p7-val` are training/calibration data, reused as permitted; no consumed
  one-shot set (`a3-sel`, `a3-sel-shift`, `p6-final*`) is reused.
- Change 1 is committed before any A4 data; the diagnosis that justifies it uses only
  already-consumed data.
- The A4 selection and final sets are each evaluated once.
- SYNTHETIC results are labelled SYNTHETIC and never support a detection claim.

## 8. Results

(Empty until the selection and final have run.)
