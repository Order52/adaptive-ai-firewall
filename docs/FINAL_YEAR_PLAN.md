# Final-year plan: working, adaptive, smart

Written 2026-11-21, before any measurement below was taken. This is the threshold for calling the
project **finished as a final-year project**. It extends `RELEASE_CRITERIA.md` (which says the
software is a release candidate) with what that page leaves out: adaptation measured on live
traffic, and detection measured under attack. Every gate is checked by a command or a stored file.
Gates that need attack traffic are **BLOCKED-EXT**: this project contains no attack generator and
nothing here is, or will be, faked.

## 1. Where the project stands

| Claim | State on 2026-11-21 (after the first measurements, section 5) |
|---|---|
| Works end to end on a real lab, enforcement verified, secure and operable | **Done** (`RELEASE_CRITERIA.md` R1 to R8, CI and CD green) |
| Adapts to new legitimate users on live traffic | **Partly.** The challenger learned 575 vouched windows live and its flag rate on the users it learned fell from 93 % to about 30 %, but on an unseen user it flagged 74.5 % against the champion's 100 % (gate A1 **failed**) |
| Detects attacks | **Brute force: yes, measured** (3 of 3 runs contained in under 6 s). SQL injection, port scan, SSH guessing: not enough team runs yet |
| No collateral harm | **No.** The ML strategy restricted all 6 legitimate background users in the 3 brute-force runs (gate D3 **failed**) |
| Smarter than static rules | Yes on brute force (static rules caught 0 of 3, ML 3 of 3); the statistical arm matched it with no false positives |

Correction: this page first said no labelled attack run existed. The team's brute-force (7 November,
3 test + 1 validation) and SQL-injection (9 November, 1) runs were already on CTRL01; the status
documents were stale and I had not checked.

## 2. Gates

Four groups. "Autonomous" gates I can run alone; "Team" gates need people with attack tools.

### W: Working (autonomous, already met, must stay green)

| # | Gate | Check | Pass when |
|---|---|---|---|
| W1 | Release criteria | `RELEASE_CRITERIA.md` R1 to R8 | all pass after the last change |
| W2 | Live lab | `afw lab verify`, `/api/readyz` | 41/41, ready, no stale sensor |

### A: Adaptive (autonomous)

Predeclared on 2026-11-21 06:52Z, before the first window of the test was scored.

| # | Gate | Check | Pass when |
|---|---|---|---|
| A1 | **Live correction of a false positive** | Six new legitimate users (`10.77.20.198, .199, .250 to .253`) are vouched with `benign_change` and run v2 personas for 100 minutes. Then one unseen user (`10.77.20.254`, not vouched, first 10 minutes only, before any of its windows can be learned) is scored by champion and challenger (`GET /api/learning/shadow`, `scripts/ad1_report.py`) | On the unseen user's windows: champion flags at least 50 % (otherwise the test is **not informative** and says so), and the challenger flags **at most half as many windows as the champion** |
| A2 | Poisoning not worse | `afw experiment adaptation` and `tests/unit/test_online_learning.py` | learned-poison counts equal or below the stored M4 baseline |
| A3 | Governance still holds | `afw challenger evaluate` on the live challenger | the gate **evaluates and refuses or accepts for stated reasons**; a refusal for missing attack data is reported as such, never overridden |
| A4 | Restart safe | restart the controller, read `n_learned` before and after | equal, no double learning |

A1 is a one-sided test of the claim "it learns live". If it fails, the result is reported as a
failure with the numbers; the thresholds are not changed afterwards.

### D: Detection (Team, BLOCKED-EXT)

Evaluated by one command on the team's evaluated runs:

```
afw experiment evaluate --datasets <test runs> --streaming --out report.json
afw experiment scorecard report.json        # exit 0 PASS, 1 FAIL, 3 NOT_RUN
```

Thresholds are in `src/afw/ml/scorecard.py` and are not read from the report. The ML strategy
(arm M2) is judged on the four known families (`web-bruteforce-login`, `web-sqli-probe`,
`net-portscan`, `net-ssh-guessing`), 3 test runs each, runs hours apart, splits by run:

| # | Gate | Pass when |
|---|---|---|
| D1 | Containment | at least 80 % of attack sources contained, in at least 2 of the 3 runs of every family |
| D2 | Speed | median time from first attack request to first traffic-affecting action at most 180 s (six 30-second windows), in at least 2 of 3 runs |
| D3 | No collateral harm | **0** legitimate background sources blocked or rate limited in any run; at least 98 % of legitimate requests unaffected |
| D4 | Value over baselines | pooled over all known-family runs: containment of M2 at least 0.2 above static rules (M0), and no more than 0.05 below the statistical profile (M1) |
| D5 | New family (`web-content-discovery`) | the adaptive arm detects more of the withheld family than the frozen one, with no known-family recall drop above 0.05 (`NEW_THREAT_EXPERIMENT.md`) |

Holdout runs (`low-and-slow-bruteforce`, `net-slow-scan`) are evaluated once, reported, and never
gated. A run that fails a gate is part of the result and stays in it.

### G: Defensible (Team)

| # | Gate | Pass when |
|---|---|---|
| G1 | Demo | `FINAL_DEMO.md` run end to end by the team, including steps 6b, 7 and 10 |
| G2 | Explanation | each member explains the architecture, the adaptation lifecycle and one negative result without notes |
| G3 | Honest documents | `PROJECT_STATUS.md`, `RESULTS.md` and README state exactly what the gates above show |

## 3. Stop rule

* **Done** when W and A pass and the team has run D and G. Then the status is final-year ready.
* **Done without D** (what I can reach alone): W and A pass. The project is then
  *finished as engineering*, with detection stated as unmeasured. This is a legitimate final state
  and the documents say so.
* At most **two** attempts at A1 (one repeat only to fix a measurement fault, never to chase the
  threshold). No new detectors, no new features: gates only.
* Nothing is edited after seeing it. Results are recorded as measured.

## 4. Work items

| Item | Gate | Who | State |
|---|---|---|---|
| Scorecard command (`afw experiment scorecard`) with tests on hand-made structures | D1 to D4 | me | done 2026-11-21 |
| Live adaptation test and report script | A1 | me | done 2026-11-21: **failed** |
| Gate evaluation, restart, poisoning re-check | A2 to A4 | me | done 2026-11-21: A2, A4 pass; gate ran, one check fails |
| Attack runs (`TEAM_ATTACK_QUICKSTART.md`), then the scorecard | D1 to D5 | team | brute force done (D3 fails); SQL injection 1 of 3 runs; port scan, SSH, content discovery open |
| Demo rehearsal and explanation | G1, G2 | team | open |

## 5. Log

**2026-11-21 first measurements** (details and files: `artifacts/evidence/final-year-2026-11-21/`):

| Gate | Result |
|---|---|
| A1 live correction | **FAIL**: unseen user, challenger flagged 74.5 % of 94 windows, champion 100 % (needed at most 50 %) |
| A2 poisoning | PASS (equal to the M4 baseline; residual risk unchanged) |
| A3 governance | Gate evaluated with real attack data for the first time: 6 of 7 checks pass (attack recall 1.0 on 30 windows, benign FPR 0.0017 vs champion 0.9462); **`sensitive_invariance` fails** (`auth_fail_frac`, -1.0). Not promoted |
| A4 restart | PASS (1182 before and after) |
| D1, D2 (brute force) | PASS: 3 of 3 contained, 2.4 to 5.2 s |
| D3 (brute force) | **FAIL**: 6 of 6 legitimate users restricted by the ML strategy |
| D4 (brute force) | PASS |
| D1 to D4, other families | NOT_RUN (SQL injection 1 run; port scan and SSH none) |
| D5, G | open (team) |

Stop rule: the A1 allowance is used (no repeat was run). Two failures, A1 and D3, are the same weakness
seen twice: legitimate users unlike the training population are scored anomalous. The next step is a
design decision for the owner (strategy choice, learner constraints for `auth_fail_frac`), not another
measurement of the same run. Fresh team runs are needed for any re-test of D3.

## 6. Conclusion (2026-11-21)

Stop rule outcome: the engineering that the rules allow is finished; the gates are **not all met**.
No result was edited and no threshold moved.

**Met:** W1, W2, A2, A4; D1, D2, D4 for brute force.
**Failed, with cause:**

* **A1 and D3** are one weakness: legitimate users unlike the training population are scored
  anomalous. Online learning only changes the HST detector (Isolation Forest and robust statistics
  drove most proposals), so it cannot close D3 alone.
* **A3 `sensitive_invariance`.** Offline decomposition (`adaptation-experiment-ad2.json`,
  `sensitivity_decomposition`): at the champion's *own* threshold the learned challenger is not less
  sensitive; the loss appears only at the recalibrated threshold. The champion flags about 95 % of
  unseen benign windows, so any threshold calibrated to a small false-positive budget sits above a
  lone `auth_fail_frac` probe. Admission rules in the learner do not cause this, so I did not change
  them. Closing the gate means either judging sensitivity on the whole decision (the AUTH security
  path flags such windows regardless of HST) or bounding recalibration. Both change a predeclared
  safety check, so that is the owner's decision, with an ADR, not part of this work.

**Open, outside this work:**

1. Owner decisions: (a) strategy `ml` vs `statistical` (one family says statistical; decide after
   the other families, D4 compares them), (b) how to treat `sensitive_invariance` (above),
   (c) a batch profile rebuild on more varied users, which earlier phases found loses sensitivity.
2. Team runs: 2 more SQL injection, 3 port scan, 3 SSH guessing, 3 content discovery (D5), then
   `afwc experiment scorecard` (deployed to CTRL01 on 2026-11-21).
3. G1 and G2: demo and explanation by the team.
4. Re-testing D3 after any change needs fresh runs; the 7 November runs are used up for that purpose.
