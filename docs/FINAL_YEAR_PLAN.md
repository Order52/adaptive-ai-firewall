# Final-year plan: working, adaptive, smart

Written 2026-11-21, before any measurement below was taken. This is the threshold for calling the
project **finished as a final-year project**. It extends `RELEASE_CRITERIA.md` (which says the
software is a release candidate) with what that page leaves out: adaptation measured on live
traffic, and detection measured under attack. Every gate is checked by a command or a stored file.
Gates that need attack traffic are **BLOCKED-EXT**: this project contains no attack generator and
nothing here is, or will be, faked.

## 1. Where the project stands

| Claim | State on 2026-11-21 |
|---|---|
| Works end to end on a real lab, enforcement verified, secure and operable | **Done** (`RELEASE_CRITERIA.md` R1 to R8, `rc.2` + faster learning pushed, CI and CD green) |
| Adapts to new legitimate users on live traffic | Path works (12 windows learned live on 2026-11-18); **effect on scores not yet measured** (gate A1 below) |
| Detects attacks | **Unmeasured.** The system detects nothing it was never shown; only team attack runs can show that |
| Smarter than static rules | Unproven for the same reason (gate D4) |

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
| Live adaptation test and report script | A1 | me | running 2026-11-21 |
| Gate evaluation, restart, poisoning re-check | A2 to A4 | me | after A1 |
| Attack runs (`TEAM_ATTACK_QUICKSTART.md`), then the scorecard | D1 to D5 | team | open |
| Demo rehearsal and explanation | G1, G2 | team | open |

## 5. Log

(Results are appended here as they are measured; see `artifacts/evidence/final-year-2026-11-21/`.)
