# M6: Attack-evaluation harness (ADR-032)

Status: harness implemented and unit-tested (2026-10-27). **Gate B (attack detection
evidence) is BLOCKED-EXT**: it needs labelled attack runs carried out by the team. No
attack results exist, and none are claimed.

## 1. Division of responsibility

The project does **not** generate attack traffic. The team runs standard tools of their
choice (for example hydra, sqlmap, nikto, nmap) from ATK01 against lab-owned targets.
The harness makes those runs safe, recorded and measurable:

| Concern | Mechanism | Code |
|---|---|---|
| Only lab-owned targets | `config/scenarios.yaml` holds an explicit target allowlist (WAF01 10.77.30.10: 443, plus 22/80/3306 for IDS-only visibility). The registry refuses any target outside 10.77.0.0/16, and any target in the management (10.77.50.0/24) or database (10.77.60.0/24) networks, whatever the file says. A scenario target must be on the allowlist | `Registry._safe` |
| Only ATTACK-zone attackers | Attackers must be inside the lab config's ATTACK zone, excluding the firewall (.1) and probe (.250) addresses | `load_registry` |
| Bounded duration | `max_duration_s` is at most 3600 s per scenario | `ScenarioSpec` |
| Ground truth | `afw scenario begin <id> --operator NAME` opens a run (one at a time, an operator name is required), `mark` records phase changes, `end` closes it. Each run is one JSON file in `~/.config/afw/runs/`, written atomically | `RunJournal` |
| Kill switch | `afw scenario abort` **stops ATK01 through the GNS3 API first**, then records the reason and the stop result | `RunJournal.abort`, `cli._kill_atk01` |
| Watchdog | `afw scenario watchdog` (run it from a timer or loop during a session) aborts the active run, with the kill switch, once it exceeds its scenario's max duration | `RunJournal.watchdog` |
| Labels | `afw scenario manifest <run>` turns the journal into a capture manifest: attacker sources labelled with the scenario family and the exact run window, and benign sources listed by the operator. This is the input to `afw dataset capture` | `manifest_for` |
| Cross-run evaluation | `afw experiment evaluate --datasets a,b,c` replays each labelled run through arms M0/M1/M2 and aggregates per arm with the **run** as the unit: mean and a 95 % bootstrap CI over runs (no CI below 3 runs). Synthetic datasets are refused; `--allow-synthetic` exists only for a demo and labels the output `SYNTHETIC - NOT A RESULT` | `afw.ml.run_evaluation` |

## 2. Team procedure (per run)

1. `afw scenario list` and choose a scenario. Holdout scenarios (`purpose: holdout`, for
   example `low-and-slow-bruteforce`) are for final testing only; do not tune on them.
2. Start benign traffic from USR01 as usual, so that the run measures FPR as well.
3. `afw scenario begin web-sqli-probe --operator <name>`, then start the tool on ATK01
   against `https://10.77.30.10/`.
4. `afw scenario mark <run> "<what changed>"` at each phase change.
5. Stop the tool, then `afw scenario end <run>`. If anything goes wrong, use
   `afw scenario abort <run> --reason "..."`, which powers off ATK01.
6. `afw scenario manifest <run> --benign 10.77.20.10 > run.json`, then capture it with
   `afw dataset capture`.
7. After at least 3 runs per family: `afw experiment evaluate --datasets ...`.

## 3. Tests

`tests/unit/test_scenario_harness.py`: 14 tests. They cover the following:

* The shipped registry is valid and safe.
* Denied or external targets are refused (4 cases).
* A target must be on the allowlist.
* Non-ATTACK, firewall and probe attackers are refused.
* The duration is capped.
* Journal lifecycle:
  * one active run at a time;
  * an operator name is required;
  * no marks after the end;
  * the manifest validates as a `DatasetManifest` with correct labels.
* The kill switch is called before the abort is recorded.
* The watchdog aborts at max+1 s and not at max.
* Evaluation:
  * synthetic data is refused;
  * run-level means and CIs are computed;
  * no CI is given below 3 runs;
  * the demo is labelled.

Ten mutations of the safety checks were each caught by the tests
(`artifacts/evidence/m6-2026-10-27/mutation-check.txt`).

## 4. What is blocked, and why

* **Gate B (attack detection with CIs).** Needs at least 3 labelled runs per family from
  the team. The M3 promotion gate check `attack_recall_regression` stays failed for the
  same reason (it refuses synthetic attack data by design).
* The kill switch has been unit-tested with an injected stop function. Live, its lookup
  was checked read-only: the GNS3 project resolves and ATK01 is found (status `started`).
  The stop call itself was **not** exercised against ATK01, because that would interrupt
  the lab without a run in progress.
