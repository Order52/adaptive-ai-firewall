# Experiments & evaluation methodology

_This document defines how the AI-Adaptive-Firewall is evaluated and records what
has actually been run. It distinguishes **synthetic correctness fixtures** (software
tests only) from **real lab evidence** (citable). Updated 2026-10-17 (session 3)._

## Evaluation arms

| Arm | Defences | Adaptive controller |
|---|---|---|
| **M0 Static** | OPNsense pf + Suricata IDS + OWASP CRS WAF | disabled (no adaptive policy) |
| **M1 Statistical** | same | robust-statistics detector only |
| **M2 ML-assisted** | same | robust-statistics + Isolation Forest |

All arms replay the **identical** observation stream through the **identical** live
pipeline (`InferenceEngine` / `CorrelationEngine` / `DecisionEngine`) at the **same**
trained false-positive budget, so any difference is attributable to the detector set
alone. M0 is credited with the WAF's own inline blocks so the static baseline is fair.
Runner: `src/afw/ml/experiments.py` (`afw experiment replay --datasets <ids>`).

## Metrics

Window-level precision / recall / FPR / F1 on the controller's traffic-affecting
action; source-level containment; legitimate-request success; first-observation→
first-action detection latency; per-arm detector scoring latency; attack-request
exposure (requests that reached the app before containment). A run with no attack
windows reports `recall = null` — never a fabricated 0. Ground-truth labels are read
only by evaluation code, never by the detectors (leakage-controlled, ADR-010).

## Data provenance (leakage controls)

- Datasets are whole recorded runs; splits are by **run**, never by mixing windows.
- Preprocessing/thresholds fit on TRAIN/VALIDATION only; TEST/HOLDOUT frozen.
- Labels, scenario names, source IPs and future events are **not** model features.
- Each `DatasetManifest` records app version, seed, UTC window, source labels,
  generator and an observations SHA-256 (integrity-checked on read).

## What has actually been run

### Real benign baseline (session 3) — REAL LAB EVIDENCE
- **Benign traffic**: `traffic/benign_personas.py` drives legitimate user journeys
  (browse, read reviews, valid login with occasional corrected typo, view/make a
  booking, review, logout) from multiple real client source IPs on USR01, through
  the WAF to APP01. Telemetry (WAF access + app events + IDS) flows to CTRL01 and is
  correlated into real feature windows.
- **Real profile training**: a trusted behavioural profile is bootstrapped from the
  captured **real** benign runs (replacing the earlier synthetic demo profile), then
  promoted and used for **live inference on CTRL01**.
- **Measured**: false-positive behaviour and legitimate-request success on
  independent real benign traffic (see `artifacts/evidence/` once captured).
- _Results with run IDs: `RESULTS.md` §2–4 and §10._

### Synthetic correctness fixtures — NOT RESULTS
- `tests/integration/test_experiments.py`, `test_closed_loop.py`,
  `test_explain.py` exercise the full pipeline on a trivially separable synthetic
  fixture (AUC 1.0 there is meaningless). These verify **software correctness only**
  and must never be cited as accuracy results.

### Adaptation experiments (M4) — REAL RECORDED DATA
- `afw experiment adaptation --learn <drift-run> --hold <later-holdout-run>` replays
  the online challenger over a real benign drift run and evaluates on a disjoint later
  holdout. Scenarios: A (legitimate drift), B (poisoning, synthetic feature-space
  injections that are labelled as such), C (regression → probation rollback). Units:
  tumbling windows; CIs bootstrapped over sources. Method and results:
  `engineering/M4_ADAPTATION_EXPERIMENTS.md`.

### Attack runs (M6) — HARNESS READY, RUNS BY THE TEAM
- Scenario registry `config/scenarios.yaml` (lab-owned targets only), ground-truth
  journal, kill switch, watchdog, manifests generated from the journal.
- `afw experiment evaluate --datasets …` aggregates M0/M1/M2 per arm with the **run**
  as the unit (95 % bootstrap CI over runs, none below 3 runs). Synthetic datasets are
  refused. See `engineering/M6_ATTACK_EVALUATION.md`.

## What is BLOCKED (and why)

- **Attack/adversarial recall and scenarios A (auth abuse), B (SQLi/CRS), E (held-out
  novelty)** require real **attack** telemetry. Generating an attack-scenario driver
  is out of scope for this project; the team runs attacks with standard tools through
  the M6 harness. The evaluation machinery is complete and
  tested; it will produce citable M0/M1/M2 attack metrics the moment those traces exist.
- **Multi-repetition variance (≥5 runs/scenario/mode)** and **ablations** depend on the
  same attack data for the adversarial arms; benign-side repetitions are feasible now.

## How to reproduce (once attack traces exist)

```
# benign (already automated):
#   run traffic/benign_personas.py from client guests → capture train/val/test
afw dataset capture <id> --manifest <m.json> --purpose <train|validation|test|holdout>
afw train bootstrap --train <train-ids> --val <val-ids>      # on CTRL01
# promote via POST /api/profiles/rental/<v>/promote (admin)
afw experiment replay --datasets <held-out-test-ids>         # M0/M1/M2 table
```

Results, manifests and figures are archived under `artifacts/evidence/` and surfaced
on the dashboard's experiments panel and the `experiment_results` MCP tool, each row
tagged with its scenario so synthetic demos are never mistaken for lab results.
