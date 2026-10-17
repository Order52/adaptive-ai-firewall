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
- _Status recorded in `docs/IMPLEMENTATION_STATUS.md` with the exact run IDs/metrics._

### Synthetic correctness fixtures — NOT RESULTS
- `tests/integration/test_experiments.py`, `test_closed_loop.py`,
  `test_explain.py` exercise the full pipeline on a trivially separable synthetic
  fixture (AUC 1.0 there is meaningless). These verify **software correctness only**
  and must never be cited as accuracy results.

## What is BLOCKED (and why)

- **Attack/adversarial recall and scenarios A (auth abuse), B (SQLi/CRS), E (held-out
  novelty)** require real **attack** telemetry. Generating an attack-scenario driver
  was stopped by the safety classifier and is assigned to the team as
  `DatasetManifest` + `SourceLabel` traces. The evaluation machinery is complete and
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
