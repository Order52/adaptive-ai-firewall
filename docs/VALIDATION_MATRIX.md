# Validation matrix

Each acceptance-gate criterion of the engineering directive is mapped to the tests and
evidence that support it. Status words:

* **MET**: evidence exists.
* **PARTIAL**: some evidence exists; the gap is named.
* **NOT MET**: the criterion fails on the evidence available.
* **BLOCKED-EXT**: needs something only the team can supply.

Gate definitions are unchanged from the directive. Evidence paths are relative to
`artifacts/evidence/`. Latest runs (2026-10-28):

* unit/integration: 198 passed, 14 skipped (skips: live-lab tests without `AFW_LAB=1`);
* live lab: `AFW_LAB=1 pytest tests/lab` 14/14 and isolation 37/37 after the P5 changes
  (IDS mTLS, HTTPS API, real-country enforcement) on 2026-10-28 09:52Z
  (`p1-2026-10-28/p5-final-regression-2.txt`; earlier: `p5-final-regression.txt`,
  `m9-2026-10-27/`).

## Gate A: Infrastructure

| Criterion | Tests / procedure | Evidence | Status |
|---|---|---|---|
| Reproducible network deployment | `afw lab build/start/provision-fw/provision-ids/deploy` (idempotent; second run `changed=0`) | `cold-restart-2026-10-18.md`, `m5-2026-10-27/deploy-*.txt`, `m8-2026-10-27/deploy-ctrl01.txt` | MET |
| Validated zone separation | `afw lab verify` (37 reachability checks, both directions, incl. DB tier and plaintext-port checks) | `m9-2026-10-27/lab-verify.txt` | MET |
| Application/database connectivity | Functional round trip USR01 → WAF → APP → DB | `dbtier-2026-10-21.md` | MET |
| Consistent node inventory and configuration | Topology as code (`lab/gns3/topology.yaml`), `afw lab status`, `COMPONENT_INVENTORY.md` | `phase0-2026-10-27/lab-start.txt` | MET |

## Gate B: Detection

| Criterion | Tests / procedure | Evidence | Status |
|---|---|---|---|
| Real telemetry from multiple sensor types | WAF access + audit, app events (mTLS), Suricata IDS (FW01); `test_telemetry*.py`, `test_provenance.py` | `m2-2026-10-27/live-provenance.txt`, `m5-2026-10-27/live-envelope.txt` | MET |
| Demonstrated live inference | Live controller scoring real windows; IDS-only view live | `real-benign-baseline-2026-10-17.md`, `m2-2026-10-27/live-shadow-final.txt` | MET |
| Reproducible labelled attack evaluation | M6 harness (`test_scenario_harness.py`, 14 tests); `afw experiment evaluate` | Harness only; **no team attack runs exist** | BLOCKED-EXT |
| Correct false-positive and false-negative measurements | P1 predeclared protocol: FP per tumbling window (CIs over users), per user and per request (each counted once), on unseen users, a later period and workload shifts (`afw experiment benign-generalization`, `test_benign_generalization.py`); FN requires attack runs | `p1-2026-10-28/p1-eval.json`; FN: none | PARTIAL: FP measured with real denominators (v2: 13/16 unseen users restricted; v3 candidate: 0/16, but fails the sensitivity criterion); FN BLOCKED-EXT |

## Gate C: Genuine adaptation

| Criterion | Tests / procedure | Evidence | Status |
|---|---|---|---|
| Challenger learns incrementally from eligible new traffic | `test_online_learning.py`; `afw experiment online-replay` on real recorded runs | `m2-2026-10-27/m2-replay-*.json` (227 learned, 1 pivot) | PARTIAL: shown on real recorded traffic in replay. **Live, 0 windows learned** (all new sources tainted by champion proposals, fail-closed) |
| Drift and adaptation distinguishable and observable | Drift reports vs model lineage; dashboard panels | `dashboard-live-2026-10-20.md`, `m8-2026-10-27/dashboard-panels.txt` | MET |
| Model state genuinely changes | Pivot detected, mean absolute score change 0.18 | `m2-2026-10-27/m2-replay-drift-relaxed.json` | MET (replay) |
| Candidate promotion follows documented validation | `test_challenger_lifecycle.py` (20 tests, mutation-checked); live gate refusals (409) | `m3-2026-10-27/live-gate-refusals.txt`, `m3-2026-10-27/mutation-check.txt` | MET |
| Distribution-shift experiment shows an actual benefit | M4 scenario A on real drift: HST holdout FPR 0.650 → 0.031 (calibrated) | `m3-2026-10-27/m4-adaptation.json` | PARTIAL: benefit shown offline for the HST arm only; IF and robust stats unchanged; gate fails, so no live promotion |
| No silent sensitivity loss | Matched-window, per-feature `sensitive_invariance` (ADR-034) with a regression benchmark of deliberately desensitized challengers; cross-profile matched probes in P1 | `p1-2026-10-28/p2-mutation-check.txt` (6/6), `m4-adaptation-p2-gate.json`, `p1-eval.json` | MET: the M4 challenger and the v3 candidate both show measured losses and neither is promoted |
| Poisoning and regressions do not silently corrupt the trusted model | M4 scenarios B and C; `test_benign_drift_cannot_vouch_for_poison_sharing_a_driver_name` | `m4-adaptation.json` (0/180 poison learned after fix), `m4-adaptation-v1-name-corroboration.json` (140/180 before) | MET, with a documented residual (4+ colluding sources) |
| Rejected candidates and rollback demonstrated | Gate failure, probation auto-rollback (M4 C, unit tests) | `m4-adaptation.json` (rollback after 100 windows) | MET (replay and unit); no live promotion has been performed |

## Gate D: Enforcement

| Criterion | Tests / procedure | Evidence | Status |
|---|---|---|---|
| Real firewall/WAF actions | `tests/lab/test_enforcement_lab.py` (OPNsense alias, WAF deny, rate limit) | `m9-2026-10-27/pytest-lab.txt` | MET |
| Verified containment and policy state | Read-back + probe verification before `enforced` | same; `real-benign-baseline-2026-10-17.md` | MET |
| Expiry, revocation, rollback, crash recovery | Lab tests (revoke); restart restore 5 s; FW watchdog flush 106 s; cold restart | `cold-restart-2026-10-18.md`, `docs/archive/IMPLEMENTATION_STATUS.md` (restart restore 5 s, watchdog flush 106 s) | MET |
| Mandatory protected-infrastructure restrictions | `test_policy.py`; lab safety tests; MCP refusal | `m9-2026-10-27/pytest-lab.txt` | MET |
| Directional real-country enforcement (P5) | `test_geo_enforcement.py` (21, 9/9 mutants); `tests/lab/test_geo_enforcement_lab.py`; watchdog fail-safe run | `p1-2026-10-28/p5-geo-*.txt` | MET for outbound (read-back + egress probe + independent connects); inbound read-back only (no real-country traffic reaches the lab) |

## Gate E: Independent value

| Criterion | Tests / procedure | Evidence | Status |
|---|---|---|---|
| Fair comparisons against static rules and non-adaptive ML | M0/M1/M2 replay through the identical pipeline (`test_experiments.py`) | `real-benign-baseline-2026-10-17.md` (benign only) | PARTIAL: benign-only (equal safety, different cost) |
| Quantified incremental benefit where demonstrated | `afw experiment evaluate` with run-level CIs | none | BLOCKED-EXT (needs attack runs) |
| Honest documentation where adaptation does not help | RESULTS §3 (champion FPR under a workload shift, corrected), M4 caveats | `RESULTS.md`, `engineering/M4_ADAPTATION_EXPERIMENTS.md` | MET |

## Gate F: Security and operations

| Criterion | Tests / procedure | Evidence | Status |
|---|---|---|---|
| Authenticated and constrained MCP | `tests/lab/test_mcp_lab.py`; channel-scoped tokens; no shell, no promotion tool | `m9-2026-10-27/pytest-lab.txt` | MET |
| Auditable operations | Audit log for policies, promotions, rollbacks, mode, feedback | API `/api/audit`; dashboard | MET |
| Secure API and deployment | Role tokens; MGMT-only API; mTLS for all sensors incl. FW01 IDS (ADR-035, no plaintext listener); host nftables default-deny | `test_api.py`, `test_telemetry_v2.py`, `test_pki.py`, `tests/lab/test_api_tls_lab.py`, `p1-2026-10-28/p5-ids-mtls.txt`, `p5-api-tls.txt` | MET: API HTTPS-only with lab-CA certificate (ADR-023 revised); all sensors mTLS |
| Accurate operator dashboard | Live headless render, no console errors; panels read the API only | `m8-2026-10-27/dashboard-panels.txt` | MET |
| Tested recovery mechanisms | Cold restart; controller restart; sensor reconnect and staleness | `cold-restart-2026-10-18.md`, `m5-2026-10-27/reconnect.txt`, `heartbeat-liveness.txt` | MET |

## Gate G: Academic defensibility

| Criterion | Where | Status |
|---|---|---|
| Clear research question and contribution | `AI_RESEARCH.md` §1–2 | MET |
| Sound methodology and unbiased evaluation | `EXPERIMENTS.md`; leakage controls in code; run-level CIs; synthetic refusal | MET for the benign/adaptation half; attack half BLOCKED-EXT |
| Reproducible results | Commands, dataset ids, timestamps and versions in each evidence file | PARTIAL: datasets live on CTRL01 `/var/lib/afw/datasets` (not in Git) |
| Detailed limitations | `SECURITY_AND_LIMITATIONS.md`, `THREAT_MODEL.md`, per-milestone docs | MET |
| Professional documentation | The 13 deliverables (this directory) | MET |
| Team can run and explain the system independently | `FINAL_DEMO.md`, `OPERATOR_GUIDE.md` | BLOCKED-EXT: only the team can demonstrate this |

## Overall

| Gate | Status |
|---|---|
| A Infrastructure | **MET** |
| B Detection | **NOT MET**: attack evaluation BLOCKED-EXT |
| C Genuine adaptation | **PARTIAL**: live learning, pivots and restart restore on CTRL01; no promotion (gate refuses: no attack recall data; sensitivity) |
| D Enforcement | **MET** |
| E Independent value | **NOT MET**: benign-only comparison; attack-side value BLOCKED-EXT |
| F Security and operations | **MET**: HTTPS API (ADR-023 revised), all telemetry mTLS, audited and constrained MCP, tested recovery |
| G Academic defensibility | **PARTIAL**: team demonstration BLOCKED-EXT |
