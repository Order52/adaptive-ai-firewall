# Autonomous engineering progress (authoritative)

Branch `engineering-directive`. Baseline tag `baseline-2026-10-27`. This file is the
single source of truth for milestone status under the autonomous execution directive.
Status words: **DONE** (implemented, tested, evidence exists), **PARTIAL** (some
acceptance criteria open, listed), **BLOCKED-EXT** (needs something only the team can
supply), **TODO**.

Last updated: 2026-10-28 ~08:45Z (M0–M9 plus directive priorities P1–P5 worked through; remaining gaps are BLOCKED-EXT or listed below).

## Milestones

| M | Scope | Status | Commits | Evidence |
|---|---|---|---|---|
| M0 | Phase 0 audit, baseline, hygiene | DONE | `b3c8702`, `d096cc0` | `docs/audit/PHASE0_AUDIT_2026-10-27.md`, `artifacts/evidence/phase0-2026-10-27/` |
| M1 | Provenance-aware corroboration (ADR-027) | DONE (SV-1 open: needs attack runs, see risks) | `9b99947` | `tests/unit/test_evidence_independence.py` |
| M2 | Online shadow learning, eligibility, provenance, mTLS (ADR-028/029) | DONE (2026-10-28, P4): live learning on CTRL01 (367 windows, 2 live pivots, checkpoints), exact checkpoint restore across 2 controller restarts, live gate rejection; 0-learned cause explained (deliberate taint). Found and fixed a leaking per-source rate cap | `a5f5d9f`, `673202a`, `f41f6cf`, P4 commits | `docs/engineering/M2_ONLINE_LEARNING_DESIGN.md` §9–10, `artifacts/evidence/p1-2026-10-28/p4-*` |
| M3 | Champion/challenger gate, human promotion, probation, auto-rollback (ADR-030) | DONE (code + tests + live refusals); live gate BLOCKED-EXT (no real labelled attack runs) | `44031d4` | `docs/engineering/M3_CHAMPION_CHALLENGER.md`, `artifacts/evidence/m3-2026-10-27/` |
| M4 | Adaptation experiments: real drift, poisoning, regression rollback | DONE: found and fixed a real poisoning flaw (driver-name corroboration); gate still FAILS on attack recall (BLOCKED-EXT) and sensitive invariance; P2 traced the latter to threshold calibration, not the learned state | `346f9d9` | `docs/engineering/M4_ADAPTATION_EXPERIMENTS.md`, `artifacts/evidence/m3-2026-10-27/m4-adaptation*.json` |
| M5 | Telemetry v2: envelope, IDS dedup, IDS-only view, heartbeats, liveness (ADR-031) | DONE: live-verified. Found and fixed two live defects (silent ~55 min stall after restart; heartbeat JSON mangled by systemd quoting). Residual: TCP syslog loses lines written into a dead session (≤ about 100 s), RELP not done | `81e8d76` | `docs/engineering/M5_TELEMETRY_V2.md`, `artifacts/evidence/m5-2026-10-27/` |
| M6 | Attack-evaluation harness: registry, journal, kill switch, watchdog, run-level CIs (ADR-032) | DONE (harness); Gate B BLOCKED-EXT on team attack runs | `81e8d76` | `docs/engineering/M6_ATTACK_EVALUATION.md`, `artifacts/evidence/m6-2026-10-27/` |
| M7 | Real GeoIP: DB-IP Lite, integrity, freshness, preview (ADR-033) | DONE (lookup + preview, live); directional real-country enforcement added 2026-10-28 (P5, ADR-036) | `81e8d76`, P5 commits | `docs/engineering/M7_GEOIP.md` |
| M8 | Dashboard: shadow learning (eligibility exclusions, learned-window fingerprints), gate/probation, sensor liveness, IDS-only, GeoIP freshness | DONE: deployed and rendered live (headless Chromium, no console errors); screenshot committed (`dashboard-m8.png`, lab data only) | `2148038` | `artifacts/evidence/m8-2026-10-27/dashboard-panels.txt` |
| M9 | Docs consolidation: the 13 Phase 11 deliverables, validation matrix, single project status | DONE: superseded status files moved to `docs/archive/`; RESULTS corrected | `19d401c` | `docs/PROJECT_STATUS.md`, `docs/VALIDATION_MATRIX.md`, `artifacts/evidence/m9-2026-10-27/` |


## Directive priorities (2026-10-28)

| P | Scope | Status | Evidence |
|---|---|---|---|
| P1 | Benign generalization | DONE (negative-with-trade-off): predeclared protocol; 16 unseen users, later period, workload shifts. v2 restricts 13/16 unseen users; the v3 candidate 0/16 but **fails** the predeclared sensitivity, old-regime and IF-FPR criteria, so it is not promoted. Cause: training data (one 5.4-min run with an unrealistic multi-account generator), not thresholds. The earlier "six new users" claim was false and is corrected | `docs/engineering/P1_BENIGN_GENERALIZATION.md`, `artifacts/evidence/p1-2026-10-28/p1-*` |
| P2 | Sensitive invariance | DONE: mechanism is threshold recalibration, not the learned state (matched windows, decomposition); gate check rebuilt on matched windows per feature (ADR-034) with a desensitization benchmark (6/6 mutants) | `M4_ADAPTATION_EXPERIMENTS.md` §2, `p2-*`, `m4-adaptation-p2-gate.json` |
| P3 | Independent attack evaluation | BLOCKED-EXT: harness ready; precise team runbook written; `experiment evaluate --version` evaluates candidates too | `docs/engineering/P3_TEAM_ATTACK_RUNBOOK.md` |
| P4 | Real online adaptation | DONE for the governed loop (live learning, pivots, restart restore, live gate rejection); no live promotion (needs attack runs; sensitivity fails) | `M2_ONLINE_LEARNING_DESIGN.md` §9–10 |
| P5 | Hardening | DONE: FW01 IDS feed mTLS, plaintext listener removed (ADR-035); API HTTPS by default with tunnel-safe certificate (ADR-023 revised); directional real-country enforcement on FW01 with read-back, egress-probe proof and watchdog fail-safe (ADR-036; found and fixed a live read-back defect); node count reconciled (16); replay request denominators fixed. Inbound country blocks verifiable by read-back only | `p5-*.txt`, `GNS3_TOPOLOGY.md`, `M7_GEOIP.md` §5 |

## Tests (latest full run)

`uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest -q`
→ ruff clean, mypy clean (97 files), pytest 198 passed, 14 skipped (lab tests need
`AFW_LAB=1`; live: 14/14 lab tests, 37/37 isolation, 2026-10-28 09:52Z). Mutation checks: M5 (in M5 doc), M6 10/10, M7 7/7, P2 6/6, P4 rate cap 3/3, P5 country enforcement 9/9 caught.
Live (after all M5–M8 deploys, 2026-10-27 20:59–21:00Z): `uv run afw lab verify` 37/37;
`AFW_LAB=1 uv run pytest tests/lab` 9 passed (`artifacts/evidence/m9-2026-10-27/`).

## Acceptance gates (directive A–G)

Unchanged by M2/M3: none may be declared passed without evidence. Any gate that needs
attack-detection results stays **failed/blocked** until real labelled attack runs exist.

## Risks and open items

* **SV-1 (security validation, open, needs attack runs):** M1's occlusion test shows a
  detector stays anomalous with the evidence features masked; it is not proof of causal
  independence. Benign traffic cannot exercise it (AUTH evidence needs ≥ 5 failed logins
  at ≥ 50 % in 30 s). Proposed stronger test once brute-force runs exist: rebuild the
  window without the evidence-generating requests and re-score.
* **Champion false positives on legitimate users (2026-10-27/28):** the v2 champion
  flags most users whose behaviour differs from its training run (P1: 13/16 unseen users
  in replay; live monitor-mode proposals tainted 21/24 P1 Phase A users). Policed sources
  are tainted, so online learning cannot correct the champion's own errors (M2 §9).
  The fix is a better champion through the gate, which needs attack runs.
* **v3 candidate trade-off (P1):** far fewer false positives, measurably less ML
  sensitivity to moderate single-feature changes. Not promoted.
* **Default learning caps make adaptation slow:** 20 windows/source/hour means a
  reference pivot (window 180) needs at least 1.5 h of 6 clean tenured sources.
* No real labelled attack runs: M3 live gate, M6 metrics and every attack-recall claim
  are blocked externally.
* **Sensitive-feature invariance fails** for the M4 drift challenger and the live P4
  challenger (matched windows, ADR-034). P2: for M4 the loss comes from the calibrated
  threshold; the learned state alone is more sensitive. Promotion is refused either way.
* **Leaking per-source learning cap (fixed 2026-10-28):** the first 367 live windows
  were admitted while the cap leaked (disclosed in M2 §10).
* **Lab availability:** an unattended host upgrade restarted gns3server on 2026-10-28
  06:36Z and stopped every VM (`p1-2026-10-28/lab-outage-2026-10-28.log`). Recommended
  (host change, not made by the agent): exclude `gns3server` from needrestart's
  automatic restarts.
* **Residual poisoning risk** (M4): four or more colluding tenured sources with similar
  behaviour can still corroborate each other. Documented, not solved.
* **Telemetry loss window** (M5): up to about 100 s of lines written into a dead TCP
  session are lost; heartbeat staleness makes the gap visible. RELP would close it.
  FW01 sends no heartbeat, so a silent IDS feed is not detected.
* **Kill switch** (M6) was verified by unit test and a read-only live lookup of ATK01,
  not by actually stopping ATK01.

## Blocked tasks (external)

* Team-run attack scenarios through the M6 harness (`afw scenario begin/mark/end`,
  `afw scenario manifest`, `afw dataset capture`), at least 3 runs per family →
  unblocks Gate B, the M3 live gate and `afw experiment evaluate`.

## Next task

All achievable directive work is done and verified; the rest is external:

1. Team attack runs (`P3_TEAM_ATTACK_RUNBOOK.md`) → Gate B, Gate E, M3 live gate, SV-1,
   and the decision on v3 (`afw experiment evaluate --version 3`).
2. Team demonstration (Gate G).

Engineering follow-ups that need no team input but were not required: RELP for
loss-free telemetry; API TLS by default; a training-data design that keeps ML
sensitivity while covering benign variety (e.g. per-feature monotone constraints on the
sensitive features).

## Resume commands

```bash
cd ~/uot/ai-adaptive-firewall && git checkout engineering-directive && git log --oneline -8
uv sync && uv run pytest -q                        # local gates
uv run afw lab verify                              # live isolation (needs lab up)
curl -s -H "Authorization: Bearer $(cat ~/.config/afw/api/dashboard.token)" \
  https://10.77.50.10:8080/api/learning/shadow | jq .status
uv run afw lab deploy --limit ctrl01               # redeploy controller
```
