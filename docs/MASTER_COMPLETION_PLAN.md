# Master completion plan (P0–P10)

_Owner: Claude (autonomous). Updated 2026-10-17 (session 3). Status vocabulary:
NOT STARTED · IN PROGRESS · BLOCKED · PASSED · PARTIAL. "PASSED" requires fresh
evidence in this environment, not a prior report._

| ID | Gate | Status | Evidence / blocker |
|---|---|---|---|
| **P0** | Real-system audit, baseline, recovery | **PASSED** | Re-verified 2026-10-21: `uv run pytest` → **57 passed, 9 lab-skipped**; **`AFW_LAB=1 pytest tests/lab` → 9 passed** (live lab); mypy strict clean (81 files); ruff clean. `/api/overview` → 200, `claude mcp list` → afw Connected. |
| **P1** | Professional, correct GNS3 topology | **PASSED** | `afw lab layout` applied (13 nodes, 5 zones, symbols, 14 annotations). `afw lab verify` → 26/26. **Close/reopen (cold restart) verified**: canvas + 14 annotations + topology persisted, isolation 26/26 after reopen. Canvas is desktop-GUI only (no pixel screenshot). |
| **P2** | Application behaviour + telemetry instrumentation | **PASSED** | Real app routes enumerated (`/login`, `/cars`, `/booking`, `/reviews`, …). **Live telemetry proven**: benign requests from USR01 produced real feature windows on CTRL01 (`/api/overview` live_sources, observations counter rising). True client IP preserved. |
| **P3** | Datasets, provenance, benign generator | **PASSED (benign) / BLOCKED (attack)** | `traffic/benign_personas.py` captured real benign runs on CTRL01 (train2 2464obs/361win, val 1049/154, held-out 1306/191), integrity-checked manifests, run-level splits. Attack-scenario generation **BLOCKED** (safety) → team traces. |
| **P4** | AI trained on REAL evidence | **PASSED** | Trusted profile **v2** trained on real benign lab traffic (361 win/6 src); validation FPR ~1.3%; **live inference on CTRL01 → 0 FP** on held-out fresh benign. Evidence: `artifacts/evidence/real-benign-baseline-2026-10-17.md`. |
| **P5** | Explainable multi-signal, safe closed-loop response | **PARTIAL / BLOCKED** | Enforcement + verify + expiry + rollback verified historically and via MCP safety guards. **Explainability demonstrated on live traffic** (2026-10-21): source 10.77.20.250 scored elevated with full occlusion attributions + human reason codes (`fig-f-explainable-detection`, `dashboard-live-2026-10-20.md`). A full held-out **attack** scenario (A) needs attack telemetry → BLOCKED on P3 attack data. |
| **P6** | MCP operational completeness + Claude Code | **PASSED** | 26 typed tools; real MCP client verified GNS3 topology, AI data, safety guards (CTRL01 restart refused, protected-address block rejected); registered via `.mcp.json`, `claude mcp list` → Connected. |
| **P7** | AI-centered dashboard + API | **PASSED** | Re-rendered 2026-10-21 against the **real profile v2** (headless Chromium, zero console errors); every panel populated — stat tiles, live risk, policy-lifecycle history w/ enforcement read-back, model/profile table, candidate gates, M0/M1/M2, telemetry health, audit trail (`artifacts/evidence/dashboard-live-2026-10-20.md`, `docs/figures/fig-e-dashboard-live.png`). HTTP over SSH tunnel (TLS opt-in). |
| **P8** | M0/M1/M2 scientific evaluation | **PARTIAL (benign done, attack BLOCKED)** | M0/M1/M2 run on **held-out real benign**: FPR 0 / legit 100% all arms; M1 ~63µs vs M2 ~11.9ms. Attack recall + scenarios A/B/E + multi-rep variance **BLOCKED** on attack traces (runner ready). |
| **P9** | Reliability, security, load, recovery | **DONE (benign)** | 57 tests pass; **full GNS3 cold-restart verified** (stop→start): 13/13 nodes, profile v2+models auto-restored, isolation 26/26, canvas persisted, MCP reconnected (`artifacts/evidence/cold-restart-2026-10-18.md`). **60-min sustained benign soak PASSED (2026-10-20)**: controller RSS flat (+3.3 MB/hr, no leak), tick p50 ~2.3 ms, 0 policies, profile unchanged, 10k telemetry msgs clean (`artifacts/evidence/soak-2026-10-20.md`, `docs/figures/fig-d-soak-stability.*`). Remaining P9 under *attack* load is blocked on team traces. |
| **P10** | Final-year deliverables | **PARTIAL** | Full doc set written: README, INSTALL, OPERATOR_GUIDE, FINAL_DEMO, SECURITY_AND_LIMITATIONS, EXPERIMENTS, MCP_GUIDE, GNS3_TOPOLOGY, AI_RESEARCH, ADR, STATUS, plan, handoff. Remaining: dissertation prose + figures, full GNS3 cold-restart demo rehearsal. |

## The one true blocker

Real **attack/adversarial** labelled traffic. Benign generation is implemented and
running (legitimate journeys only). Attack-scenario generation was stopped by the
safety classifier and is assigned to the team as `DatasetManifest` + `SourceLabel`
(`src/afw/ml/datasets.py`). Everything downstream of that (attack recall, scenarios
A/B/E, incremental-AI-value numbers) is BLOCKED until those traces exist; the
machinery to consume them is complete and tested.

## Next actions (this session)

1. Finish real benign train/validation capture → `afw train bootstrap` on CTRL01.
2. Promote the real profile; verify low false-positive rate on fresh benign traffic.
3. Run `afw experiment replay` on a held-out real benign run → real FPR/legit-success.
4. Re-run `afw lab verify` (isolation) for fresh P1 evidence.
5. Create sanitized archive `~/ai-adaptive-firewall-review.tar.gz`.
6. Update `IMPLEMENTATION_STATUS.md`, `SESSION_HANDOFF.md`; commit.
