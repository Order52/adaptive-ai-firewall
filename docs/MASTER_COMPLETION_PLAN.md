# Master completion plan (P0–P10)

_Owner: Claude (autonomous). Updated 2026-10-17 (session 3). Status vocabulary:
NOT STARTED · IN PROGRESS · BLOCKED · PASSED · PARTIAL. "PASSED" requires fresh
evidence in this environment, not a prior report._

| ID | Gate | Status | Evidence / blocker |
|---|---|---|---|
| **P0** | Real-system audit, baseline, recovery | **PASSED** | `uv run pytest` → 57 passed, 9 lab-skipped; mypy strict clean (81 files); ruff clean. `afw lab status` → 13/13 nodes started. Controller `/api/overview` → 200. `claude mcp list` → afw Connected. Git clean on `session3-...` branch. |
| **P1** | Professional, correct GNS3 topology | **PASSED** | `afw lab layout` applied (13 nodes, 5 zones, symbols, 14 annotations), verified via GNS3 API. **`afw lab verify` re-run this session → 26/26 PASSED** (fresh evidence). Canvas is desktop-GUI only (no pixel screenshot). |
| **P2** | Application behaviour + telemetry instrumentation | **PASSED** | Real app routes enumerated (`/login`, `/cars`, `/booking`, `/reviews`, …). **Live telemetry proven**: benign requests from USR01 produced real feature windows on CTRL01 (`/api/overview` live_sources, observations counter rising). True client IP preserved. |
| **P3** | Datasets, provenance, benign generator | **PASSED (benign) / BLOCKED (attack)** | `traffic/benign_personas.py` captured real benign runs on CTRL01 (train2 2464obs/361win, val 1049/154, held-out 1306/191), integrity-checked manifests, run-level splits. Attack-scenario generation **BLOCKED** (safety) → team traces. |
| **P4** | AI trained on REAL evidence | **PASSED** | Trusted profile **v2** trained on real benign lab traffic (361 win/6 src); validation FPR ~1.3%; **live inference on CTRL01 → 0 FP** on held-out fresh benign. Evidence: `artifacts/evidence/real-benign-baseline-2026-10-17.md`. |
| **P5** | Explainable multi-signal, safe closed-loop response | **PARTIAL / BLOCKED** | Enforcement + verify + expiry + rollback verified historically and via MCP safety guards. A full held-out **attack** scenario (A) needs attack telemetry → BLOCKED on P3 attack data. Benign false-positive behaviour is verifiable now. |
| **P6** | MCP operational completeness + Claude Code | **PASSED** | 26 typed tools; real MCP client verified GNS3 topology, AI data, safety guards (CTRL01 restart refused, protected-address block rejected); registered via `.mcp.json`, `claude mcp list` → Connected. |
| **P7** | AI-centered dashboard + API | **PASSED** | Rendered in headless Chromium (zero console/page errors); every panel validated with real backend data; interactive explain works; two bugs fixed; populated live. HTTP over SSH tunnel (TLS opt-in). |
| **P8** | M0/M1/M2 scientific evaluation | **PARTIAL (benign done, attack BLOCKED)** | M0/M1/M2 run on **held-out real benign**: FPR 0 / legit 100% all arms; M1 ~63µs vs M2 ~11.9ms. Attack recall + scenarios A/B/E + multi-rep variance **BLOCKED** on attack traces (runner ready). |
| **P9** | Reliability, security, load, recovery | **PARTIAL** | 57 tests pass; isolation 26/26 fresh; **controller restart recovery verified this session** (profile v2 + models auto-restored). Full GNS3 cold-restart + ≥60-min soak still pending. |
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
