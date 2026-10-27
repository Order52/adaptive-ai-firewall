# Autonomous engineering progress (authoritative)

Branch `engineering-directive`. Baseline tag `baseline-2026-10-27`. This file is the
single source of truth for milestone status under the autonomous execution directive.
Status words: **DONE** (implemented, tested, evidence exists), **PARTIAL** (some
acceptance criteria open, listed), **BLOCKED-EXT** (needs something only the team can
supply), **TODO**.

Last updated: 2026-10-27 ~21:15Z (M0–M9 worked through; remaining gaps are BLOCKED-EXT or listed below).

## Milestones

| M | Scope | Status | Commits | Evidence |
|---|---|---|---|---|
| M0 | Phase 0 audit, baseline, hygiene | DONE | `b3c8702`, `d096cc0` | `docs/audit/PHASE0_AUDIT_2026-10-27.md`, `artifacts/evidence/phase0-2026-10-27/` |
| M1 | Provenance-aware corroboration (ADR-027) | DONE (SV-1 open, see risks) | `9b99947` | `tests/unit/test_evidence_independence.py` |
| M2 | Online shadow learning, eligibility, provenance, mTLS (ADR-028/029) | PARTIAL: pivot and checkpoint-restore shown on real benign replays (227 learned, 1 pivot, restore true); live challenger learned 0 because every new live source was tainted by champion proposals (fail-closed by design), so no live pivot or live restore yet | `a5f5d9f`, `673202a`, `f41f6cf` | `artifacts/evidence/m2-2026-10-27/`, `docs/engineering/M2_ONLINE_LEARNING_DESIGN.md` |
| M3 | Champion/challenger gate, human promotion, probation, auto-rollback (ADR-030) | DONE (code + tests + live refusals); live gate BLOCKED-EXT (no real labelled attack runs) | `44031d4` | `docs/engineering/M3_CHAMPION_CHALLENGER.md`, `artifacts/evidence/m3-2026-10-27/` |
| M4 | Adaptation experiments: real drift, poisoning, regression rollback | DONE: found and fixed a real poisoning flaw (driver-name corroboration); gate still FAILS on attack recall (BLOCKED-EXT) and sensitive invariance (real finding) | `346f9d9` | `docs/engineering/M4_ADAPTATION_EXPERIMENTS.md`, `artifacts/evidence/m3-2026-10-27/m4-adaptation*.json` |
| M5 | Telemetry v2: envelope, IDS dedup, IDS-only view, heartbeats, liveness (ADR-031) | DONE: live-verified. Found and fixed two live defects (silent ~55 min stall after restart; heartbeat JSON mangled by systemd quoting). Residual: TCP syslog loses lines written into a dead session (≤ about 100 s), RELP not done | `81e8d76` | `docs/engineering/M5_TELEMETRY_V2.md`, `artifacts/evidence/m5-2026-10-27/` |
| M6 | Attack-evaluation harness: registry, journal, kill switch, watchdog, run-level CIs (ADR-032) | DONE (harness); Gate B BLOCKED-EXT on team attack runs | `81e8d76` | `docs/engineering/M6_ATTACK_EVALUATION.md`, `artifacts/evidence/m6-2026-10-27/` |
| M7 | Real GeoIP: DB-IP Lite, integrity, freshness, preview (ADR-033) | DONE (lookup + preview, live); real-country *enforcement* deliberately refused (not implemented, documented) | `81e8d76` | `docs/engineering/M7_GEOIP.md`, `artifacts/evidence/m7-2026-10-27/` |
| M8 | Dashboard: shadow learning (eligibility exclusions, learned-window fingerprints), gate/probation, sensor liveness, IDS-only, GeoIP freshness | DONE: deployed and rendered live (headless Chromium, no console errors); screenshot kept locally (`dashboard-m8.png`, not committed) | `2148038` | `artifacts/evidence/m8-2026-10-27/dashboard-panels.txt` |
| M9 | Docs consolidation: the 13 Phase 11 deliverables, validation matrix, single project status | DONE: superseded status files moved to `docs/archive/`; RESULTS corrected (new-user FPR) | this commit | `docs/PROJECT_STATUS.md`, `docs/VALIDATION_MATRIX.md`, `artifacts/evidence/m9-2026-10-27/` |

## Tests (latest full run)

`uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest -q`
→ ruff clean, mypy clean (94 files), pytest 155 passed, 9 skipped (lab tests need
`AFW_LAB=1`). Mutation checks: M5 (in M5 doc), M6 10/10, M7 7/7 caught.
Live (after all M5–M8 deploys, 2026-10-27 20:59–21:00Z): `uv run afw lab verify` 37/37;
`AFW_LAB=1 uv run pytest tests/lab` 9 passed (`artifacts/evidence/m9-2026-10-27/`).

## Acceptance gates (directive A–G)

Unchanged by M2/M3: none may be declared passed without evidence. Any gate that needs
attack-detection results stays **failed/blocked** until real labelled attack runs exist.

## Risks and open items

* **SV-1 (security validation, open):** M1's occlusion test shows a detector stays
  anomalous with the evidence features masked; it is not proof of causal independence.
* **Champion false positives on new benign sources (observed live 2026-10-27):** the
  v2 champion flagged personas on 10.77.20.11–16 (16 proposals in monitor mode, none
  enforced). Because policed sources are tainted, the live challenger learned 0
  windows from them. Fail-closed by design; adaptation needs an operator
  FALSE_POSITIVE path or a curated drift dataset (M4).
* **Default learning caps make adaptation slow:** 20 windows/source/hour means a
  reference pivot (window 180) needs at least 1.5 h of 6 clean tenured sources.
* No real labelled attack runs: M3 live gate, M6 metrics and every attack-recall claim
  are blocked externally.
* **Sensitive-feature invariance fails on the real drift experiment** (M4): the adapted
  challenger flags 0.162 of attack-like probes, against the champion's 0.419 (limit
  0.369). Learning drift lost sensitivity to high-auth-failure behaviour; a promotion
  would be refused. A real finding, not hidden.
* **Residual poisoning risk** (M4): four or more colluding tenured sources with similar
  behaviour can still corroborate each other. Documented, not solved.
* **Telemetry loss window** (M5): up to about 100 s of lines written into a dead TCP
  session are lost; heartbeat staleness makes the gap visible. RELP would close it.
* **Kill switch** (M6) was verified by unit test and a read-only live lookup of ATK01,
  not by actually stopping ATK01.

## Blocked tasks (external)

* Team-run attack scenarios through the M6 harness (`afw scenario begin/mark/end`,
  `afw scenario manifest`, `afw dataset capture`), at least 3 runs per family →
  unblocks Gate B, the M3 live gate and `afw experiment evaluate`.

## Next task

All achievable directive work is done. What remains is listed in `docs/PROJECT_STATUS.md`
§4. Items 1 (team attack runs) and the Gate G team demonstration are external. Items
2–4 are follow-up engineering that needs new benign data captures or hours of live
traffic: broader benign training data, live online adaptation, and investigating the
sensitive-invariance failure.

## Resume commands

```bash
cd ~/uot/ai-adaptive-firewall && git checkout engineering-directive && git log --oneline -8
uv sync && uv run pytest -q                        # local gates
uv run afw lab verify                              # live isolation (needs lab up)
curl -s -H "Authorization: Bearer $(cat ~/.config/afw/api/dashboard.token)" \
  http://10.77.50.10:8080/api/learning/shadow | jq .status
uv run afw lab deploy --limit ctrl01               # redeploy controller
```
