# Autonomous engineering progress (authoritative)

Branch `engineering-directive`. Baseline tag `baseline-2026-10-27`. This file is the
single source of truth for milestone status under the autonomous execution directive.
Status words: **DONE** (implemented, tested, evidence exists), **PARTIAL** (some
acceptance criteria open, listed), **BLOCKED-EXT** (needs something only the team can
supply), **TODO**.

Last updated: 2026-10-27 (M3 implemented; live 75-min benign run in progress).

## Milestones

| M | Scope | Status | Commits | Evidence |
|---|---|---|---|---|
| M0 | Phase 0 audit, baseline, hygiene | DONE | `b3c8702`, `d096cc0` | `docs/audit/PHASE0_AUDIT_2026-10-27.md`, `artifacts/evidence/phase0-2026-10-27/` |
| M1 | Provenance-aware corroboration (ADR-027) | DONE (SV-1 open, see risks) | `9b99947` | `tests/unit/test_evidence_independence.py` |
| M2 | Online shadow learning, eligibility, provenance, mTLS (ADR-028/029) | PARTIAL: live pivot-level evidence and restart-on-CTRL01 evidence pending | `a5f5d9f`, `673202a`, `f41f6cf` | `artifacts/evidence/m2-2026-10-27/`, `docs/engineering/M2_ONLINE_LEARNING_DESIGN.md` |
| M3 | Champion/challenger gate, human promotion, probation, auto-rollback (ADR-030) | DONE (code + tests); live gate BLOCKED-EXT (no real labelled attack runs) | pending | `docs/engineering/M3_CHAMPION_CHALLENGER.md`, `artifacts/evidence/m3-2026-10-27/` |
| M4 | Adaptation experiments (drift, poisoning, replay) | TODO | | |
| M5 | Telemetry v2 / IDS-only view | TODO | | |
| M6 | Attack evaluation harness | TODO (gate BLOCKED-EXT on team attack traces) | | |
| M7 | Real GeoIP (DB-IP Lite, pre-authorised) | TODO | | |
| M8 | Dashboard (shadow, gate, probation views) | TODO | | |
| M9 | Docs consolidation, validation matrix | TODO | | |

## Tests (latest full run)

`uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest -q`
→ ruff clean, mypy clean (90 files), pytest 121 passed, 9 skipped (lab tests need
`AFW_LAB=1`). Live: `uv run afw lab verify` 37/37; `AFW_LAB=1 uv run pytest tests/lab` 9 passed.

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

## Blocked tasks (external)

* Team-supplied attack scenarios as datasets (`afw dataset capture` with a manifest
  listing `role: attack` sources) → unblocks M3 live gate, M6 evaluation, gate recall checks.

## Next task

Finish M2 live evidence after the run ends (~19:18Z): capture the run as a dataset,
redeploy CTRL01 (restart = checkpoint-restore evidence), replay with relaxed caps for
a pivot, run `afw challenger evaluate` live (expected FAIL: no real attack runs). Then M4.

## Resume commands

```bash
cd ~/uot/ai-adaptive-firewall && git checkout engineering-directive && git log --oneline -8
uv sync && uv run pytest -q                        # local gates
uv run afw lab verify                              # live isolation (needs lab up)
curl -s -H "Authorization: Bearer $(cat ~/.config/afw/api/dashboard.token)" \
  http://10.77.50.10:8080/api/learning/shadow | jq .status
uv run afw lab deploy --limit ctrl01               # redeploy controller
```
