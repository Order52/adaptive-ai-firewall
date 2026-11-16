# Finish plan: from "working lab system" to "release-quality v1.0"

Status: PLAN (written 2026-11-16). Baseline: `PROJECT_STATUS.md`. Nothing here is done yet.

## 0. What "finished" means (definition of done)

The project is finished when **all five** are true. Anything not on this list is out of scope.

1. **Evidence:** attack-side results exist (recall / false negatives per scenario family) and
   are written into `RESULTS.md`, good or bad. Gates B, E and G are closed or honestly
   marked "not achieved, because X".
2. **Quality:** CI is green and *enforcing* (lint, strict types, tests with a coverage floor,
   CVE gate, secret scan). `main` is protected. Release is tagged `v1.0.0`.
3. **Security:** the API and host pass a short checklist based on OWASP ASVS L2 (API subset)
   and CIS Linux basics. No known CRITICAL/HIGH issue is open.
4. **Operations:** health/metrics exist, backup *and restore* are rehearsed, upgrade and
   rollback are written down and rehearsed once, runbooks cover the top failures.
5. **Docs:** one README entry point, a limitations and "path to production" section, a demo
   the whole team can run.

### Explicitly out of scope (state this in the report, do not build it)

High availability / multi-controller, multi-site, a public-CA PKI, SIEM integration, a
Kubernetes deployment, throughput beyond lab scale, enforce-mode ML on real traffic.
These are listed in the report as "path to production" (see Phase 5).

## Standards used (kept deliberately small)

| Area | Standard |
|---|---|
| Versioning / releases | SemVer 2.0, Keep a Changelog |
| App security | OWASP ASVS L2 (API subset), OWASP API Security Top 10 |
| Host hardening | CIS Ubuntu 24.04 Level 1 (key items only) |
| Supply chain | SBOM (CycloneDX), pinned CI actions, dependency audit; SLSA-1/2 level provenance via GitHub |
| Operations | 12-factor config, health/readiness endpoints, Prometheus metrics, simple SLOs |
| Incident handling | NIST SP 800-61 (lightweight runbooks) |
| ML evaluation | Predeclared protocol, one-shot final test, confidence intervals (already your practice) |

## Phase 1: Evidence (team-run; the only thing that moves the grade most)

| # | Task | Done when |
|---|---|---|
| 1.1 | Run >= 3 runs per scenario family per `engineering/P3_TEAM_ATTACK_RUNBOOK.md` | `afw dataset validate` passes for every run |
| 1.2 | Evaluate: `afw experiment evaluate --streaming` on all runs | Recall + FN per family, with CI, in an artifact |
| 1.3 | Exercise the promotion gate live with real attack data | Gate verdict recorded in `live-governance-*/` |
| 1.4 | Four-way comparison (static / ML / hybrid / adaptive) under attack | Table in `RESULTS.md` |
| 1.5 | Update `VALIDATION_MATRIX.md` + `GATE_STATES.md`; mark each gate MET / NOT MET with reason | Gates B, C, E, G have final states |

Rules: never edit results after seeing them; report failures; attack traffic is supplied by
the team only.

## Phase 2: Engineering quality (about 1-2 days)

**Status 2026-11-16: implemented on branch `phase2-engineering-quality`; tasks 2.2 (branch
protection) must be switched on in GitHub settings by the repository owner. The new CI
jobs (`audit`, `secrets`) and the blocking Trivy gate have not yet run on GitHub.**

| # | Task | Done when |
|---|---|---|
| 2.1 | Add `LICENSE`, `SECURITY.md` (how to report issues), `CHANGELOG.md`, `.github/CODEOWNERS`, PR template | Files present |
| 2.2 | Branch protection on `main`: required CI checks, no force-push, PR review | Setting enabled |
| 2.3 | Coverage floor in CI (`--cov-fail-under=N`, N = current coverage rounded down) | CI fails below N |
| 2.4 | Make the Trivy scan **blocking for CRITICAL**; keep HIGH as a report | Pipeline fails on CRITICAL |
| 2.5 | Add `pip-audit` (or `uv` audit) and `gitleaks` jobs | Both run in CI |
| 2.6 | Pin GitHub Actions to commit SHAs (Dependabot keeps them fresh) | No `@vN` tags left |
| 2.7 | Generate a CycloneDX SBOM and attach it to the release | SBOM in release assets |
| 2.8 | `.pre-commit-config.yaml` (ruff, format, gitleaks) | `pre-commit run -a` clean |
| 2.9 | Repo hygiene: move `dash_live.png` and `scratch/` out of the root; fix stale branch line in `PROJECT_STATUS.md`; archive old reports in `docs/` | Root is clean |

## Phase 3: Security review (about 2 days)

API (ASVS L2 subset, one checklist table in `docs/SECURITY_CHECKLIST.md`):

| # | Check | Notes |
|---|---|---|
| 3.1 | AuthN: tokens hashed at rest (done), expiry + rotation procedure, revoke command | Add `afw token revoke` / rotate if missing |
| 3.2 | AuthZ: viewer / operator / admin enforced on every mutating route | One test per route |
| 3.3 | Input validation on every request model; request size limits | Pydantic strict; fuzz two routes |
| 3.4 | Rate limiting on the API and login-like routes | Test returns 429 |
| 3.5 | Audit log for every mutation: who, what, when, result (append-only) | Exists in parts: verify coverage |
| 3.6 | TLS: modern protocol only; cert rotation procedure written and rehearsed once | Runbook |
| 3.7 | Secrets: none in git (gitleaks clean), none in logs | Scan history once |

Host (CIS Level 1, key items only) on CTRL01/WAF01/APP01:

| # | Check |
|---|---|
| 3.8 | SSH: key-only, no root login, limited users |
| 3.9 | Default-deny nftables, only needed ports (already host nftables, verify) |
| 3.10 | `unattended-upgrades` for security patches; services run as non-root (systemd hardening: `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`) |
| 3.11 | Time sync (chrony) and log retention/rotation |

Output: a one-page "security review result" listing pass / fail / accepted-risk per item.

## Phase 4: Reliability and operations (about 2-3 days)

**Status 2026-11-16: implemented and exercised on the live lab on branch
`phase4-operations`; evidence in `SLO.md` and `runbooks/`. 4.5 was already fixed on
2026-10-29 (FW01 at 2.5 GB RAM plus swap). The FW01-reboot and full-disk drills were not run.**

| # | Task | Done when |
|---|---|---|
| 4.1 | `/healthz` (liveness) and `/readyz` (DB, sensors fresh, FW reachable); confirm what exists in `api/app.py`, add the rest | Both return correct state in a test |
| 4.2 | `/metrics` (Prometheus text): sensor lag, events/s, detection latency, policies active, errors | Scrapes cleanly |
| 4.3 | Structured JSON logs with request/correlation id | Logs parse with `jq` |
| 4.4 | Define 4 SLOs and measure them: detection-to-enforce latency (<= 5 s budget, already in docs), API availability, sensor freshness, false-block rate in benign replay | Numbers in `RESULTS.md` |
| 4.5 | **Fix FW01 memory limit**: raise RAM to >= 2.5 GB (or cap Suricata memory) and re-run capture load | No OOM during a 30 min capture |
| 4.6 | Backup + **restore drill** using `scripts/make_offhost_backup.sh` on a clean VM; record time taken (RTO) and data loss window (RPO) | Written drill report |
| 4.7 | Upgrade + rollback procedure for the controller (`afw lab deploy`, previous image/venv kept) rehearsed once | Runbook + proof |
| 4.8 | Failure drills (one table, one run each): kill controller, stop a sensor, reboot FW01, fill disk to 90 %, expire a cert | Each ends in the documented safe state (fail-safe, degraded flag, alert) |
| 4.9 | Light load test (e.g. 5x the lab's normal event rate for 10 min) with `locust` or a script; record CPU/RAM/latency | Numbers + ceiling noted |
| 4.10 | Runbooks (one page each): sensor stale, controller down, false-positive storm / unblock, rollback a promoted model, cert rotation | `docs/runbooks/` |

## Phase 5: Documentation and submission (about 2 days)

| # | Task | Done when |
|---|---|---|
| 5.1 | `README.md`: what it is, architecture picture, quick start, links. Everything else linked from it | A new reader runs the demo from it |
| 5.2 | `FINAL_REPORT.md`: add Evaluation (Phase 1 results), Security review (Phase 3), Operations (Phase 4), **Limitations** and **Path to production** | Sections present |
| 5.3 | "Path to production" list: HA pair, real PKI, SIEM export, more sensors, calibrated models, enforce-mode only after attack-recall gate passes | One page |
| 5.4 | Consolidate the many status/report files: keep `PROJECT_STATUS.md` as the single status, move the rest to `docs/archive/` | No contradictory status docs |
| 5.5 | Demo rehearsal x2 with the whole team; each member explains one component | Checklist signed off |
| 5.6 | Cut the release: update `CHANGELOG.md`, tag `v1.0.0`, confirm the image is built, scanned and published | GitHub Release exists |
| 5.7 | Freeze: archive datasets and evidence (`scripts/archive_datasets.sh`), off-host encrypted backup | Hashes recorded |

## Order and timeline (one team, about 2 weeks)

```
Week 1:  Phase 1 (team attack runs) in parallel with Phase 2 and Phase 3
Week 2:  Phase 4, then Phase 5; feed Phase 1 results into the report
```

Critical path: **Phase 1**. Phases 2-5 can be done without attack data, but the report cannot
be finalised without it. If Phase 1 slips, still ship v1.0.0 with the gates marked honestly
"NOT MET: attack runs not performed".

## Work split suggestion

| Owner | Phases |
|---|---|
| Team (lab operators) | 1.x, 4.6-4.8 drills, 5.5 |
| Claude Code (code and docs, on your review) | 2.x, 3.1-3.5, 3.7, 4.1-4.3, 4.10, 5.1-5.4 |
| Joint (needs the lab) | 3.6, 3.8-3.11, 4.4, 4.5, 4.9 |

## Risks

| Risk | Mitigation |
|---|---|
| Attack runs show weak recall | Report it; that is a valid, defensible result |
| Coverage floor breaks CI | Set N at current value, raise later |
| FW01 resize impossible | Cap Suricata memory/threads instead; document the cap |
| Scope creep | Anything outside section 0 goes to "path to production" |
