# Release criteria and stop rule

Written 2026-11-17. This is the threshold for calling the project **ready to present as a
release candidate**. It is deliberately small and every gate is checkable by a command, so
the work has an end. Progress is recorded in section 4.

## 1. Gates (all must hold)

| # | Gate | Check (command or place) | Pass when |
|---|---|---|---|
| R1 | **Pipeline** | GitHub Actions on `main` and on the tag | CI, CodeQL and CD green; a pre-release exists with the image (GHCR) and SBOM; Trivy shows no CRITICAL with a fix |
| R2 | **Tests** | `uv run pytest tests/unit tests/integration` | All pass; coverage at or above the floor in `pyproject.toml`; CI test job under 12 minutes |
| R3 | **Static quality** | `ruff check`, `ruff format --check`, `mypy --strict` | Zero findings |
| R4 | **Live lab** | `afw lab verify`, `/api/readyz`, dashboard render | 41/41 checks, controller ready, no stale sensor, dashboard with 0 console errors |
| R5 | **Security** | `pip-audit`, secret scan, `SECURITY_CHECKLIST.md` | 0 known vulnerable dependencies, 0 secrets, 0 open findings (accepted risks listed) |
| R6 | **Docs are true** | README quick start run command by command; stale-claim sweep | Every command in the README and demo works as written; no document contradicts the status page |
| R7 | **Evidence is honest** | `PROJECT_STATUS.md`, `RESULTS.md`, README | Every performance claim is labelled MEASURED (live), OFFLINE, SYNTHETIC or UNMEASURED; nothing unmeasured appears as a result |
| R8 | **Demo** | `FINAL_DEMO.md` non-attack steps executed | Each step run once with its output saved under `artifacts/evidence/release-rehearsal-*/` |

## 2. Out of scope (will not be built here)

New detectors, new features, HA, a public PKI, SIEM export, Kubernetes. These stay in
`PATH_TO_PRODUCTION.md`. **Live attack evaluation (gates B, E, G) needs the team's attack runs
and cannot be satisfied by this work. It is reported as `BLOCKED-EXT`, never faked.**

## 3. Stop rule

One **iteration** = run every check in section 1, fix each failing gate, record the result.

Stop when **any** of these holds:

1. R1 to R8 all pass. The project is then "release candidate ready".
2. Two consecutive iterations find no new failure and every remaining failing gate is
   `BLOCKED-EXT` (needs a human, the team or an outside account).
3. Three iterations have run. Whatever still fails is written up with its cause.

Rules while iterating: fix gate failures only (no scope growth); never edit a result after
seeing it; never generate attack traffic; every change keeps R2 and R3 green before it is
pushed.

## 4. Progress log

| Iteration | Date | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 2026-11-17 | fail | pass (local) | pass | pass | pass | not run | partial | not run | CD never worked since 2026-11-11 (Trivy image ref upper-case); CI test job 22 min |
