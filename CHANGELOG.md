# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [SemVer](https://semver.org/). Detailed milestone history is in
`docs/engineering/AUTONOMOUS_PROGRESS.md`; current status is in `docs/PROJECT_STATUS.md`.

## [Unreleased]

### Changed
- Default detection strategy is now `statistical` (`initial_strategy`, ADR-045); `ml` stays selectable.

### Fixed
- **Live learning deadlock.** Any proposal tainted its source for 24 h, so a false positive on a
  new legitimate user stopped the learning that would have fixed it (the live learner learned 0
  windows). A source is now tainted by a policy only while that policy really changes its
  traffic; unapplied proposals (monitor or approval mode) and proposals resting on behaviour
  models alone no longer taint.
- Test race under `pytest -n auto`: two API tests shared one token file.

### Added
- `afw experiment scorecard`: judges an evaluation report against the predeclared detection
  thresholds (`docs/FINAL_YEAR_PLAN.md`); refuses synthetic reports.
- `scripts/ad1_collect.py`, `scripts/ad1_report.py`: live champion-vs-challenger measurement.
- **Operator vouching.** `benign_change` / `false_positive` feedback on a source makes its windows
  learnable within the quarantine time, instead of waiting for tenure, a population of similar
  sources and corroboration. Evidence, range, rate and share checks still apply. Switch:
  `learning.operator_vouching`.
- `afw experiment adaptation` reports a third arm, `fast`, next to `default` and
  `experiment_relaxed`.

### Changed
- Faster live learning in `config/lab.yaml`: quarantine 600 to 180 s, source tenure 1800 to 600 s,
  20 to 60 windows per source per hour. On the recorded drift run: 45 learned windows and no
  pivot before, 190 learned windows and one pivot now. Poisoning results are unchanged.

## [1.0.0-rc.2] - 2026-11-17

Release candidate. The first release whose CI and CD pipeline ran green end to end on GitHub.
Same caveat as rc.1: **attack-side evaluation has not been run**, so detection recall on the
lab is unmeasured (gates B, E, G are "NOT MET: attack runs not performed"; see
`docs/PROJECT_STATUS.md`). Release criteria and results: `docs/RELEASE_CRITERIA.md`.

### Added
- `scripts/refresh_geoip.sh` and metrics `afw_geoip_stale` / `afw_geoip_age_days`: the GeoIP
  database had silently gone stale (47 days old); refreshed on the lab.
- `docs/RELEASE_CRITERIA.md` (measurable release gates and a stop rule) and rehearsal evidence in
  `artifacts/evidence/release-rehearsal-2026-11-17/`.
- README "Evidence at a glance": every claim labelled MEASURED, OFFLINE, SYNTHETIC or UNMEASURED.

### Fixed
- CD: the image job failed on every run since 2026-11-11. `aquasecurity/trivy-action` could not
  install Trivy 0.65.0, so no scanner existed. Trivy 0.76.2 is now installed directly, pinned, with
  the release checksum verified by its install script; the report upload also gets the
  `security-events: write` permission it needs. The tag run also checked CI before CI had
  started, which failed it; it now waits for the checks to register.
- Dashboard: with no or a rejected token the page polled the API about 15 times in its first
  second and kept going, tripping the new authentication-failure lockout on its own so the correct
  token was refused for up to a minute. It now makes no calls without a token, stops after one
  rejection and honours `Retry-After` on 429 (browser-tested: 0 failing calls with no token, 1 with
  a bad one, immediate connection with a valid one).
- Dashboard: `fmt()` stripped trailing zeros from integers, so chart axes read 1/5/0 instead of
  100/50/0. Long JSON in drift reports no longer overflows its card.
- README and docs: storage, node count (8 VMs), check count (41) and ADR range corrected; the
  "zero false positives" caption now states that it holds only for the profile's own sources.

### Changed
- Tests run in parallel (`pytest -n auto`, pytest-xdist): about 2 min locally (6 min with
  coverage). On GitHub the test job is about 12 min either way (one 217 s test is the long pole).

## [1.0.0-rc.1] - 2026-11-16 (tag exists; never published, CD failed)

Release candidate. Engineering, security review and operations work from
`docs/PRODUCTION_PLAN.md` phases 2-6 are complete. **Not a final 1.0.0:** attack-side
evaluation (plan phase 1) has not been run, so detection recall is unproven and gates B, E
and G are "NOT MET: attack runs not performed" (see `docs/PROJECT_STATUS.md`).

### Added
- `SECURITY.md`, `LICENSE`, `CODEOWNERS`, pull-request template, pre-commit config.
- CI: coverage floor, dependency audit (`pip-audit`), secret scan (`gitleaks`).
- CD: blocking Trivy gate on CRITICAL vulnerabilities; CycloneDX SBOM attached to releases.
- `docs/PRODUCTION_PLAN.md`: plan to finish the project.

- API: token expiry (default 90 days), `afw token list` / `afw token revoke` with immediate
  effect, rate limiting and authentication-failure lockout, 64 KiB body cap, security
  headers (CSP, nosniff, frame denial, no-store), audit of feedback submissions.
- Tests: route-by-route authorization matrix and API hardening tests.
- Ansible: SSH hardening, bounded persistent journal, optional automatic security updates
  (off by default), extra systemd sandboxing for the controller.
- `docs/SECURITY_CHECKLIST.md`: Phase 3 security review with evidence and accepted risks.

- Operations: `/api/readyz` (including a data-disk space check), `/api/metrics`, request ids and structured request logs,
  assessment retention (90 days, keeps rows cited by policies or feedback) with incremental
  vacuum, `scripts/backup_controller.sh` and `scripts/restore_controller.sh`,
  `scripts/loadtest.py`, `docs/SLO.md`, `docs/runbooks/`.

### Changed
- `GET /api/health` returns only `{status, version}` without a viewer token. Detail
  (mode, backends, telemetry state) now needs a token. Docs and examples updated.
- GitHub Actions pinned to commit SHAs (Dependabot keeps them current).

### Fixed
- `POST /api/profiles/{unknown}/candidates` returned HTTP 500; unknown applications now give 404.
- `test_geoip_endpoints_lookup_preview_and_real_country_tables` failed once the fixed
  `2026-10` GeoIP release passed the 45-day staleness limit; it now uses the current month.
- Upgraded `opentelemetry-api` to remove CVE-2026-126360 (reported by `pip-audit`).

## [0.1.0] - 2026-11 (pre-release; not tagged)

Working end-to-end system on a real GNS3 lab: telemetry from WAF, application and IDS
sensors (mTLS); behavioural detection and evidence correlation; safety-validated,
verified enforcement on OPNsense and the WAF; operator dashboard and MCP interface;
governed online learning (shadow challenger, promotion gate, human promotion, probation
rollback); CI, CodeQL and container build/scan/publish.

Known gaps at this version are listed in `docs/PROJECT_STATUS.md` (no attack-side
evaluation yet).
