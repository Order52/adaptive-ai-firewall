# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [SemVer](https://semver.org/). Detailed milestone history is in
`docs/engineering/AUTONOMOUS_PROGRESS.md`; current status is in `docs/PROJECT_STATUS.md`.

## [Unreleased]

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
