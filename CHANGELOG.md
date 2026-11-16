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

### Changed
- GitHub Actions pinned to commit SHAs (Dependabot keeps them current).

### Fixed
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
