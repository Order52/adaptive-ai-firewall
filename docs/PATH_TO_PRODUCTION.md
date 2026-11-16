# Path to production

What this project is: a lab-scale research system with release-quality engineering
(`PRODUCTION_PLAN.md`, `SECURITY_CHECKLIST.md`, `SLO.md`). What it is not: a product ready to
protect a real network. This page lists, in priority order, what separates the two. None of it
is built here, deliberately; each item is a decision with a cost.

| # | Gap | Today | A production deployment needs | Effort |
|---|---|---|---|---|
| 1 | **Detection is unproven under attack** | Benign-side FPR measured; attack recall unmeasured (team runs pending) | Attack-recall gate passed on labelled runs, then monitor mode, then `assisted`, then limited `auto`; never `auto` first | Weeks (needs data) |
| 2 | **False positives on new benign users** | Trusted v2 models restrict 13 of 16 unseen users in replay | Training on far more varied users, per-segment profiles, human approval for all restrictions until measured | Weeks |
| 3 | **Single points of failure** | One controller, one firewall; dead controller fails safe (blocks flush in about 120 s) | Active/passive controller pair with shared database (PostgreSQL is already supported), redundant firewall (CARP) | Weeks |
| 4 | **Identity and access** | Static bearer tokens with expiry; roles viewer/operator/admin | SSO (OIDC), per-user accounts, MFA for admin, short-lived credentials, secrets in a vault | Days to weeks |
| 5 | **PKI** | Self-signed lab CA; leaf certificates issued once, rotated by hand | Enterprise or ACME-issued certificates, automated renewal, CRL/OCSP, CA in an HSM | Days |
| 6 | **Audit integrity** | Append-only in code; not tamper-proof against database access | Hash-chained or WORM audit export to a SIEM, separate retention | Days |
| 7 | **Visibility** | Only the ATTACK and USERS segments cross Suricata; TLS opaque beyond SNI | Sensors on every segment, TLS inspection or endpoint telemetry, flow export | Weeks |
| 8 | **Scale** | Ingestion ceiling about 2 500 requests/s (join cap), single process, SQLite | Partitioned ingestion, PostgreSQL/Timescale, horizontal workers; load tests at the target rate | Weeks |
| 9 | **Monitoring stack** | Metrics and readiness endpoints exist; no scraper or alerting deployed | Prometheus + Alertmanager + dashboards, paging, SLO burn alerts | Days |
| 10 | **Backups** | Verified local encrypted backups and restore script | Automated schedule, off-site copy, quarterly restore test, documented RPO/RTO | Days |
| 11 | **Hosts** | SSH password login on by request; automatic updates off for evidence runs | Key-only SSH, automatic security updates with a patch window, CIS benchmark scan, EDR | Days |
| 12 | **Supply chain** | CI gates, SBOM, pinned Actions | Signed images and provenance (cosign/SLSA 3), reproducible builds, private registry | Days |
| 13 | **Compliance** | Not assessed | Map controls to the target framework (ISO 27001, NIST CSF), data-protection review of logged source addresses and usernames (hashed in the app log) | Weeks |
| 14 | **Online learning cannot clear its own false positives** | Policed sources are tainted by design | An operator false-positive path that governs taint release (`PROJECT_STATUS.md` section 4) | Days |

**Sequencing.** Items 1 and 2 decide whether the product works at all; do them first and keep
the system in monitor mode until they pass. Items 3-6 make it trustworthy to operate; 7-10 make
it scale and stay up; 11-13 are the standard hardening and assurance that any security product
needs before a customer relies on it.

**Honest framing for the report.** The engineering here (verified enforcement, governed
learning, tested authorization, measured capacity, rehearsed recovery) is what a production
system is built on. The claim this project can make is a well-engineered, evaluated prototype
with its limits stated, not a deployable product.
