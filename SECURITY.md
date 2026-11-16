# Security policy

## Supported versions

Only the latest release on `main` (see `CHANGELOG.md`) receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository.
Include what you found, how to reproduce it, and the affected version or commit.

You can expect an acknowledgement within 7 days and a fix or a documented mitigation
within 30 days for confirmed issues (this is a student project: best effort, no SLA).

## Scope

In scope: the controller API, the MCP server, token handling, policy validation and
enforcement logic, and the container image.

Out of scope: the lab's self-signed PKI and lab credentials (the lab is isolated by
design), and attacks that need an already-compromised controller host.

Known limitations are listed openly in `docs/SECURITY_AND_LIMITATIONS.md`.

## How we check

CI runs CodeQL, ruff security rules (`S`), a dependency audit (`pip-audit`), secret
scanning (`gitleaks`) and a Trivy image scan on every change. See `docs/CI_CD.md`.
