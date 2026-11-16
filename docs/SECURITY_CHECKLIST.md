# Security review (Phase 3)

Reviewed 2026-11-16 against an OWASP ASVS L2 subset (API) and CIS Ubuntu 24.04 L1 key items
(hosts). Each row says what was checked, the result, and the evidence. Known gaps and
accepted risks are in `SECURITY_AND_LIMITATIONS.md`.

**Result: 21 PASS, 3 ACCEPTED RISK, 0 open findings.** Items marked *new* were fixed in this
review.

## API (CTRL01, `src/afw/api/`)

| # | Check | Result | Evidence |
|---|---|---|---|
| 3.1a | Tokens stored only as SHA-256 hashes, compared in constant time | PASS | `api/auth.py`; `tests/unit/test_auth_tokens.py` |
| 3.1b | Token expiry (default 90 days, `--days 0` = never) | PASS, *new* | `afw token issue --days`; expired token returns 401 (test) |
| 3.1c | Token revocation and listing, effective immediately (file is re-read on change) | PASS, *new* | `afw token list/revoke`; `test_expired_token_is_refused_and_revoked_token_stops_working` |
| 3.1d | Token file written atomically with mode 0600; world-readable file warns | PASS, *new* | `write_entries`; `test_token_file_is_written_0600_and_roundtrips` |
| 3.1e | The five tokens already in the lab (`admin`, `operator`, `dashboard`, `mcp`, `fw01-geo`) were issued by `afw lab` before expiry existed and **do not expire** | ACCEPTED RISK | Rotating them would break saved dashboard/MCP tokens mid-project. Before any real deployment: `afw token issue <name> --role <r> --days 90` for each, update the token files, redeploy |
| 3.2 | Every route has a reviewed minimum role; below-minimum gets 403, anonymous 401 | PASS | `ROLE_TABLE` in `tests/integration/test_api_security.py` (fails if a route is added without a decision) |
| 3.3a | Strict request models; `app_id` pattern; list lengths bounded | PASS, *new* | `test_input_bounds_reject_hostile_values` |
| 3.3b | Request body cap 64 KiB (413), chunked uploads refused (411) | PASS, *new* | `api/hardening.py`; `test_oversized_body_is_413_and_never_parsed` |
| 3.3c | No route returns 500 on empty or unknown input (unknown `app_id` was a 500) | PASS, *new* | `test_no_route_crashes_on_empty_or_unknown_input` |
| 3.4a | Rate limits per client: 3000 req/min general, 60/min for mutations | PASS, *new* | `test_general_rate_limit_returns_429_with_retry_after` |
| 3.4b | Lockout after 10 failed authentications per minute (429 + `Retry-After`) | PASS, *new* | `test_token_guessing_is_locked_out` |
| 3.5 | Every mutation is audited with actor, action, subject (feedback was missing) | PASS, *new* | `test_feedback_is_audited`; policy/mode/strategy/profile/challenger paths already audited |
| 3.6a | TLS 1.2 and 1.3 only; 1.0 and 1.1 refused by the live server | PASS | probed 2026-11-16 against `10.77.50.10:8080` |
| 3.6b | Certificate rotation procedure written and rehearsed | PASS | rehearsed on CTRL01 2026-11-16 (see below) |
| 3.7a | No secrets in tracked files or git history (pattern search) | PASS | `git grep` for key/token/password patterns: no hits. CI also runs `gitleaks` |
| 3.7b | No tokens or credentials in controller logs | PASS | 0 matches in the last day of `journalctl -u afw-controller` |
| 3.8 | Browser hardening: CSP (scripts from self only), nosniff, frame denial, no-referrer, no-store on API | PASS, *new* | live dashboard renders with 0 console errors, 0 CSP violations |
| 3.9 | `/api/health` leaks nothing to anonymous callers | PASS, *new* | anonymous gets `{status, version}` only; detail needs a viewer token |

## Hosts (CTRL01, WAF01, APP01, DB01, USR01, ATK01)

| # | Check | Result | Evidence |
|---|---|---|---|
| H1 | SSH: no root login, `MaxAuthTries 3`, 30 s grace time, no X11, idle timeout | PASS, *new* | `sshd -T` on all six VMs; Ansible `common` role |
| H2 | SSH password login | ACCEPTED RISK | Enabled at the owner's request for GNS3 console and SSH convenience (`scripts/set_vm_passwords.sh`). Lab-only; hosts are reachable only from the MGMT network behind FW01, and tooling uses keys. For a production deployment run `scripts/set_vm_passwords.sh --lock` |
| H3 | Host firewall default-deny inbound, SSH only from MGMT | PASS | `nftables.conf.j2`; `afw lab verify` 41/41 on 2026-11-16 |
| H4 | Controller sandboxing (`systemd-analyze security`) | PASS, *new* | exposure **8.3 EXPOSED to 2.9 OK**; no capabilities, no devices, restricted kernel and namespaces |
| H5 | Automatic security updates | ACCEPTED RISK | Implemented but **off by default** (`auto_security_updates: true` to enable; security pocket only, no auto-reboot). Evidence runs need a frozen system. Patch in a planned window: `apt upgrade`, then `afw lab verify` |
| H6 | Time sync and log retention | PASS, *new* | chrony from FW01 (existing); journal persistent, capped at 200 MB / 30 days; app and heartbeat logs rotate (existing logrotate) |

## Certificate rotation (rehearsed 2026-11-16)

Leaf certificates are issued once and are **not** renewed automatically. CTRL01's leaf
now expires 2027-12-18; the lab CA expires 2029-01-19. Calendar a rotation at least 30 days before.

```bash
cd ~/.config/afw/pki
mkdir -m 700 ../pki-backup-$(date +%Y%m%d) && cp -p CTRL01.pem CTRL01.key ../pki-backup-*/
rm -f CTRL01.pem CTRL01.key CTRL01.csr CTRL01.ext        # a new key and cert are issued
cd ~/uot/ai-adaptive-firewall && uv run afw lab deploy --limit ctrl01
curl -s --cacert ~/.config/afw/pki/lab-ca.pem https://10.77.50.10:8080/api/health   # ok
```

Clients trust the CA, not the leaf, so nothing else changes. Rehearsal result: API verified
against the lab CA with the same SANs, controller back with `telemetry_degraded: false` within
about a minute. Rollback: copy the backup files back and redeploy.

## Token operations

```bash
afw token issue alice --role operator --days 90   # prints the secret once
afw token list                                    # names, roles, expiry (never secrets)
afw token revoke alice                            # effective immediately
```

Rotate operator and admin tokens every 90 days. On CTRL01 the token file is deployed from
`~/.config/afw/api/api_tokens.yaml` by `afw lab deploy`.

## Not covered (stated plainly)

- `gitleaks` over the full git history has not run yet; it runs in CI (`docs/CI_CD.md`). As a substitute check on 2026-11-16, `detect-secrets` scanned every tracked text file (including `artifacts/`): no real secrets. The 77 findings are dataset/model SHA-256 hashes in evidence JSON, a fake request id in a test, and code that compares a password field. History before HEAD was pattern-searched only.
- No external penetration test; no fuzzing beyond the route-level tests above.
- The audit table is application-append-only (the code exposes `record` and `recent`
  only) but not tamper-proof against someone with database access.
- Rate limits are per source address; behind the SSH tunnel all dashboard users share one.
