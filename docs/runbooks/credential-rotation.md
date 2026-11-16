# Credential rotation

**API certificate** (CTRL01 leaf expires 2027-12-18; alert at 30 days with
`afw_tls_certificate_days_left`; readiness fails inside 30 days). Rehearsed 2026-11-16.
```bash
cd ~/.config/afw/pki && mkdir -m 700 ../pki-backup-$(date +%Y%m%d) && cp -p CTRL01.pem CTRL01.key ../pki-backup-*/
rm -f CTRL01.pem CTRL01.key CTRL01.csr CTRL01.ext            # a new key and certificate are issued
cd ~/uot/ai-adaptive-firewall && uv run afw lab deploy --limit ctrl01
api /api/readyz                                                  # ready; certificate_valid ok
```
Clients trust the CA, not the leaf; nothing else changes. The lab CA itself expires
2029-01-19. Replacing the CA means re-issuing every leaf and client certificate and
redeploying all hosts: schedule it, do not improvise it.

**API tokens** (90-day default for new tokens; the five original lab tokens do not expire).
```bash
uv run afw token list
AFW_API_TOKENS_FILE=~/.config/afw/api/api_tokens.yaml uv run afw token issue <name> --role <role> --days 90
AFW_API_TOKENS_FILE=~/.config/afw/api/api_tokens.yaml uv run afw token revoke <old-name>
uv run afw lab deploy --limit ctrl01          # copies the token file; revocation is live at once
```
Update every consumer of the token (`~/.config/afw/api/dashboard.token`, the MCP token path,
FW01's pull credential) before revoking the old one. Never paste a token into a chat or ticket.
