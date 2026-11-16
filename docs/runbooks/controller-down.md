# Controller down

**Notice:** `api /api/health` fails or times out; dashboard blank; `afw_ready` absent.

1. Is the VM up? `uv run afw lab status` (CTRL01 must be `started`; if not, `afw lab start`).
2. Is the service up? `ssh -F ~/.config/afw/ssh_config ctrl01 'systemctl status afw-controller --no-pager'`
   It restarts itself after a crash (`Restart=on-failure`, 5 s; measured ready in 9.3 s).
3. Why did it stop? `ssh ... ctrl01 'sudo journalctl -u afw-controller -n 80 --no-pager'`
   - `database is locked`/disk errors: `df -h /var/lib/afw`, then `database-maintenance.md`.
   - migration error after an upgrade: `upgrade-rollback.md` (roll back first, investigate after).
   - certificate error: `credential-rotation.md`.
4. Start it: `ssh ... ctrl01 'sudo systemctl restart afw-controller'`.

**Safety while it is down:** FW01 flushes dynamic blocks within about 120 s without
heartbeats (ADR-009), so a dead controller cannot leave a stale block in place. On restart
the reconciler restores owned policies from the database.

**Verify:** `api /api/readyz` is `{"ready": true}`; mode is what it was (`api /api/health`).
