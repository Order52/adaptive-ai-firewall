# Backup and restore

| What | Script | Time | Contains |
|---|---|---|---|
| Code, datasets, frozen models, secrets | `scripts/make_offhost_backup.sh` | 22 s | git bundle, dataset archive, `~/.config/afw` (keys, PKI, tokens), encrypted (AES-256) |
| Controller runtime data | `scripts/backup_controller.sh` | 14 s | SQLite database (policies, audit, profiles, assessments), model files, challenger state |

Both encrypt with `~/.config/afw/backup.passphrase` and **prove the restore** (decrypt,
checksums, integrity check, row counts, the application opens the database). Archives land
in `~/afw-backups/`: **that is the same machine.** Copy the `.gpg` files and `SHA256SUMS`
somewhere else, and keep the passphrase somewhere different from the archives.

Recommended schedule: controller backup daily (cron on the lab host), full backup after every
change to secrets or at least weekly. Targets: RPO 24 h, RTO under 30 min.

**Restore the controller** (after data loss or corruption on CTRL01)
```bash
scripts/restore_controller.sh ~/afw-backups/controller/afw-controller-<stamp>.tar.zst.gpg
api /api/readyz                                                   # {"ready": true}
ssh -F ~/.config/afw/ssh_config ctrl01 'sudo rm /var/lib/afw/pre-restore-<stamp>.sqlite3'   # when satisfied
```
The script verifies the archive, keeps the current database as `pre-restore-<stamp>.sqlite3`
(so the restore can be undone), removes the old `-wal`/`-shm` files before installing the
database, checks the installed file's checksum and integrity on CTRL01, and only then starts
the service. If any step fails it stops and leaves the service **stopped** with the reason.

Never copy a database over a running controller, and never leave an old `-wal` file beside a
different database file: SQLite applies it to the wrong database and corrupts it (this
happened to the first, hand-typed rehearsal of this runbook on 2026-11-16; recovered in
minutes by deleting the stale WAL and verifying the file against the backup checksum).

Restore everything else: `make_offhost_backup.sh` writes `RESTORE-<stamp>.txt` beside the archive.
Datasets under `/var/lib/afw/datasets` are archived by `scripts/archive_datasets.sh`.
