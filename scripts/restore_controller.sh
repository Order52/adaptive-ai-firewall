#!/bin/bash
# Restore the controller's runtime data on CTRL01 from a scripts/backup_controller.sh archive.
#
#   scripts/restore_controller.sh ~/afw-backups/controller/afw-controller-<stamp>.tar.zst.gpg
#
# Safe by construction:
#   * verifies the archive checksums BEFORE touching CTRL01;
#   * keeps the current database as /var/lib/afw/pre-restore-<stamp>.sqlite3 so the restore can
#     itself be undone (delete it once you are satisfied: it is as large as the database);
#   * removes the old -wal/-shm files BEFORE installing the new database (a stale WAL next to a
#     different database file corrupts it);
#   * streams files over ssh (no temp files with the wrong owner or mode);
#   * checks the installed file's sha256 and integrity ON CTRL01, and only then starts the service;
#   * any failure leaves the service STOPPED and says so (a stopped controller is safe: FW01
#     flushes dynamic blocks without heartbeats, and the pre-restore copy is untouched).
set -euo pipefail
umask 077
ARCH=${1:?usage: restore_controller.sh <afw-controller-*.tar.zst.gpg>}
PASS=$HOME/.config/afw/backup.passphrase
SSH="ssh -F $HOME/.config/afw/ssh_config -o BatchMode=yes -o ConnectTimeout=8 ctrl01"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
V=$(mktemp -d); trap 'rm -rf "$V"' EXIT

echo "1/6 decrypt and verify the archive"
gpg --batch --yes --pinentry-mode loopback --passphrase-file "$PASS" -d "$ARCH" 2>/dev/null | zstd -dq | tar -C "$V" -xf -
( cd "$V/ctrl" && sha256sum -c --quiet SHA256SUMS ) && echo "  checksums match"
WANT=$(awk '$2=="afw.sqlite3"{print $1}' "$V/ctrl/SHA256SUMS")

fail() { echo; echo "RESTORE FAILED at: $1"; echo "afw-controller is STOPPED. Current database kept as pre-restore-$STAMP.sqlite3 on CTRL01."; exit 1; }

echo "2/6 stop the controller and keep the current database"
$SSH 'sudo systemctl stop afw-controller'
$SSH "sudo cp -p /var/lib/afw/afw.sqlite3 /var/lib/afw/pre-restore-$STAMP.sqlite3" || fail "pre-restore copy (disk full?)"

echo "3/6 remove the old WAL files, install the database"
$SSH 'sudo rm -f /var/lib/afw/afw.sqlite3-wal /var/lib/afw/afw.sqlite3-shm' || fail "WAL removal"
$SSH 'sudo install -o afwctl -g afwctl -m 0644 /dev/stdin /var/lib/afw/afw.sqlite3' < "$V/ctrl/afw.sqlite3" || fail "database install"

echo "4/6 restore model and challenger state"
$SSH 'sudo -u afwctl tar -C /var/lib/afw -xf -' < "$V/ctrl/state.tar" || fail "state restore"

echo "5/6 verify on CTRL01 before starting"
GOT=$($SSH 'sudo sha256sum /var/lib/afw/afw.sqlite3' | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || fail "sha256 mismatch ($GOT)"
IC=$($SSH "sudo -u afwctl /opt/afw/venv/bin/python -c \"import sqlite3;print(sqlite3.connect('file:/var/lib/afw/afw.sqlite3?mode=ro&immutable=1',uri=True).execute('pragma integrity_check').fetchone()[0])\"")
[ "$IC" = ok ] || fail "integrity_check: $IC"
echo "  sha256 equals the backup; integrity_check ok"

echo "6/6 start the controller"
$SSH 'sudo systemctl start afw-controller' || fail "service start"
echo "done. Verify: GET /api/readyz. Remove the safety copy when satisfied:"
echo "  ssh ctrl01 'sudo rm /var/lib/afw/pre-restore-$STAMP.sqlite3'"
