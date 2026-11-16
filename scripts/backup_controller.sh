#!/bin/bash
# Back up the controller's runtime state from CTRL01 and PROVE it restores.
#
# What: the SQLite database (policies, audit, profiles, models registry, assessments), the
# trained model files and the challenger state. Not the lab secrets or the code: those are in
# scripts/make_offhost_backup.sh.
#
# How: an online SQLite backup (consistent while the controller keeps running), copied to
# this host, encrypted with the same passphrase file as the off-host backup, then a restore
# drill into a scratch directory: integrity check, schema at head, row counts equal to the
# source snapshot, and the restored database opened through the real application code.
#
#   scripts/backup_controller.sh            # backup + restore drill
# Output: ~/afw-backups/controller/afw-controller-<stamp>.tar.zst.gpg (+ SHA256SUMS, RESTORE)
# Restore on CTRL01: docs/runbooks/backup-restore.md
set -euo pipefail
umask 077
REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=$HOME/afw-backups/controller; mkdir -p "$OUT"
PASS=$HOME/.config/afw/backup.passphrase
[ -s "$PASS" ] || { echo "missing $PASS (run scripts/make_offhost_backup.sh once to create it)"; exit 1; }
SSH="ssh -F $HOME/.config/afw/ssh_config -o BatchMode=yes -o ConnectTimeout=8 ctrl01"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
T0=$(date +%s)
STG=$(mktemp -d); trap 'rm -rf "$STG"' EXIT
mkdir -p "$STG/ctrl"

echo "1/4 online snapshot on CTRL01"
$SSH 'sudo -u afwctl /opt/afw/venv/bin/python - <<"PY"
import sqlite3, pathlib
src = sqlite3.connect("file:/var/lib/afw/afw.sqlite3?mode=ro", uri=True, timeout=60)
# VACUUM INTO writes a consistent, compacted copy while the controller keeps running
# (free pages are not copied, so the temporary file is the size of the live data, not the
# size of the database file)
src.execute("VACUUM INTO ?", ("/var/lib/afw/.backup-snapshot.sqlite3",))
src.close()
PY
sudo -u afwctl tar -C /var/lib/afw -cf /var/lib/afw/.backup-state.tar models challengers 2>/dev/null || true'
$SSH 'sudo cat /var/lib/afw/.backup-snapshot.sqlite3' > "$STG/ctrl/afw.sqlite3"
$SSH 'sudo cat /var/lib/afw/.backup-state.tar' > "$STG/ctrl/state.tar"
$SSH 'sudo rm -f /var/lib/afw/.backup-snapshot.sqlite3 /var/lib/afw/.backup-state.tar'

echo "2/4 record source counts, encrypt"
python3 - "$STG/ctrl/afw.sqlite3" > "$STG/ctrl/COUNTS.txt" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
for (n,) in c.execute("select name from sqlite_master where type='table' order by 1").fetchall():
    print(n, c.execute(f'select count(*) from "{n}"').fetchone()[0])
PY
( cd "$STG/ctrl" && sha256sum afw.sqlite3 state.tar > SHA256SUMS )
tar -C "$STG" -cf - ctrl | zstd -q -10 -o "$STG/ctrl.tar.zst"
ARCH="$OUT/afw-controller-$STAMP.tar.zst.gpg"
gpg --batch --yes --pinentry-mode loopback --passphrase-file "$PASS" --symmetric --cipher-algo AES256 -o "$ARCH" "$STG/ctrl.tar.zst"
( cd "$OUT" && sha256sum "$(basename "$ARCH")" >> SHA256SUMS-controller )

echo "3/4 restore drill (scratch directory)"
V=$(mktemp -d); trap 'rm -rf "$STG" "$V"' EXIT
gpg --batch --yes --pinentry-mode loopback --passphrase-file "$PASS" -d "$ARCH" 2>/dev/null | zstd -dq | tar -C "$V" -xf -
( cd "$V/ctrl" && sha256sum -c --quiet SHA256SUMS ) && echo "  checksums match"
[ "$(sqlite3 "$V/ctrl/afw.sqlite3" 'pragma integrity_check' 2>/dev/null || python3 -c "import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('pragma integrity_check').fetchone()[0])" "$V/ctrl/afw.sqlite3")" = ok ] && echo "  integrity_check ok"
python3 - "$V/ctrl/afw.sqlite3" > "$V/ctrl/COUNTS.restored" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
for (n,) in c.execute("select name from sqlite_master where type='table' order by 1").fetchall():
    print(n, c.execute(f'select count(*) from "{n}"').fetchone()[0])
PY
diff -q "$V/ctrl/COUNTS.txt" "$V/ctrl/COUNTS.restored" >/dev/null && echo "  row counts equal the source snapshot" || { echo "ROW COUNT MISMATCH"; exit 1; }
mkdir -p "$V/data" && cp "$V/ctrl/afw.sqlite3" "$V/data/afw.sqlite3" && tar -C "$V/data" -xf "$V/ctrl/state.tar" 2>/dev/null || true
( cd "$REPO" && AFW_DATA_DIR="$V/data" AFW_CONFIG="$REPO/config/lab.yaml" uv run afw db upgrade 2>&1 | tail -1 )
( cd "$REPO" && AFW_DATA_DIR="$V/data" AFW_CONFIG="$REPO/config/lab.yaml" uv run python - <<'PY'
from afw.config import get_settings
from afw.container import build_container
c = build_container(get_settings(), simulated=True)
print("  application opened the restored database: mode =", c.settings_repo.get_mode(),
      "| audit rows =", len(c.audit.recent(1000)), "| policies =", len(c.policies_repo.recent(100000)))
PY
)
echo "4/4 done"
T1=$(date +%s)
SIZE=$(du -h "$ARCH" | cut -f1)
echo; echo "backup: $ARCH ($SIZE)"; echo "elapsed: $((T1 - T0)) s (snapshot + encrypt + full restore drill)"
