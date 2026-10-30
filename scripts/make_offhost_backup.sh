#!/bin/bash
# Build ENCRYPTED recovery archives that are safe to copy off this host, and PROVE they restore.
# Nothing is uploaded, pushed or published: moving the files off-host is a separate step that
# needs the owner's authorisation (see the printed instructions).
#
#   afw-recovery-code-data-<stamp>.tar.zst.gpg   git bundle (full history) + dataset archive +
#                                                frozen models + manifest
#   afw-recovery-secrets-<stamp>.tar.gz.gpg      ~/.config/afw (keys, tokens, passwords, PKI)
#
# Encryption: GnuPG symmetric AES-256, passphrase in ~/.config/afw/backup.passphrase (mode 600,
# generated on first use). KEEP THE PASSPHRASE SEPARATE from the archives when you move them:
# an archive next to its passphrase is not protected.
# Excluded on purpose: ~/afw-external-datasets (large, re-downloadable; provenance + sha256 are
# in artifacts/evidence/offline-cic-*/provenance.txt).
set -euo pipefail
umask 077
REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=$HOME/afw-backups/offhost; mkdir -p "$OUT"
PASS=$HOME/.config/afw/backup.passphrase
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
[ -s "$PASS" ] || { head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c 40 > "$PASS"; chmod 600 "$PASS"; echo "generated passphrase: $PASS"; }
enc() { gpg --batch --yes --pinentry-mode loopback --passphrase-file "$PASS" --symmetric --cipher-algo AES256 -o "$2" "$1"; }
dec() { gpg --batch --yes --pinentry-mode loopback --passphrase-file "$PASS" -d "$1"; }
STG=$(mktemp -d); trap 'rm -rf "$STG"' EXIT

# ---- 1. code + data (no secrets) ----
mkdir -p "$STG/code-data"
( cd "$REPO" && git bundle create "$STG/code-data/repo.bundle" --all >/dev/null 2>&1 )
LATEST_DS=$(ls -t "$HOME"/afw-datasets-archive/datasets-*.tar.gz | head -1)
cp "$LATEST_DS" "$STG/code-data/"; cp "$(ls -t "$HOME"/afw-datasets-archive/SHA256SUMS-* | head -1)" "$STG/code-data/"
mkdir -p "$STG/code-data/frozen-models"; cp "$HOME"/.local/share/afw-frozen/*.pkl "$STG/code-data/frozen-models/" 2>/dev/null || true
( cd "$REPO" && { echo "commit: $(git rev-parse HEAD)"; echo "branch: $(git rev-parse --abbrev-ref HEAD)"; echo "ahead of origin: $(git rev-list --count origin/engineering-directive..HEAD 2>/dev/null || echo ?)"; echo "created: $STAMP"; } > "$STG/code-data/MANIFEST.txt" )
( cd "$STG/code-data" && sha256sum repo.bundle datasets-*.tar.gz SHA256SUMS-* frozen-models/*.pkl >> MANIFEST.txt )
tar -C "$STG" -cf - code-data | zstd -q -19 -o "$STG/code-data.tar.zst"
enc "$STG/code-data.tar.zst" "$OUT/afw-recovery-code-data-$STAMP.tar.zst.gpg"

# ---- 2. secrets (separate archive) ----
tar -C "$HOME/.config" --exclude='afw/dist' --exclude='afw/backup.passphrase' -czf "$STG/secrets.tar.gz" afw
enc "$STG/secrets.tar.gz" "$OUT/afw-recovery-secrets-$STAMP.tar.gz.gpg"

# ---- 3. restore proof: decrypt, unpack, verify ----
V=$(mktemp -d); trap 'rm -rf "$STG" "$V"' EXIT
dec "$OUT/afw-recovery-code-data-$STAMP.tar.zst.gpg" | zstd -dq | tar -C "$V" -xf -
git bundle verify "$V/code-data/repo.bundle" >/dev/null 2>&1 && echo "restore check: git bundle complete" || { echo "BUNDLE VERIFY FAILED"; exit 1; }
( cd "$V/code-data" && grep -E "datasets-.*\.tar\.gz$" SHA256SUMS-* >/dev/null 2>&1; sha256sum -c --quiet <(grep -E '^[0-9a-f]{64}  (datasets-.*\.tar\.gz|repo\.bundle)$' MANIFEST.txt) ) && echo "restore check: dataset archive + bundle sha256 match the manifest" || { echo "CHECKSUM VERIFY FAILED"; exit 1; }
dec "$OUT/afw-recovery-secrets-$STAMP.tar.gz.gpg" | tar -tzf - | grep -q 'afw/lab_ed25519$' && echo "restore check: secrets archive decrypts and contains the lab SSH key" || { echo "SECRETS VERIFY FAILED"; exit 1; }
( cd "$OUT" && sha256sum afw-recovery-*"$STAMP"*.gpg | tee "SHA256SUMS-offhost-$STAMP" >/dev/null )
cat > "$OUT/RESTORE-$STAMP.txt" <<TXT
Restore (needs the passphrase file, kept separately):
  gpg --batch --pinentry-mode loopback --passphrase-file <passphrase> -d afw-recovery-code-data-$STAMP.tar.zst.gpg | zstd -d | tar -xf -
  git clone code-data/repo.bundle ai-adaptive-firewall
  gpg ... -d afw-recovery-secrets-$STAMP.tar.gz.gpg | tar -xzf - -C ~/.config     # restores ~/.config/afw
Verify the copies first:  sha256sum -c SHA256SUMS-offhost-$STAMP
TXT
echo; ls -lh "$OUT"/*"$STAMP"* | awk '{print $5"  "$9}'
echo; echo "NOT moved off-host. When authorised: copy the two .gpg files + SHA256SUMS to the destination, and store the passphrase ($PASS) somewhere DIFFERENT."
