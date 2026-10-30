#!/bin/bash
# Archive CTRL01's captured datasets with per-file SHA-256 sums (N7).
# Usage: scripts/archive_datasets.sh [dest_dir]   (default ~/afw-datasets-archive)
# Read-only on CTRL01. The archive stays on this host; only the SHA256SUMS file is
# meant for Git (datasets contain lab addresses and synthetic persona accounts only).
set -euo pipefail
DEST=${1:-$HOME/afw-datasets-archive}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SSH="ssh -F $HOME/.config/afw/ssh_config ctrl01"
mkdir -p "$DEST"
$SSH 'sudo tar -C /var/lib/afw -czf - datasets' > "$DEST/datasets-$STAMP.tar.gz"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
tar -C "$tmp" -xzf "$DEST/datasets-$STAMP.tar.gz"
(cd "$tmp" && find datasets -type f | sort | xargs sha256sum) > "$DEST/SHA256SUMS-$STAMP"
sha256sum "$DEST/datasets-$STAMP.tar.gz" | sed "s#$DEST/##" >> "$DEST/SHA256SUMS-$STAMP"
echo "$DEST/datasets-$STAMP.tar.gz"
echo "$DEST/SHA256SUMS-$STAMP ($(wc -l < "$DEST/SHA256SUMS-$STAMP") entries)"
