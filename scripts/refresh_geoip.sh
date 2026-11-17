#!/usr/bin/env bash
# Refresh the DB-IP Country Lite database on CTRL01 (monthly; see docs/runbooks/database-maintenance.md).
# Usage: scripts/refresh_geoip.sh [YYYY-MM]    (default: this month, falling back to last month)
# Run from the workstation that has ~/.config/afw/ssh_config. Idempotent; only touches
# <data_dir>/geo and restarts afw-controller (about 10 s without telemetry processing).
set -euo pipefail

SSH_CFG="${AFW_SSH_CONFIG:-$HOME/.config/afw/ssh_config}"
HOST="${AFW_CTRL_HOST:-ctrl01}"
ssh_ctrl() { ssh -F "$SSH_CFG" "$HOST" "$@"; }

release="${1:-$(date -u +%Y-%m)}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() {
  curl -fsSL --max-time 180 -o "$work/db.csv.gz" \
    "https://download.db-ip.com/free/dbip-country-lite-$1.csv.gz"
}
if ! fetch "$release"; then
  if [[ $# -eq 0 ]]; then
    release="$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)"
    echo "this month's release is not published yet; trying $release" >&2
    fetch "$release"
  else
    echo "could not download release $release" >&2; exit 1
  fi
fi

# sanity: valid gzip, plausible size, first line looks like "start,end,CC"
rows="$(zcat "$work/db.csv.gz" | wc -l)"
[[ "$rows" -gt 100000 ]] || { echo "refusing: only $rows rows" >&2; exit 1; }
first="$(zcat "$work/db.csv.gz" | sed -n 1p)"  # not head -1: it would SIGPIPE zcat under pipefail
[[ "$first" =~ ^[0-9a-fA-F:.]+,[0-9a-fA-F:.]+,[A-Z]{2}$ ]] \
  || { echo "refusing: unexpected CSV format: $first" >&2; exit 1; }

scp -q -F "$SSH_CFG" "$work/db.csv.gz" "$HOST:/tmp/dbip.csv.gz"
# run from the data dir: the afw settings loader reads ./.env and the ssh user's home is not readable by afwctl
ssh_ctrl "sudo -u afwctl sh -c 'cd /var/lib/afw && AFW_CONFIG=/etc/afw/lab.yaml AFW_DATA_DIR=/var/lib/afw \
  /opt/afw/venv/bin/afw geoip install /tmp/dbip.csv.gz --release $release \
  --source https://download.db-ip.com/free/dbip-country-lite-$release.csv.gz'; sudo rm -f /tmp/dbip.csv.gz"
ssh_ctrl 'sudo systemctl restart afw-controller'
sleep 12
ssh_ctrl 'systemctl is-active afw-controller'
echo "GeoIP $release installed ($rows ranges)."
