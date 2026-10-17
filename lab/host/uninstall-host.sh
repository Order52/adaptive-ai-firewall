#!/usr/bin/env bash
# Reverse lab/host/bootstrap-host.sh. Leaves packages installed unless PURGE=1.
# Never deletes GNS3 projects or images under the lab user's home directory.
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo bash $0" >&2; exit 1; }

systemctl disable --now gns3server.service afw-mgmt-tap.service 2>/dev/null || true
rm -f /etc/systemd/system/gns3server.service /etc/systemd/system/afw-mgmt-tap.service
rm -f /usr/local/sbin/afw-mgmt-tap /etc/sudoers.d/afw-lab
systemctl daemon-reload

if [[ "${PURGE:-0}" == "1" ]]; then
  apt-mark unhold gns3-server
  apt-get purge -y gns3-server ubridge vpcs libvirt-daemon-system
  add-apt-repository -y --remove ppa:gns3/ppa
fi
echo "Host lab integration removed."
