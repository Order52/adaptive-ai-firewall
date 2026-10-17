#!/usr/bin/env bash
# AI-Adaptive-Firewall — one-time ROOT host preparation for the GNS3 lab.
#
# What this does (and nothing else):
#   1. Adds the official GNS3 PPA and installs a pinned GNS3 2.2 server, ubridge,
#      QEMU/KVM, qemu-utils and cloud-image-utils. Holds gns3-server at the pin.
#   2. Installs libvirt's daemon only for the documented GNS3 NAT node (virbr0,
#      192.168.122.0/24). It is used solely for the optional maintenance uplink.
#   3. Grants the lab user the kvm/ubridge/libvirt groups and verifies ubridge caps.
#   4. Installs a systemd oneshot that creates a host-only TAP (afw-mgmt0,
#      10.77.50.254/24) for the GNS3 Cloud node on the MGMT zone, and a route for
#      the lab supernet via FW01 (10.77.50.1). It never touches existing NICs,
#      the default route, Tailscale, or ufw policy.
#   5. Installs a gns3server systemd service running as the lab user, bound to
#      127.0.0.1 (config file is written by the unprivileged setup step).
#
# Re-running is safe (idempotent). Undo: lab/host/uninstall-host.sh
set -euo pipefail

LAB_USER="${LAB_USER:-gns3}"
GNS3_VERSION="${GNS3_VERSION:-2.2.61~noble1}"
TAP_DEV="afw-mgmt0"
TAP_ADDR="10.77.50.254/24"
LAB_SUPERNET="10.77.0.0/16"
FW_MGMT_IP="10.77.50.1"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi
id "${LAB_USER}" >/dev/null

log() { printf '\n[afw-bootstrap] %s\n' "$*"; }

log "Checking for subnet conflicts with ${LAB_SUPERNET}"
if ip -4 route show | grep -v "${TAP_DEV}" | grep -qE '^10\.77\.'; then
  echo "A non-lab route in 10.77.0.0/16 already exists; aborting." >&2
  ip -4 route show | grep -E '^10\.77\.' >&2
  exit 1
fi

log "Installing packages"
export DEBIAN_FRONTEND=noninteractive
if ! grep -rqs 'gns3/ppa' /etc/apt/sources.list.d/; then
  apt-get install -y software-properties-common
  add-apt-repository -y ppa:gns3/ppa
fi
apt-get update
apt-get install -y --no-install-recommends \
  "gns3-server=${GNS3_VERSION}" ubridge vpcs dynamips \
  qemu-system-x86 qemu-utils cloud-image-utils \
  libvirt-daemon-system \
  dnsmasq-base telnet socat jq sqlite3 iproute2
apt-mark hold gns3-server

log "Groups and ubridge capabilities"
for g in kvm ubridge libvirt; do
  getent group "$g" >/dev/null && usermod -aG "$g" "${LAB_USER}"
done
UBRIDGE_BIN="$(command -v ubridge)"
setcap cap_net_admin,cap_net_raw=ep "${UBRIDGE_BIN}"
getcap "${UBRIDGE_BIN}"

log "Host-only management TAP service"
install -m 0755 /dev/stdin /usr/local/sbin/afw-mgmt-tap <<EOF
#!/usr/bin/env bash
# Create/remove the host-only TAP used by the GNS3 Cloud node on the MGMT zone.
set -euo pipefail
case "\${1:-}" in
  up)
    ip link show ${TAP_DEV} >/dev/null 2>&1 || ip tuntap add dev ${TAP_DEV} mode tap user ${LAB_USER}
    ip addr replace ${TAP_ADDR} dev ${TAP_DEV}
    ip link set ${TAP_DEV} up
    ip route replace ${LAB_SUPERNET} via ${FW_MGMT_IP} dev ${TAP_DEV} onlink
    sysctl -qw net.ipv6.conf.${TAP_DEV}.disable_ipv6=1
    ;;
  down)
    ip route del ${LAB_SUPERNET} dev ${TAP_DEV} 2>/dev/null || true
    ip link del ${TAP_DEV} 2>/dev/null || true
    ;;
  *) echo "usage: \$0 up|down" >&2; exit 2 ;;
esac
EOF

cat >/etc/systemd/system/afw-mgmt-tap.service <<EOF
[Unit]
Description=AI-Adaptive-Firewall host-only MGMT TAP (${TAP_DEV})
After=network-pre.target
Before=gns3server.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/afw-mgmt-tap up
ExecStop=/usr/local/sbin/afw-mgmt-tap down

[Install]
WantedBy=multi-user.target
EOF

log "GNS3 server service (runs as ${LAB_USER}, localhost only via its config)"
cat >/etc/systemd/system/gns3server.service <<EOF
[Unit]
Description=GNS3 server (AI-Adaptive-Firewall lab)
After=network-online.target afw-mgmt-tap.service libvirtd.service
Wants=network-online.target afw-mgmt-tap.service

[Service]
User=${LAB_USER}
Group=${LAB_USER}
SupplementaryGroups=kvm ubridge libvirt
ExecStart=/usr/bin/gns3server
Restart=on-failure
RestartSec=5
LimitNOFILE=16384

[Install]
WantedBy=multi-user.target
EOF

# Allow the lab user to restart only these two units without a password.
cat >/etc/sudoers.d/afw-lab <<EOF
${LAB_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl restart gns3server.service, /usr/bin/systemctl start gns3server.service, /usr/bin/systemctl stop gns3server.service, /usr/bin/systemctl restart afw-mgmt-tap.service
EOF
chmod 0440 /etc/sudoers.d/afw-lab
visudo -cf /etc/sudoers.d/afw-lab

systemctl daemon-reload
systemctl enable --now libvirtd.service
virsh net-autostart default >/dev/null 2>&1 || true
virsh net-start default >/dev/null 2>&1 || true
systemctl enable --now afw-mgmt-tap.service
systemctl enable gns3server.service
systemctl restart gns3server.service

log "Verification"
gns3server --version
qemu-system-x86_64 --version | head -n1
ip -br addr show "${TAP_DEV}"
ip route show "${LAB_SUPERNET}"
ip -br addr show virbr0 || true
systemctl --no-pager --lines=0 status gns3server.service || true
log "Done. Log out/in (or reboot) so ${LAB_USER} picks up the new groups."
