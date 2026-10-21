#!/usr/bin/env bash
# Bake the shared golden Ubuntu 24.04 image for all Linux lab guests.
# Runs QEMU/KVM directly with user-mode networking (Internet only during the bake),
# installs every runtime the lab needs, pre-pulls the pinned WAF image, then
# resets cloud-init so each GNS3 node gets its identity from its own seed ISO.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DL="${DL:-$HOME/afw-lab/downloads}"
OUT="${OUT:-$HOME/GNS3/images/QEMU}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BASE="$DL/ubuntu-24.04-minimal-cloudimg-amd64.img"
GOLD="$OUT/afw-ubuntu-24.04-golden.qcow2"
WAF_IMAGE="owasp/modsecurity-crs@sha256:c739cfcb17028bbe604af1a632174cfdd78e7782f8e5f6407bbc8a6524e66335"
export PATH="$HOME/.local/bin:$PATH"

cd "$ROOT"
uv export --no-dev --no-hashes --no-emit-project --format requirements-txt -q > "$WORK/requirements.txt"
uv build --wheel -q -o "$WORK/dist"
WHEEL="$(ls "$WORK"/dist/*.whl)"

mkdir -p "$OUT"
qemu-img convert -O qcow2 "$BASE" "$WORK/gold.qcow2"
qemu-img resize -q "$WORK/gold.qcow2" 12G

b64() { base64 -w0 "$1"; }
cat > "$WORK/user-data" <<UD
#cloud-config
hostname: afw-golden
users:
  - name: afw
    groups: [sudo, adm]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys: ["$(cat "$HOME/.config/afw/lab_ed25519.pub")"]
package_update: true
packages: [python3-venv, rsyslog, docker.io, nftables, chrony, curl, jq, ca-certificates,
           tcpdump, iproute2, iputils-ping, netcat-openbsd, openssh-server, qemu-guest-agent, logrotate]
write_files:
  - path: /opt/afw/dist/requirements.txt
    encoding: b64
    content: $(b64 "$WORK/requirements.txt")
  - path: /opt/afw/dist/$(basename "$WHEEL")
    encoding: b64
    content: $(b64 "$WHEEL")
runcmd:
  - [bash, -c, "python3 -m venv /opt/afw/venv && /opt/afw/venv/bin/pip install -q -r /opt/afw/dist/requirements.txt && /opt/afw/venv/bin/pip install -q --no-deps /opt/afw/dist/*.whl"]
  - [bash, -c, "systemctl enable --now docker && docker pull $WAF_IMAGE && docker tag $WAF_IMAGE afw/waf:4.25.2-lts"]
  - [bash, -c, "docker pull postgres:16-alpine && docker tag postgres:16-alpine afw/postgres:16"]
  - [bash, -c, "mkdir -p /var/log/afw /etc/afw && systemctl disable --now docker.socket docker || true"]
  - [bash, -c, "echo 'net.ipv6.conf.all.disable_ipv6=1' > /etc/sysctl.d/90-afw.conf"]
  - [bash, -c, "/opt/afw/venv/bin/python -c 'import afw, sklearn, river, fastapi, psycopg, psycopg_pool; print(\"AFW_BAKE_OK\", afw.__version__)' > /dev/ttyS0"]
  - [bash, -c, "cloud-init clean --logs --machine-id && apt-get clean && fstrim -av || true"]
  - [poweroff]
UD
printf 'instance-id: afw-golden-bake\nlocal-hostname: afw-golden\n' > "$WORK/meta-data"
cloud-localds "$WORK/seed.iso" "$WORK/user-data" "$WORK/meta-data"

echo "[bake] booting (this takes several minutes)"
timeout 1800 qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 3072 -nographic \
  -drive file="$WORK/gold.qcow2",if=virtio,discard=unmap \
  -drive file="$WORK/seed.iso",if=virtio,media=cdrom \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -serial mon:stdio | tee "$WORK/console.log" | grep --line-buffered -E 'AFW_BAKE_OK|Cloud-init.*finished|rror' || true

grep -q AFW_BAKE_OK "$WORK/console.log" || { echo "[bake] FAILED — see console log"; cp "$WORK/console.log" "$OUT/bake-failed.log"; exit 1; }
qemu-img convert -O qcow2 -c "$WORK/gold.qcow2" "$GOLD.tmp" && mv "$GOLD.tmp" "$GOLD"
sha256sum "$GOLD" | tee "$GOLD.sha256"
echo "[bake] golden image: $GOLD"
