#!/bin/bash
# Give the lab VMs a username/password login (owner's request: easy access via the GNS3
# console), in addition to the SSH key. Idempotent; safe to re-run (e.g. after a rebuild,
# because src/afw/lab/seeds.py bakes the VMs with the password LOCKED).
#
#   user:      afw   (passwordless sudo, unchanged)
#   password:  the first line of ~/.config/afw/vm.password  (NOT stored in Git)
#
# What it does on each Linux VM:
#   1. sets the afw password            -> GNS3 console / telnet / VNC login works
#   2. enables SSH password login       -> /etc/ssh/sshd_config.d/00-afw-password.conf
#                                          (00- sorts before the cloud-image "no" setting;
#                                           sshd uses the first value it reads)
# To undo:  scripts/set_vm_passwords.sh --lock
# FW01 (OPNsense) is NOT touched: it already has root + a password, and the provisioning
# tooling reads that password from ~/.config/afw/opnsense/root.password.
set -euo pipefail
PWFILE=$HOME/.config/afw/vm.password
SSH="ssh -F $HOME/.config/afw/ssh_config -o BatchMode=yes -o ConnectTimeout=8"
VMS="ctrl01 waf01 app01 db01 desk01 usr01 atk01"
mode=set; [ "${1:-}" = "--lock" ] && mode=lock
[ -r "$PWFILE" ] || { echo "missing $PWFILE"; exit 1; }
PW=$(head -n1 "$PWFILE")
for h in $VMS; do
  if [ $mode = set ]; then
    # password via stdin so it never appears in a process list
    printf 'afw:%s\n' "$PW" | $SSH $h 'sudo chpasswd' &&
    $SSH $h 'printf "PasswordAuthentication yes\nKbdInteractiveAuthentication no\n" | sudo tee /etc/ssh/sshd_config.d/00-afw-password.conf >/dev/null && sudo sshd -t && sudo systemctl reload ssh'
    echo "$h: password set, SSH password login enabled"
  else
    $SSH $h 'sudo passwd -l afw >/dev/null; sudo rm -f /etc/ssh/sshd_config.d/00-afw-password.conf; sudo sshd -t && sudo systemctl reload ssh'
    echo "$h: locked again, SSH key-only"
  fi
done
