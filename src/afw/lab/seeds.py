"""Per-node cloud-init NoCloud seed ISOs (identity + static addressing only).

Role configuration happens later over SSH; seeds stay minimal so a node can be
re-created from the golden image at any time.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml


def user_data(hostname: str, ssh_pubkey: str) -> str:
    doc: dict[str, Any] = {
        "hostname": hostname,
        "fqdn": f"{hostname.lower()}.lab.afw",
        "manage_etc_hosts": True,
        "ssh_pwauth": False,
        "users": [
            {
                "name": "afw",
                "groups": ["sudo", "adm"],
                "shell": "/bin/bash",
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "lock_passwd": True,
                "ssh_authorized_keys": [ssh_pubkey],
            }
        ],
        "timezone": "UTC",
    }
    return "#cloud-config\n" + yaml.safe_dump(doc, sort_keys=False)


def network_config(ip: str, gw: str, extra_ips: list[str]) -> str:
    doc = {
        "version": 2,
        "ethernets": {
            "lab0": {
                # No set-name: renaming races networkd on first boot (observed).
                "match": {"driver": "virtio_net"},
                "dhcp4": False,
                "dhcp6": False,
                "accept-ra": False,
                "addresses": [ip, *extra_ips],
                "routes": [{"to": "default", "via": gw}],
            }
        },
    }
    return yaml.safe_dump(doc, sort_keys=False)


def build_seed(
    out: Path, hostname: str, ip: str, gw: str, extra_ips: list[str], ssh_pubkey: str
) -> Path:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "user-data").write_text(user_data(hostname, ssh_pubkey))
        (tmp / "meta-data").write_text(
            f"instance-id: afw-{hostname.lower()}-1\nlocal-hostname: {hostname.lower()}\n"
        )
        (tmp / "network-config").write_text(network_config(ip, gw, extra_ips))
        subprocess.run(  # noqa: S603 - fixed binary, generated file paths
            [
                "/usr/bin/cloud-localds",
                "--network-config",
                str(tmp / "network-config"),
                str(out),
                str(tmp / "user-data"),
                str(tmp / "meta-data"),
            ],
            check=True,
        )
    return out
