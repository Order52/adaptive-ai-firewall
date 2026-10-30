"""Apply ``lab/gns3/topology.yaml`` to the GNS3 server idempotently."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from afw.lab.gns3 import Gns3Client, Gns3Error
from afw.lab.seeds import build_seed

IMAGES_DIR = Path("~/GNS3/images/QEMU").expanduser()


def load_topology(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text())  # type: ignore[no-any-return]


def _qemu_props(spec: dict[str, Any], image: str, cdrom: str = "") -> dict[str, Any]:
    return {
        "hda_disk_image": image,
        "hda_disk_interface": "virtio",
        "cdrom_image": cdrom,
        "linked_clone": True,
        "ram": spec["ram"],
        "cpus": spec["cpus"],
        "adapters": spec.get("adapters", 1),
        "adapter_type": "virtio-net-pci",
        "console_type": "telnet",
        "on_close": "shutdown_signal",
        "boot_priority": "c",
        "options": "-cpu host",
        "platform": "x86_64",
    }


def _node_body(
    name: str, spec: dict[str, Any], topo: dict[str, Any], pubkey: str, log: Callable[[str], None]
) -> dict[str, Any]:
    kind = spec["kind"]
    body: dict[str, Any] = {
        "name": name,
        "compute_id": "local",
        "x": spec.get("x", 0),
        "y": spec.get("y", 0),
    }
    if kind == "opnsense":
        body |= {
            "node_type": "qemu",
            "symbol": ":/symbols/firewall.svg",
            "properties": _qemu_props(spec, topo["images"]["opnsense"]),
        }
    elif kind == "ubuntu":
        iso = f"afw-seed-{name.lower()}.iso"
        build_seed(
            IMAGES_DIR / iso, name, spec["ip"], spec["gw"], spec.get("extra_ips", []), pubkey
        )
        log(f"seed {iso}")
        body |= {
            "node_type": "qemu",
            "properties": _qemu_props(spec, topo["images"]["ubuntu"], iso),
        }
    elif kind == "desktop":
        iso = f"afw-seed-{name.lower()}.iso"
        build_seed(
            IMAGES_DIR / iso, name, spec["ip"], spec["gw"], spec.get("extra_ips", []), pubkey
        )
        log(f"seed {iso}")
        props = _qemu_props(spec, topo["images"]["desktop"], iso)
        props["console_type"] = "vnc"  # graphical XFCE desktop, viewed via GNS3 VNC
        body |= {
            "node_type": "qemu",
            "symbol": ":/symbols/computer.svg",
            "properties": props,
        }
    elif kind == "cloud":
        tap = spec["tap"]
        body |= {
            "node_type": "cloud",
            "properties": {
                "ports_mapping": [{"interface": tap, "name": tap, "port_number": 0, "type": "tap"}]
            },
        }
    elif kind == "nat":
        body |= {"node_type": "nat"}
    else:
        raise Gns3Error(f"unknown node kind {kind}")
    return body


def apply(
    client: Gns3Client, topo: dict[str, Any], pubkey: str, log: Callable[[str], None] = print
) -> str:
    for img in topo["images"].values():
        if not (IMAGES_DIR / img).exists():
            raise Gns3Error(f"missing image {IMAGES_DIR / img}")
    project = client.ensure_project(topo["project"])
    pid: str = project["project_id"]
    existing = client.node_by_name(pid)

    for name, pos in topo["switches"].items():
        if name not in existing:
            client.create_node(
                pid,
                {
                    "name": name,
                    "node_type": "ethernet_switch",
                    "compute_id": "local",
                    "x": pos["x"],
                    "y": pos["y"],
                },
            )
            log(f"created {name}")
    for name, spec in topo["nodes"].items():
        if name not in existing:
            client.create_node(pid, _node_body(name, spec, topo, pubkey, log))
            log(f"created {name}")

    by_name = client.node_by_name(pid)
    used = {
        (n["node_id"], n["adapter_number"], n["port_number"])
        for link in client.links(pid)
        for n in link["nodes"]
    }
    for a, b in topo["links"]:
        ends = [(by_name[n]["node_id"], ad, po) for n, ad, po in (a, b)]
        if all(e in used for e in ends):
            continue
        if any(e in used for e in ends):
            raise Gns3Error(f"port conflict for link {a} <-> {b}; fix the project manually")
        client.create_link(pid, ends)
        log(f"linked {a[0]} <-> {b[0]}")
    return pid
