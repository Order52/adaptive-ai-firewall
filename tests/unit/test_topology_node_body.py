"""`_node_body`'s console override: `console: vnc` on a `kind: ubuntu` node switches
the GNS3 console type without touching the disk image (no desktop is baked in --
one must be installed live on the running guest for this to show anything)."""

from __future__ import annotations

from afw.lab.topology import _node_body

TOPO = {
    "images": {"ubuntu": "afw-ubuntu-24.04-golden.qcow2", "desktop": "afw-ubuntu-desktop.qcow2"}
}
SPEC = {
    "kind": "ubuntu",
    "ram": 2048,
    "cpus": 2,
    "zone": "USERS",
    "ip": "10.77.20.10/24",
    "gw": "10.77.20.1",
    "extra_ips": ["10.77.20.250/24"],
}


def test_plain_ubuntu_node_keeps_default_telnet_console(monkeypatch, tmp_path):
    monkeypatch.setattr("afw.lab.topology.IMAGES_DIR", tmp_path)
    monkeypatch.setattr("afw.lab.topology.build_seed", lambda *a, **k: None)
    body = _node_body("USR01", SPEC, TOPO, "ssh-ed25519 AAAA", print)
    assert body["properties"]["console_type"] == "telnet"
    assert body["properties"]["hda_disk_image"] == TOPO["images"]["ubuntu"]


def test_console_vnc_overrides_console_type_but_keeps_the_plain_ubuntu_image(monkeypatch, tmp_path):
    monkeypatch.setattr("afw.lab.topology.IMAGES_DIR", tmp_path)
    monkeypatch.setattr("afw.lab.topology.build_seed", lambda *a, **k: None)
    spec = {**SPEC, "console": "vnc"}
    body = _node_body("USR01", spec, TOPO, "ssh-ed25519 AAAA", print)
    assert body["properties"]["console_type"] == "vnc"
    # Unlike `kind: desktop`, this does not swap to the baked desktop image.
    assert body["properties"]["hda_disk_image"] == TOPO["images"]["ubuntu"]
    assert body["properties"]["ram"] == 2048
    assert body["properties"]["cpus"] == 2


def test_desktop_kind_still_uses_its_own_baked_image_and_vnc(monkeypatch, tmp_path):
    monkeypatch.setattr("afw.lab.topology.IMAGES_DIR", tmp_path)
    monkeypatch.setattr("afw.lab.topology.build_seed", lambda *a, **k: None)
    spec = {**SPEC, "kind": "desktop"}
    body = _node_body("DESK01", spec, TOPO, "ssh-ed25519 AAAA", print)
    assert body["properties"]["console_type"] == "vnc"
    assert body["properties"]["hda_disk_image"] == TOPO["images"]["desktop"]
