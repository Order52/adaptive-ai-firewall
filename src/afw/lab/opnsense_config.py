"""Transform the factory OPNsense 26.7 ``config.xml`` into the FW01 lab config.

Works on the config dumped from the running image so image-specific defaults
(and their private keys) never enter Git. Element formats were taken from the
26.7 factory config and model sources (see docs/IMPLEMENTATION_STATUS.md).

Zone ↔ interface map (GNS3 adapter order):
  lan=vtnet0 MGMT · wan=vtnet1 maintenance uplink · opt1=vtnet2 ATTACK
  opt2=vtnet3 USERS · opt3=vtnet4 DMZ · opt4=vtnet5 APP · opt5=vtnet6 DB
"""

from __future__ import annotations

import base64
import copy
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

ZONES = {  # key: (if, descr, address)
    "lan": ("vtnet0", "MGMT", "10.77.50.1"),
    "opt1": ("vtnet2", "ATTACK", "10.77.10.1"),
    "opt2": ("vtnet3", "USERS", "10.77.20.1"),
    "opt3": ("vtnet4", "DMZ", "10.77.30.1"),
    "opt4": ("vtnet5", "APP", "10.77.40.1"),
    "opt5": ("vtnet6", "DB", "10.77.60.1"),
}
CLIENT_ZONES = ("opt1", "opt2")
WAF = "10.77.30.10"
APP = "10.77.40.10"
DB = "10.77.60.10"
CTRL = "10.77.50.10"


@dataclass
class FwParams:
    root_hash: str  # sha512-crypt
    controller_key: str
    controller_secret_hash: str
    provisioner_key: str
    provisioner_secret_hash: str
    cert_pem: str
    key_pem: str
    hostname: str = "FW01"
    domain: str = "lab.afw"
    extra_rules: list[dict[str, str]] = field(default_factory=list)


def _set(parent: ET.Element, tag: str, text: str | None) -> ET.Element:
    e = parent.find(tag)
    if e is None:
        e = ET.SubElement(parent, tag)
    e.text = text
    return e


def _drop(parent: ET.Element, *tags: str) -> None:
    for t in tags:
        for e in parent.findall(t):
            parent.remove(e)


def _interfaces(root: ET.Element) -> None:
    ifs = root.find("interfaces")
    assert ifs is not None
    wan = ifs.find("wan")
    assert wan is not None
    _drop(wan, "blockpriv", "ipaddrv6", "dhcp6-ia-pd-len")  # uplink is libvirt NAT (RFC1918)
    _set(wan, "descr", "MAINT")
    lan = ifs.find("lan")
    assert lan is not None
    _drop(lan, "ipaddrv6", "subnetv6", "track6-interface", "track6-prefix-id")
    for key, (dev, descr, addr) in ZONES.items():
        e = ifs.find(key)
        if e is None:
            e = ET.SubElement(ifs, key)
        for tag, val in (
            ("enable", "1"),
            ("if", dev),
            ("descr", descr),
            ("ipaddr", addr),
            ("subnet", "24"),
            ("spoofmac", ""),
            ("blockbogons", "1"),
        ):
            _set(e, tag, val)


def _rule(template: ET.Element, seq: int, **fields: str) -> ET.Element:
    r = copy.deepcopy(template)
    r.set("uuid", str(uuid.uuid4()))
    base = {
        "enabled": "1",
        "sequence": str(seq),
        "action": "pass",
        "quick": "1",
        "interface": "",
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "any",
        "source_net": "any",
        "source_port": "",
        "destination_net": "any",
        "destination_port": "",
        "log": "0",
        "description": "",
    }
    for k, v in (base | fields).items():
        _set(r, k, v)
    return r


def lab_rules(template: ET.Element) -> list[ET.Element]:
    rules: list[ET.Element] = []
    seq = 100

    def add(**f: str) -> None:
        nonlocal seq
        rules.append(_rule(template, seq, **f))
        seq += 10

    for z in CLIENT_ZONES:
        add(
            interface=z,
            action="block",
            source_net="AFW_BLOCK_WEB",
            log="1",
            description=f"AFW: adaptive block ({ZONES[z][1]})",
        )
        add(
            interface=z,
            protocol="TCP",
            source_net=z,
            destination_net=WAF,
            destination_port="443",
            description=f"AFW: {ZONES[z][1]} to WAF HTTPS",
        )
    for z in ("opt1", "opt2", "opt3", "opt4", "opt5"):
        add(
            interface=z,
            protocol="UDP",
            source_net=z,
            destination_net="(self)",
            destination_port="123",
            description=f"AFW: {ZONES[z][1]} NTP to FW",
        )
        add(
            interface=z,
            protocol="ICMP",
            source_net=z,
            destination_net="(self)",
            description=f"AFW: {ZONES[z][1]} ping FW",
        )
    add(
        interface="opt3",
        protocol="TCP",
        source_net=WAF,
        destination_net=APP,
        destination_port="8000",
        description="AFW: WAF to APP (only path to the app)",
    )
    add(
        interface="opt4",
        protocol="TCP",
        source_net=APP,
        destination_net=DB,
        destination_port="5432",
        description="AFW: APP to DB (only path to the database tier)",
    )
    for src, z in ((WAF, "opt3"), (APP, "opt4")):
        add(
            interface=z,
            protocol="TCP",
            source_net=src,
            destination_net=CTRL,
            destination_port="5514",
            description=f"AFW: {ZONES[z][1]} telemetry to CTRL01",
        )
    return rules


def _filter(root: ET.Element) -> None:
    rules = root.find("OPNsense/Firewall/Filter/rules")
    assert rules is not None
    template = None
    for r in list(rules):
        if r.findtext("ipprotocol") == "inet6":
            rules.remove(r)  # lab is IPv4-only
        elif r.findtext("interface") == "lan" and template is None:
            template = r
            _set(r, "description", "MGMT: allow management zone (incl. host TAP)")
    assert template is not None, "factory LAN rule not found"
    for r in lab_rules(template):
        rules.append(r)


def _alias(name: str, typ: str, content: str, descr: str) -> ET.Element:
    a = ET.Element("alias", {"uuid": str(uuid.uuid4())})
    for tag, val in (
        ("enabled", "1"),
        ("name", name),
        ("type", typ),
        ("proto", ""),
        ("interface", ""),
        ("counters", "1"),
        ("updatefreq", ""),
        ("content", content),
        ("password", ""),
        ("username", ""),
        ("authtype", ""),
        ("categories", ""),
        ("description", descr),
    ):
        _set(a, tag, val)
    return a


def _aliases(root: ET.Element) -> None:
    aliases = root.find("OPNsense/Firewall/Alias/aliases")
    assert aliases is not None
    for e in list(aliases):
        if e.findtext("name") in {"AFW_BLOCK_WEB", "AFW_HEARTBEAT"}:
            aliases.remove(e)
    aliases.append(
        _alias(
            "AFW_BLOCK_WEB",
            "external",
            "",
            "Managed by the AFW controller (alias_util); flushed by watchdog",
        )
    )
    aliases.append(
        _alias(
            "AFW_HEARTBEAT", "external", "", "AFW controller liveness; refreshed every reconcile"
        )
    )


def _users(root: ET.Element, p: FwParams) -> None:
    system = root.find("system")
    assert system is not None
    rootuser = next(u for u in system.findall("user") if u.findtext("name") == "root")
    _set(rootuser, "password", p.root_hash)
    _set(rootuser, "apikeys", f"{p.provisioner_key}|{p.provisioner_secret_hash}")
    for u in system.findall("user"):
        if u.findtext("name") == "afw-controller":
            system.remove(u)
    ctl = copy.deepcopy(rootuser)
    ctl.set("uuid", str(uuid.uuid4()))
    for tag, val in (
        ("uid", "2000"),
        ("name", "afw-controller"),
        ("scope", "user"),
        ("password", "*"),
        ("descr", "AFW controller (least privilege API)"),
        ("shell", "/usr/sbin/nologin"),
        ("priv", "page-diagnostics-tables,page-diagnostics-showstates"),
        ("apikeys", f"{p.controller_key}|{p.controller_secret_hash}"),
    ):
        _set(ctl, tag, val)
    system.insert(list(system).index(rootuser) + 1, ctl)


def _system(root: ET.Element, p: FwParams) -> None:
    _drop(root, "trigger_initial_wizard")
    system = root.find("system")
    assert system is not None
    _set(system, "hostname", p.hostname)
    _set(system, "domain", p.domain)
    refid = "afwlabfw01"
    webgui = system.find("webgui")
    assert webgui is not None
    _set(webgui, "ssl-certref", refid)
    _drop(root, "cert")
    cert = ET.SubElement(root, "cert")
    _set(cert, "refid", refid)
    _set(cert, "descr", "AFW lab CA: FW01 web GUI/API")
    _set(cert, "crt", base64.b64encode(p.cert_pem.encode()).decode())
    _set(cert, "prv", base64.b64encode(p.key_pem.encode()).decode())
    ids = root.find("OPNsense/Interfaces/settings")
    if ids is not None:
        _set(ids, "disableipv6", "1")


def transform(factory_xml: bytes, p: FwParams) -> bytes:
    root = ET.fromstring(factory_xml)  # noqa: S314 - our own dumped config
    _system(root, p)
    _interfaces(root)
    _filter(root)
    _aliases(root)
    _users(root, p)
    ET.indent(root, "  ")
    return b'<?xml version="1.0"?>\n' + bytes(ET.tostring(root, encoding="utf-8"))
