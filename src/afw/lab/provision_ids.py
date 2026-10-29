"""Configure Suricata (IDS mode) and syslog forwarding on FW01 via its API.

Uses the root *provisioner* key (host-side only, ``~/.config/afw/opnsense``).
The controller's own key cannot change these settings (ADR-017).

- IDS (pcap, detection only) on the client-zone interfaces (opt1 ATTACK,
  opt2 USERS). HOME_NET is the protected side (DMZ, APP, MGMT) so client zones
  are EXTERNAL_NET and inbound signatures apply to client → WAF traffic.
- ET Open categories relevant to an HTTPS-fronted web service.
- EVE alerts → local syslog (program ``suricata``) → CTRL01. Default: mutually
  authenticated TLS to 5514 with the ``fw01-telemetry.lab.afw`` client certificate (role
  ``ids``, P5); ``plaintext=True`` restores the earlier TCP feed to 5515. Only Suricata
  and pf's ``filterlog`` are forwarded; the controller keeps pf blocks of protected
  sources only (lateral-movement evidence, shadow).
- RELP pass rules (ADR-038) for a FW01 built before RELP: WAF01 (DMZ) and APP01 (APP)
  to CTRL01:5516, as automation rules. New builds carry the same rules in config.xml.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

SECRETS = Path("~/.config/afw").expanduser()
RULESETS = [
    "emerging-scan.rules",
    "emerging-exploit.rules",
    "emerging-web_server.rules",
    "emerging-web_specific_apps.rules",
    "emerging-sql.rules",
    "emerging-dos.rules",
    "emerging-attack_response.rules",
]
CA_DESCR = "AFW lab CA"
CLIENT_DESCR = "AFW FW01 telemetry client (mTLS to CTRL01)"
DESTINATION = {
    "enabled": "1",
    "transport": "tcp4",
    "program": "suricata,filterlog",  # filterlog: pf blocks (SENSOR_EXPANSION_DECISION §3)
    "level": "info,notice,warn,err,crit,alert,emerg",
    "facility": "",
    "hostname": "10.77.50.10",
    "certificate": "",
    "port": "5515",
    "rfc5424": "0",
    "description": "AFW controller telemetry (Suricata EVE alerts)",
}


def client(base_url: str = "https://10.77.50.1") -> httpx.Client:
    key = (SECRETS / "opnsense" / "provisioner.key").read_text().strip()
    secret = (SECRETS / "opnsense" / "provisioner.secret").read_text().strip()
    return httpx.Client(
        base_url=base_url + "/api",
        auth=(key, secret),
        verify=str(SECRETS / "pki" / "lab-ca.pem"),
        timeout=60,
    )


def _post(c: httpx.Client, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    r = c.post(path, json=body or {})
    r.raise_for_status()
    data: dict[str, Any] = r.json()
    if data.get("result") == "failed" or data.get("validations"):
        raise RuntimeError(f"{path}: {data}")
    return data


def _rows(c: httpx.Client, path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = c.post(path, json={"rowCount": -1}).json().get("rows", [])
    return rows


def ensure_trust(c: httpx.Client, log: Callable[[str], None] = print) -> str:
    """Import the lab CA and FW01's telemetry client certificate into the FW01 trust
    store (once, matched by description); return the client certificate's refid."""
    pki = SECRETS / "pki"
    if not any(r.get("descr") == CA_DESCR for r in _rows(c, "/trust/ca/search")):
        _post(
            c,
            "/trust/ca/add",
            {
                "ca": {
                    "action": "existing",
                    "descr": CA_DESCR,
                    "crt_payload": (pki / "lab-ca.pem").read_text(),
                }
            },
        )
        log("lab CA imported into the FW01 trust store")
    found = [r for r in _rows(c, "/trust/cert/search") if r.get("descr") == CLIENT_DESCR]
    if not found:
        _post(
            c,
            "/trust/cert/add",
            {
                "cert": {
                    "action": "import",
                    "descr": CLIENT_DESCR,
                    "crt_payload": (pki / "FW01-telemetry.pem").read_text(),
                    "prv_payload": (pki / "FW01-telemetry.key").read_text(),
                }
            },
        )
        found = [r for r in _rows(c, "/trust/cert/search") if r.get("descr") == CLIENT_DESCR]
        log("FW01 telemetry client certificate imported")
    return str(found[0]["refid"])


def destination(c: httpx.Client, plaintext: bool, log: Callable[[str], None] = print) -> None:
    dest = dict(DESTINATION)
    if not plaintext:
        dest |= {"transport": "tls4", "port": "5514", "certificate": ensure_trust(c, log)}
    dests = c.get("/syslog/settings/get").json()["syslog"]["destinations"]["destination"]
    existing = [
        uuid
        for uuid, d in (dests or {}).items()
        if d.get("description") == DESTINATION["description"]
    ]
    if existing:
        _post(c, f"/syslog/settings/set_destination/{existing[0]}", {"destination": dest})
    else:
        _post(c, "/syslog/settings/add_destination", {"destination": dest})
    _post(c, "/syslog/service/reconfigure")
    log(
        f"syslog destination CTRL01:{dest['port']} ({dest['transport']}, {dest['program']}) applied"
    )


RELP_RULES = [
    {
        "enabled": "1",
        "quick": "1",
        "action": "pass",
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "TCP",
        "sequence": str(seq),
        "interface": iface,
        "source_net": src,
        "destination_net": "10.77.50.10",
        "destination_port": "5516",
        "description": f"AFW: {zone} RELP telemetry to CTRL01 (ADR-038)",
    }
    for seq, iface, src, zone in (
        (3, "opt3", "10.77.30.10", "DMZ"),
        (4, "opt4", "10.77.40.10", "APP"),
    )
]


def relp_rules(c: httpx.Client, log: Callable[[str], None] = print) -> None:
    from afw.lab.provision_geo import _ok, ensure_rule

    for rule in RELP_RULES:
        log(f"rule '{rule['description']}': {ensure_rule(c, rule)}")
    _ok(c.post("/firewall/filter/apply").json(), "filter apply")
    log("filter applied")


def provision(c: httpx.Client, log: Callable[[str], None] = print, plaintext: bool = False) -> None:
    _post(
        c,
        "/ids/settings/set",
        {
            "ids": {
                "general": {
                    "enabled": "1",
                    "mode": "pcap",
                    "promisc": "0",
                    "interfaces": "opt1,opt2",
                    "homenet": "10.77.30.0/24,10.77.40.0/24,10.77.50.0/24",
                    "syslog": "0",
                    "syslog_eve": "1",
                    "LogPayload": "0",
                }
            }
        },
    )
    log("IDS general settings saved")
    _post(c, f"/ids/settings/toggle_ruleset/{','.join(RULESETS)}/1")
    log(f"enabled {len(RULESETS)} ET Open categories")

    destination(c, plaintext, log)

    _post(c, "/ids/service/update_rules")
    log("rule download started")
    for _ in range(60):  # download + install runs in the background on the firewall
        time.sleep(5)
        rows = c.post("/ids/settings/search_installed_rules", json={"rowCount": 1}).json()
        if int(rows.get("total", 0)) > 0:
            break
    _post(c, "/ids/service/reconfigure")
    st = c.get("/ids/service/status").json()
    log(f"suricata status: {st.get('status')}; installed rules: {rows.get('total')}")
