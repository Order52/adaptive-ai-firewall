"""Configure Suricata (IDS mode) and syslog forwarding on FW01 via its API.

Uses the root *provisioner* key (host-side only, ``~/.config/afw/opnsense``).
The controller's own key cannot change these settings (ADR-017).

- IDS (pcap, detection only) on the client-zone interfaces (opt1 ATTACK,
  opt2 USERS). HOME_NET is the protected side (DMZ, APP, MGMT) so client zones
  are EXTERNAL_NET and inbound signatures apply to client → WAF traffic.
- ET Open categories relevant to an HTTPS-fronted web service.
- EVE alerts → local syslog (program ``suricata``) → TCP to CTRL01:5514.
  Only Suricata is forwarded.
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
DESTINATION = {
    "enabled": "1",
    "transport": "tcp4",
    "program": "suricata",
    "level": "info,notice,warn,err,crit,alert,emerg",
    "facility": "",
    "hostname": "10.77.50.10",
    "certificate": "",
    "port": "5514",
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


def provision(c: httpx.Client, log: Callable[[str], None] = print) -> None:
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

    dests = c.get("/syslog/settings/get").json()["syslog"]["destinations"]["destination"]
    existing = [
        uuid
        for uuid, d in (dests or {}).items()
        if d.get("description") == DESTINATION["description"]
    ]
    if existing:
        _post(c, f"/syslog/settings/set_destination/{existing[0]}", {"destination": DESTINATION})
    else:
        _post(c, "/syslog/settings/add_destination", {"destination": DESTINATION})
    _post(c, "/syslog/service/reconfigure")
    log("syslog destination CTRL01:5514 (suricata only) applied")

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
