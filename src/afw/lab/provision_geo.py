"""Install real-country enforcement on FW01 (ADR-036), idempotently.

API part (root *provisioner* key, host-side only, ADR-017):

* two external aliases (pf tables) ``AFW_GEO_IN`` and ``AFW_GEO_OUT``, empty;
* two filter rules referencing them, both ``quick`` and logged:
  - inbound: block packets entering any interface from ``AFW_GEO_IN``;
  - outbound: reject connections from the client zones (ATTACK ``opt1``, USERS
    ``opt2``) to ``AFW_GEO_OUT``. Server zones and MGMT are deliberately not covered,
    so a country policy can never cut deployment or management egress.

Serial-console part (root shell, as for the watchdog): the controller CA, FW01's pull
token (role ``firewall``) and the watchdog that pulls the published lists while the
controller's heartbeat is fresh and flushes every AFW table when it is not.

Empty tables match nothing, so installing the rules changes no traffic.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from afw.config import GeoEnforcementConfig

SECRETS = Path("~/.config/afw").expanduser()
ALL_INTERFACES = "lan,wan,opt1,opt2,opt3,opt4,opt5"
CLIENT_INTERFACES = "opt1,opt2"
INBOUND_DESCR = "AFW: real-country inbound block (ADR-036)"
OUTBOUND_DESCR = "AFW: real-country outbound reject, client zones (ADR-036)"


def _ok(res: dict[str, Any], what: str) -> None:
    result = str(res.get("result", "")).strip().lower()
    status = str(res.get("status", "")).strip().lower()  # filter/apply answers "OK\n\n"
    if result not in ("saved", "ok") and status not in ("ok", "done"):
        raise RuntimeError(f"{what}: {res}")


def ensure_alias(c: httpx.Client, name: str, descr: str) -> str:
    rows = c.post(
        "/firewall/alias/search_item", json={"current": 1, "rowCount": 500, "searchPhrase": name}
    ).json()["rows"]
    found = next((r for r in rows if r.get("name") == name), None)
    if found is not None:
        return "exists"
    res = c.post(
        "/firewall/alias/add_item",
        json={
            "alias": {
                "enabled": "1",
                "name": name,
                "type": "external",
                "content": "",
                "description": descr,
            }
        },
    ).json()
    _ok(res, f"alias {name}")
    return "created"


def rules(g: GeoEnforcementConfig) -> list[dict[str, str]]:
    common = {"enabled": "1", "quick": "1", "direction": "in", "ipprotocol": "inet"}
    common |= {"protocol": "any", "log": "1"}
    return [
        common
        | {
            "sequence": "1",
            "action": "block",
            "interface": ALL_INTERFACES,
            "source_net": g.inbound_alias,
            "destination_net": "any",
            "description": INBOUND_DESCR,
        },
        common
        | {
            "sequence": "2",
            "action": "reject",
            "interface": CLIENT_INTERFACES,
            "source_net": "any",
            "destination_net": g.outbound_alias,
            "description": OUTBOUND_DESCR,
        },
    ]


def ensure_rule(c: httpx.Client, rule: dict[str, str]) -> str:
    rows = c.post(
        "/firewall/filter/search_rule",
        json={"current": 1, "rowCount": 500, "searchPhrase": rule["description"]},
    ).json()["rows"]
    found = next((r for r in rows if r.get("description") == rule["description"]), None)
    if found is None:
        _ok(c.post("/firewall/filter/add_rule", json={"rule": rule}).json(), "add rule")
        return "created"
    _ok(
        c.post(f"/firewall/filter/set_rule/{found['uuid']}", json={"rule": rule}).json(),
        "update rule",
    )
    return "updated"


def provision_api(
    c: httpx.Client, g: GeoEnforcementConfig, log: Callable[[str], None] = print
) -> None:
    for name, d in ((g.inbound_alias, "inbound"), (g.outbound_alias, "outbound")):
        log(f"alias {name}: {ensure_alias(c, name, f'AFW real-country {d} table (ADR-036)')}")
    _ok(c.post("/firewall/alias/reconfigure").json(), "alias reconfigure")
    for rule in rules(g):
        log(f"rule '{rule['description']}': {ensure_rule(c, rule)}")
    _ok(c.post("/firewall/filter/apply").json(), "filter apply")
    log("filter applied")


def provision_console(host: str, port: int, log: Callable[[str], None] = print) -> None:
    from afw.lab.console import SerialConsole
    from afw.lab.provision_fw import ASSETS, FwShell

    token = (SECRETS / "api" / "fw01-geo.token").read_bytes()
    ca = (SECRETS / "pki" / "lab-ca.pem").read_bytes()
    con = SerialConsole(host, port)
    try:
        sh = FwShell(con, log)
        sh.login()
        sh.run("mkdir -p /usr/local/etc/afw && chmod 0700 /usr/local/etc/afw")
        sh.write_file("/usr/local/etc/afw/lab-ca.pem", ca, "0644")
        sh.write_file("/usr/local/etc/afw/geo.token", token, "0600")
        sh.write_file(
            "/usr/local/sbin/afw-watchdog.sh", (ASSETS / "afw-watchdog.sh").read_bytes(), "0755"
        )
        log("FW01: CA, pull token and watchdog (with country-table sync) installed")
    finally:
        con.close()
