"""Acceptance tests against the running GNS3 lab (real OPNsense, WAF, app).

Skipped unless AFW_LAB=1. Effects are verified from the data plane with the
probe agents (called via CTRL01, the only allowed caller), never only from the
controller's own bookkeeping.

    AFW_LAB=1 uv run pytest tests/lab -v
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import httpx
import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AFW_LAB"), reason="needs the GNS3 lab")

HOME = Path("~/.config/afw").expanduser()
API = "http://10.77.50.10:8080"
ATTACK_SRC = "10.77.10.10"  # ATK01 primary address (not a protected probe address)
USER_SRC = "10.77.20.10"
LEGIT_PROBE = "10.77.20.250"
AGENT = {"10.77.10": "10.77.10.10", "10.77.20": "10.77.20.10"}
TERMINAL = {"enforced", "failed", "rejected", "unknown", "expired", "rolled_back"}


def api() -> httpx.Client:
    token = (HOME / "api" / "operator.token").read_text().strip()
    return httpx.Client(base_url=API, headers={"Authorization": f"Bearer {token}"}, timeout=30)


def probe(source: str) -> dict[str, object]:
    agent = AGENT[source.rsplit(".", 1)[0]]
    cmd = (
        'curl -s -m 10 -H "Authorization: Bearer $(sudo cat /etc/afw/secrets/probe.token)" '
        f"'http://{agent}:9180/v1/probe?source={source}'"
    )
    out = subprocess.run(
        ["ssh", "-F", str(HOME / "ssh_config"), "ctrl01", cmd],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout
    return json.loads(out)


def submit(c: httpx.Client, kind: str, ip: str, **extra: object) -> dict[str, object]:
    body = {
        "kind": kind,
        "target": {"type": "source", "source_ip": ip},
        "duration_s": 120,
        "reason": "lab acceptance test",
    } | extra
    r = c.post("/api/policies", json=body)
    r.raise_for_status()
    return r.json()


def wait_state(c: httpx.Client, pid: str, states: set[str], timeout: float = 30) -> dict:
    end = time.monotonic() + timeout
    while True:
        p = c.get(f"/api/policies/{pid}").json()
        if p["state"] in states or time.monotonic() > end:
            return p
        time.sleep(0.5)


def revoke(c: httpx.Client, pid: str) -> dict:
    c.post(f"/api/policies/{pid}/revoke", json={"reason": "lab acceptance cleanup"})
    return wait_state(c, pid, {"rolled_back", "expired"})


def test_baseline_reachability():
    assert probe(LEGIT_PROBE)["ok"] is True
    assert probe(ATTACK_SRC)["connected"] is True


def test_source_block_is_enforced_verified_and_reversible():
    with api() as c:
        t0 = time.monotonic()
        p = submit(c, "source_block", ATTACK_SRC)
        p = wait_state(c, p["policy_id"], TERMINAL)
        elapsed = time.monotonic() - t0
        try:
            assert p["state"] == "enforced", p["history"][-3:]
            print(f"\nSOURCE_BLOCK enforced in {elapsed:.2f}s")
            assert probe(ATTACK_SRC)["connected"] is False  # dropped at FW01
            assert probe(LEGIT_PROBE)["ok"] is True  # no collateral damage
            fw = next(
                b for b in c.get("/api/health").json()["backends"] if b["backend"] == "opnsense"
            )
            assert ATTACK_SRC in fw["blocked_sources"]  # read back from the device
            explain = c.get(f"/api/policies/{p['policy_id']}/explain").json()
            assert explain  # explanation built from recorded data
        finally:
            r = revoke(c, p["policy_id"])
        assert r["state"] in {"rolled_back", "expired"}
        assert probe(ATTACK_SRC)["connected"] is True


def test_waf_deny_returns_403_only_for_target():
    with api() as c:
        p = submit(c, "waf_deny", USER_SRC)
        p = wait_state(c, p["policy_id"], TERMINAL)
        try:
            assert p["state"] == "enforced", p["history"][-3:]
            denied = probe(USER_SRC)
            assert denied["connected"] is True and denied["status"] == 403
            assert probe(LEGIT_PROBE)["status"] == 200
        finally:
            revoke(c, p["policy_id"])
        assert probe(USER_SRC)["status"] == 200


@pytest.mark.parametrize("ip", [LEGIT_PROBE, "10.77.50.10", "10.77.30.10", "10.77.10.1"])
def test_protected_addresses_cannot_be_blocked(ip):
    with api() as c:
        r = c.post(
            "/api/policies",
            json={
                "kind": "source_block",
                "target": {"type": "source", "source_ip": ip},
                "duration_s": 60,
                "reason": "must be refused",
            },
        )
        assert r.status_code in (200, 422)
        if r.status_code == 200:
            assert r.json()["state"] == "rejected"
        fw = next(b for b in c.get("/api/health").json()["backends"] if b["backend"] == "opnsense")
        assert ip not in fw["blocked_sources"]


def test_ids_alert_reaches_controller():
    """One SYN to a DB port on the DMZ host (dropped by FW01) matches ET SCAN 2010937
    on Suricata (vtnet2, before pf); the alert must arrive at CTRL01 via syslog.

    After a controller restart FW01's syslog-ng reconnects only on its ~60 s reopen
    timer (measured: alert delivered after 58 s, buffered, not lost), hence 75 s."""
    subprocess.run(
        [
            "ssh",
            "-F",
            str(HOME / "ssh_config"),
            "atk01",
            'timeout 3 bash -c "exec 3<>/dev/tcp/10.77.30.10/3306" 2>/dev/null; true',
        ],
        check=True,
        timeout=30,
    )
    with api() as c:
        t0 = time.monotonic()
        while time.monotonic() - t0 < 75:
            age = c.get("/api/overview").json()["telemetry"]["age_s"].get("ids")
            if age is not None and age < time.monotonic() - t0 + 2:
                break
            time.sleep(1)
        assert age is not None and age < time.monotonic() - t0 + 2, f"no new IDS alert ({age=})"
