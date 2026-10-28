"""Live ADR-036: real-country enforcement on FW01, checked independently of the controller.

Traffic is checked with plain TCP connects run on the lab hosts over SSH (not through
the controller or its probe agents), before, during and after a policy:

* outbound AU (DB-IP: 1.1.1.1 is AU, 8.8.8.8 is US): USR01 cannot reach 1.1.1.1:443
  while the policy is active; it still reaches 8.8.8.8:443; APP01 (a server zone, not
  covered by design) still reaches 1.1.1.1:443; after revocation USR01 reaches it again;
* inbound: the table is loaded and read back, but the policy is never claimed
  ENFORCED, because no real-country traffic reaches the lab.
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest
from test_enforcement_lab import api, wait_state

pytestmark = pytest.mark.skipif(not os.environ.get("AFW_LAB"), reason="needs the GNS3 lab")

SSH = ["ssh", "-F", os.path.expanduser("~/.config/afw/ssh_config")]
PULL_S = 120  # FW01 pulls twice a minute; allow two cycles plus apply time


def connects(host: str, address: str, port: int = 443) -> bool:
    cmd = f"timeout 6 bash -c '</dev/tcp/{address}/{port}' 2>/dev/null && echo open || echo shut"
    out = subprocess.run([*SSH, host, cmd], capture_output=True, text=True, timeout=30).stdout
    return out.strip() == "open"


def revoke(c, pid: str) -> dict:
    """Removal is confirmed only after FW01 has pulled the shrunken list and the
    controller has read the table back, so allow a full pull window."""
    c.post(f"/api/policies/{pid}/revoke", json={"reason": "lab acceptance cleanup"})
    return wait_state(c, pid, {"rolled_back", "expired"}, PULL_S)


def country_policy(cc: str, direction: str) -> dict[str, object]:
    return {
        "kind": "geo_block",
        "target": {
            "type": "country",
            "country_code": cc,
            "direction": direction,
            "simulated": False,
        },
        "duration_s": 600,
        "reason": "lab acceptance test (ADR-036)",
    }


def test_outbound_country_block_is_real_scoped_and_reversible():
    with api() as c:
        assert connects("usr01", "1.1.1.1") and connects("usr01", "8.8.8.8"), "no egress"
        r = c.post("/api/policies", json=country_policy("AU", "outbound"))
        r.raise_for_status()
        p = r.json()
        try:
            p = wait_state(c, p["policy_id"], {"enforced", "failed", "rejected"}, PULL_S)
            assert p["state"] == "enforced", (p["state"], p["verification"], p["history"][-2:])
            assert p["verification"]["traffic_outbound"].startswith("blocked")
            assert not connects("usr01", "1.1.1.1")  # independent of the controller
            assert connects("usr01", "8.8.8.8")  # other countries unaffected
            assert connects("app01", "1.1.1.1")  # server zones deliberately not covered
        finally:
            done = revoke(c, p["policy_id"])
        assert done["state"] == "rolled_back"
        end = time.monotonic() + PULL_S
        while not connects("usr01", "1.1.1.1") and time.monotonic() < end:
            time.sleep(5)
        assert connects("usr01", "1.1.1.1")


def test_inbound_country_block_is_read_back_but_never_claimed_enforced():
    with api() as c:
        r = c.post("/api/policies", json=country_policy("KP", "inbound"))
        r.raise_for_status()
        p = r.json()
        try:
            end = time.monotonic() + PULL_S
            while time.monotonic() < end:
                p = c.get(f"/api/policies/{p['policy_id']}").json()
                if p["verification"].get("readback"):
                    break
                time.sleep(2)
            assert p["verification"].get("readback") is True, p
            assert p["state"] == "applied_unverified"
            assert p["verification"]["traffic_inbound"].startswith("n/a")
        finally:
            assert revoke(c, p["policy_id"])["state"] == "rolled_back"
