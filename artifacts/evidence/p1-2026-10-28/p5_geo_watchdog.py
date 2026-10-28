"""Live: country tables are flushed by the FW01 watchdog when the controller dies."""
import os, subprocess, sys, time
sys.path.insert(0, "tests/lab")
from test_enforcement_lab import api, wait_state, revoke
from test_geo_enforcement_lab import connects, country_policy
SSH = ["ssh", "-F", os.path.expanduser("~/.config/afw/ssh_config")]
def t(): return time.strftime("%H:%M:%S", time.gmtime())
with api() as c:
    p = c.post("/api/policies", json=country_policy("AU", "outbound")).json()
    p = wait_state(c, p["policy_id"], {"enforced", "failed"}, 120)
    print(t(), "policy", p["policy_id"], p["state"], "usr01->1.1.1.1:", connects("usr01", "1.1.1.1"))
    subprocess.run([*SSH, "ctrl01", "sudo systemctl stop afw-controller"], check=True)
    stopped = time.monotonic(); print(t(), "controller stopped")
    while connects("usr01", "1.1.1.1") is False and time.monotonic() - stopped < 240:
        time.sleep(5)
    print(t(), f"usr01->1.1.1.1 open again after {time.monotonic()-stopped:.0f}s:", connects("usr01", "1.1.1.1"))
    subprocess.run([*SSH, "ctrl01", "sudo systemctl start afw-controller"], check=True)
    print(t(), "controller started")
for _ in range(60):
    try:
        with api() as c:
            c.get("/api/health").raise_for_status(); break
    except Exception: time.sleep(2)
with api() as c:
    started = time.monotonic()
    while connects("usr01", "1.1.1.1") and time.monotonic() - started < 240:
        time.sleep(5)
    q = c.get(f"/api/policies/{p['policy_id']}").json()
    print(t(), f"blocked again after restart ({time.monotonic()-started:.0f}s):", not connects("usr01", "1.1.1.1"), "state", q["state"])
    for h in q["history"][-4:]: print("   ", h["at"][11:19], h["from_state"], "->", h["to_state"], "|", h["note"][:90])
    print(t(), "revoke ->", revoke(c, p["policy_id"])["state"])
