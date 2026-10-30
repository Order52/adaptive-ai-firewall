"""Measure telemetry loss when FW01 silently drops the live WAF01->CTRL01 session.

WAF01 appends N numbered non-JSON marker lines (1/s) to its forwarded heartbeat log;
CTRL01 counts each received one as parse_error:no_json. At t=KILL_AT FW01's pf states
between WAF01 and CTRL01 are killed (pfctl -k), which makes the established session
dead without notice to either end. Delivered = counter delta after settling.
"""
import json, os, subprocess, sys, time, ssl, urllib.request
from afw.lab.gns3 import Gns3Client
from afw.lab.console import SerialConsole
from afw.lab.provision_fw import FwShell

N, KILL_AT, SETTLE_S = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
H = os.path.expanduser("~/.config/afw")
CTX = ssl.create_default_context(cafile=f"{H}/pki/lab-ca.pem")
TOKEN = open(f"{H}/api/operator.token").read().strip()

def counts():
    req = urllib.request.Request("https://10.77.50.10:8080/api/overview",
                                 headers={"Authorization": f"Bearer {TOKEN}"})
    t = json.load(urllib.request.urlopen(req, context=CTX, timeout=10))["telemetry"]
    return t["counts"], t["sensors"]

def log(*a):
    print(time.strftime("%H:%M:%SZ", time.gmtime()), *a, flush=True)

gc = Gns3Client.from_env(); p = gc.find_project("AI-Adaptive-Firewall")
fw = gc.node_by_name(p["project_id"])["FW01"]
con = SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"]))
sh = FwShell(con, lambda m: None); sh.login()
log("FW01 states WAF01<->CTRL01 before:",
    sh.run("pfctl -ss | grep -c '10.77.30.10.*10.77.50.10' || true", check=False).strip().splitlines()[-1:])
c0 = counts()[0].get("parse_error:no_json", 0)
log("counter before", c0)
tag = f"afw-relp-test-{int(time.time())}"
writer = subprocess.Popen(["ssh", "-F", f"{H}/ssh_config", "waf01",
    f"for i in $(seq 1 {N}); do echo '{tag} '$i | sudo tee -a /var/log/afw-hb/heartbeat.log >/dev/null; sleep 1; done"])
t0 = time.monotonic()
while time.monotonic() - t0 < KILL_AT:
    time.sleep(0.5)
KILL = ("n=0; for id in $(pfctl -ss -vv | awk '/10[.]77[.]30[.]10:[0-9]+ -> 10[.]77[.]50[.]10:551[46] "
        "|10[.]77[.]50[.]10:551[46] <- 10[.]77[.]30[.]10/{f=1;next} f&&/id:/{print $2;f=0}'); "
        "do pfctl -k id -k $id >/dev/null 2>&1 && n=$((n+1)); done; echo killed_by_id=$n")
out = sh.run(KILL, check=False)
log("killed states:", out.strip().splitlines()[-1:])
con.close()
writer.wait()
log(f"writer done: {N} lines written")
last, stable_since = None, time.monotonic()
end = time.monotonic() + SETTLE_S
while time.monotonic() < end:
    c = counts()[0].get("parse_error:no_json", 0) - c0
    if c != last:
        log("delivered so far", c); last, stable_since = c, time.monotonic()
    if c >= N and time.monotonic() - stable_since > 30:
        break
    time.sleep(5)
cs, sensors = counts()
log(f"RESULT written={N} delivered={last} lost={N - last}")
log("sessions", {k: v for k, v in cs.items() if "session" in k or "relp" in k or "drop" in k}, "sensors", sensors)
