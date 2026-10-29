import time, datetime
from afw.lab.gns3 import Gns3Client
from afw.lab.console import SerialConsole
from afw.lab.provision_fw import FwShell
gc=Gns3Client.from_env(); p=gc.find_project("AI-Adaptive-Firewall")
fw=gc.node_by_name(p["project_id"])["FW01"]
sh=FwShell(SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"])), lambda m: None); sh.login()
maxrss=0
for i in range(11):
    pid=sh.run("pgrep suricata", check=False).strip()[:16]
    rss=sh.run("ps -axo rss,command | grep '[s]uricata' | awk '{print int($1/1024)}'", check=False).strip()[:16]
    free=sh.run("top -b 2>/dev/null | grep -o '[0-9]*M Free'", check=False).strip()[:20]
    sw=sh.run("swapinfo | tail -1 | awk '{print $3}'", check=False).strip()[:16]
    try: maxrss=max(maxrss,int(rss))
    except: pass
    t=datetime.datetime.now(datetime.UTC).strftime("%H:%M:%S")
    print(f"{t} suricata={pid or 'DOWN!'} rss={rss}M free={free} swapKB={sw}")
    time.sleep(45)
print("peak Suricata RSS:", maxrss, "M")
