from afw.lab.gns3 import Gns3Client
from afw.lab.console import SerialConsole
from afw.lab.provision_fw import FwShell
gc=Gns3Client.from_env(); p=gc.find_project("AI-Adaptive-Firewall")
fw=gc.node_by_name(p["project_id"])["FW01"]
sh=FwShell(SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"])), lambda m: None); sh.login()
print("dmesg kill/swap:", sh.run("dmesg 2>/dev/null | grep -iE 'killed|swap|suricata|out of' | tail -5", check=False).strip()[:600])
print("messages kill:", sh.run("clog /var/log/system/latest.log 2>/dev/null | grep -iE 'killed|swap|out of|suricata.*exit|kernel' | tail -5", check=False).strip()[:600])
print("swap:", sh.run("swapinfo -h 2>/dev/null", check=False).strip()[:300])
print("midpoint mem (start suricata then sample):", sh.run("configctl ids start >/dev/null 2>&1; sleep 12; top -b 2>/dev/null | grep -E 'Mem|suricata' | head -3; pgrep suricata", check=False).strip()[:400])
