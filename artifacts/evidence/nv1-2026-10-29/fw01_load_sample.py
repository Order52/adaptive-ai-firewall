"""Read-only FW01 load sample over the serial console (no configuration change)."""
from afw.lab.gns3 import Gns3Client
from afw.lab.console import SerialConsole
from afw.lab.provision_fw import FwShell
gc = Gns3Client.from_env(); p = gc.find_project("AI-Adaptive-Firewall")
fw = gc.node_by_name(p["project_id"])["FW01"]
sh = FwShell(SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"])), lambda m: None)
sh.login()
for cmd in ["date -u", "sysctl -n hw.ncpu hw.physmem", "uptime",
            "vmstat 5 4 | tail -3",
            "ps -axo pid,rss,vsz,%cpu,time,command | grep -i '[s]uricata' | cut -c1-140",
            "netstat -i -b -n | egrep 'vtnet[0-9] .*Link' | awk '{print $1, $5, $8, $11}'",
            "ls -la /var/log/suricata/ | head; df -h /var | tail -1"]:
    print("$", cmd); print(sh.run(cmd, check=False).strip())
