"""Read-only: Suricata version and livedev flow-tracking settings on FW01."""
from afw.lab.gns3 import Gns3Client
from afw.lab.console import SerialConsole
from afw.lab.provision_fw import FwShell
gc = Gns3Client.from_env(); p = gc.find_project("AI-Adaptive-Firewall")
fw = gc.node_by_name(p["project_id"])["FW01"]
sh = FwShell(SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"])), lambda m: None)
sh.login()
for cmd in ["date -u", "suricata -V",
            "grep -n -A3 '^livedev' /usr/local/etc/suricata/suricata.yaml",
            "grep -n -B1 -A3 'interface:' /usr/local/etc/suricata/suricata.yaml | head -30",
            "grep -rn 'livedev' /usr/local/etc/suricata/ | head"]:
    print("$", cmd); print(sh.run(cmd, check=False).strip())
