"""Read-only: FW01 pf filter log sample (format, whether blocks are logged, per interface)."""
from afw.lab.gns3 import Gns3Client
from afw.lab.console import SerialConsole
from afw.lab.provision_fw import FwShell
gc = Gns3Client.from_env(); p = gc.find_project("AI-Adaptive-Firewall")
fw = gc.node_by_name(p["project_id"])["FW01"]
sh = FwShell(SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"])), lambda m: None)
sh.login()
F = "$(ls -t /var/log/filter/filter_*.log | head -1)"
for cmd in ["date -u",
            "for f in /var/log/filter/filter_2026102[89].log; do grep ',block,' $f | awk -F'] ' '{print $2}' | awk -F, '$5 ~ /vtnet[456]/ {print $5, $8, $17, $19, $20, $22}' ; done | sort | uniq -c | sort -rn | head -30",
            "for f in /var/log/filter/filter_2026102[89].log; do grep ',block,' $f | awk -F'] ' '$2 ~ /,vtnet[456],/' | head -2 | cut -c1-60; done"]:
    print("$", cmd); print(sh.run(cmd, check=False).strip()[:3000])
