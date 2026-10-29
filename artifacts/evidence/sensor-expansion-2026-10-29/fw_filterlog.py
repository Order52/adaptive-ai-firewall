"""Read-only: FW01 pf filter log sample (format, whether blocks are logged, per interface)."""
from afw.lab.gns3 import Gns3Client
from afw.lab.console import SerialConsole
from afw.lab.provision_fw import FwShell
gc = Gns3Client.from_env(); p = gc.find_project("AI-Adaptive-Firewall")
fw = gc.node_by_name(p["project_id"])["FW01"]
sh = FwShell(SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"])), lambda m: None)
sh.login()
F = "$(ls -t /var/log/filter/filter_*.log | head -1)"
for cmd in ["date -u", "ls -la /var/log/filter/ | tail -4",
            f"wc -l {F}", f"grep -c ',block,' {F}",
            f"grep ',block,' {F} | cut -d, -f5 | sort | uniq -c",
            f"grep ',block,' {F} | grep -E '10[.]77[.](30|40|60)[.]' | tail -3",
            f"grep ',block,' {F} | tail -3",
            "pfctl -sr 2>/dev/null | grep -c ' log '",
            "pfctl -sr 2>/dev/null | grep 'block' | grep ' log ' | head -5"]:
    print("$", cmd); print(sh.run(cmd, check=False).strip()[:3000])
