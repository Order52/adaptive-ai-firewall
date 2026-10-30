import time
from afw.lab.gns3 import Gns3Client
from afw.lab.console import SerialConsole
from afw.lab.provision_fw import FwShell
gc=Gns3Client.from_env(); p=gc.find_project("AI-Adaptive-Firewall")
fw=gc.node_by_name(p["project_id"])["FW01"]
sh=FwShell(SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"])), lambda m: None); sh.login()
print("creating 1GB swap file (dd)...")
print(sh.run("dd if=/dev/zero of=/swap0 bs=1m count=1024 2>&1 | tail -1", check=False, timeout=120).strip()[:200])
sh.run("chmod 600 /swap0", check=False)
# persistent fstab entry (md-backed swap file, late)
sh.run("grep -q '/swap0' /etc/fstab || echo 'md99 none swap sw,file=/swap0,late 0 0' >> /etc/fstab", check=False)
print("fstab:", sh.run("grep swap /etc/fstab", check=False).strip()[:150])
print("enable swap:", sh.run("swapon -aLq 2>&1; swapinfo -h | tail -2", check=False).strip()[:300])
