"""Run one shell command on FW01 over its serial console (lab only); prints the output.

usage: fw01_cmd.py '<command>'
"""
import sys

from afw.lab.console import SerialConsole
from afw.lab.gns3 import Gns3Client
from afw.lab.provision_fw import FwShell

c = Gns3Client.from_env()
p = c.find_project("AI-Adaptive-Firewall")
fw = c.node_by_name(p["project_id"])["FW01"]
con = SerialConsole(fw.get("console_host") or "127.0.0.1", int(fw["console"]))
try:
    sh = FwShell(con, lambda m: None)
    sh.login()
    print(sh.run(sys.argv[1], check=False), end="")
finally:
    con.close()
