import sys, time
from afw.lab.gns3 import Gns3Client
gc=Gns3Client.from_env(); p=gc.find_project("AI-Adaptive-Firewall"); pid=p["project_id"]
fw=gc.node_by_name(pid)["FW01"]; nid=fw["node_id"]
target=int(sys.argv[1])
cur=fw.get("properties",{}).get("ram")
print(f"FW01 current ram={cur} MB, target={target} MB, status={fw['status']}")
print("stopping FW01..."); gc.node_action(pid, nid, "stop"); gc.wait_status(pid, nid, "stopped", timeout=60)
print("setting ram..."); gc.update_node(pid, nid, {"properties": {"ram": target}})
chk=gc.node_by_name(pid)["FW01"].get("properties",{}).get("ram")
print("ram now set to", chk, "MB")
print("starting FW01..."); gc.node_action(pid, nid, "start"); gc.wait_status(pid, nid, "started", timeout=90)
print("FW01 started")
