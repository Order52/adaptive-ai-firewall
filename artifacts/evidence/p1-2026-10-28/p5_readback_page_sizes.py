import time, httpx
from pathlib import Path
H=Path("~/.config/afw").expanduser()
def cl(**kw):
    return httpx.Client(base_url="https://10.77.50.1/api",auth=((H/"opnsense/controller.key").read_text().strip(),(H/"opnsense/controller.secret").read_text().strip()),verify=str(H/"pki/lab-ca.pem"),timeout=60,**kw)
for label, headers, rc in [("gzip default",{},500),("gzip default",{},2000),("identity",{"Accept-Encoding":"identity"},500),("identity",{"Accept-Encoding":"identity"},2000),("identity",{"Accept-Encoding":"identity"},5000),("identity",{"Accept-Encoding":"identity"},20000)]:
    ok=fail=0; t=time.monotonic()
    for rep in range(3):
        c=cl(headers=headers); page=1; n=0
        try:
            while True:
                d=c.post("/firewall/alias_util/list/AFW_GEO_OUT",json={"current":page,"rowCount":rc}).json()
                n+=len(d["rows"])
                if len(d["rows"])<rc or n>=d["total"]: break
                page+=1
            ok+= n==d["total"]
        except httpx.HTTPError as e: fail+=1
    print(f"{label:13} rowCount={rc:5} ok={ok} fail={fail} avg={(time.monotonic()-t)/3:.2f}s rows={n}")
