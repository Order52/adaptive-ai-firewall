# POST-HOC (after the one-shot NV1 test): destinations of the strong-verdict user .156. usage: <snapshot>
import sys
from collections import Counter
from datetime import timedelta
from ipaddress import IPv4Address
from pathlib import Path
from afw.config import Settings
from afw.container import build_container
from afw.domain.network import NetKind
from afw.features.network import residual
c=build_container(Settings(config=Path("config/lab.yaml"), data_dir=Path(sys.argv[1])), simulated=True, migrate=False)
services=frozenset((s.address,s.port) for s in c.cfg.services)
ev=[e for e in c.datasets.net_events("a3-sel-shift") if e.src_ip==IPv4Address("10.77.20.156") and residual(e,services) and e.kind is NetKind.FLOW]
ev.sort(key=lambda e:(e.started_at or e.observed_at))
# busiest 60 s by distinct dst
best=(0,None)
for i,e in enumerate(ev):
    t=(e.started_at or e.observed_at); w=[x for x in ev if t<=(x.started_at or x.observed_at)<t+timedelta(seconds=60)]
    n=len({x.dst_ip for x in w}); best=max(best,(n,i),key=lambda z:z[0])
t=(ev[best[1]].started_at or ev[best[1]].observed_at)
w=[x for x in ev if t<=(x.started_at or x.observed_at)<t+timedelta(seconds=60)]
print("max distinct dst in 60s:",best[0])
print(Counter((str(x.dst_ip),x.proto,x.dst_port) for x in w).most_common())
allc=Counter((x.proto,x.dst_port) for x in ev); print("all residual flows by proto/port:",allc.most_common(10))
print("distinct dst overall:",len({x.dst_ip for x in ev}))
