# POST-HOC diagnostic (after the one-shot NV1 test; explains, does not re-test). usage: <snapshot> <calibration.json>
import json, sys
from pathlib import Path
from collections import Counter
from afw.config import Settings
from afw.container import build_container
from afw.ml.network_detector import NetworkNovelty, calibration_windows
snap=Path(sys.argv[1]); c=build_container(Settings(config=Path("config/lab.yaml"), data_dir=snap), simulated=True, migrate=False)
services=[(s.address,s.port) for s in c.cfg.services]
det=NetworkNovelty(); det.load(json.loads(Path(sys.argv[2]).read_text()))
for ds in ["a3-sel","a3-sel-shift"]:
    vs=calibration_windows(c.datasets.manifest(ds), c.datasets.net_events(ds), services)
    for v in vs:
        x=det.assess(v)
        if x.strong: print("STRONG", ds, v.source_ip, x.reasons)
    by=Counter(str(v.source_ip) for v in vs if det.assess(v).unfamiliar)
    print(ds, dict(by))
