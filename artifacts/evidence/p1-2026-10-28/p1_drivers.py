"""P1 attribution: occlusion drivers of each frozen version's flagged tumbling windows.

usage: p1_drivers.py <versions,comma> <datasets,comma>   (read-only; run on CTRL01)
For every flagged window, each feature is reset to the version's own training median
in turn; the feature whose reset lowers the score most is that window's driver.
"""

import json
import sys
from collections import Counter

import numpy as np

from afw.config import get_settings
from afw.container import build_container
from afw.domain.features import FEATURE_NAMES
from afw.ml.challenger_gate import tumbling

c = build_container(get_settings(), simulated=True, migrate=False)
out = {}
for v in [int(x) for x in sys.argv[1].split(",")]:
    prof, models = c.learning.load_version("rental", v)
    cat = c.learning.catalog("rental", prof)
    train = []
    for ds in prof.provenance.dataset_ids:
        train += c.learning.windows(c.learning._benign_observations([ds]), cat)
    med = np.median(np.array([w.as_row() for w in train], dtype=float), axis=0)
    for ds in sys.argv[2].split(","):
        ws = tumbling(c.learning.windows(c.datasets.observations(ds), cat))
        x = np.array([w.as_row() for w in ws], dtype=float)
        rec = {}
        for m in models:
            s = np.asarray(m.detector.score(x))
            flagged = np.flatnonzero(s >= m.record.threshold)
            drivers = Counter()
            for i in flagged:
                rows = np.repeat(x[i : i + 1], len(FEATURE_NAMES), axis=0)
                for j in range(len(FEATURE_NAMES)):
                    rows[j, j] = med[j]
                drivers[FEATURE_NAMES[int(np.argmax(s[i] - m.detector.score(rows)))]] += 1
            rec[m.record.detector.value] = {
                "flagged": len(flagged), "windows": len(ws), "drivers": dict(drivers.most_common())
            }
        out[f"v{v}/{ds}"] = rec
print(json.dumps(out, indent=1))
