"""P1 EXPLORATORY (post hoc, not a predeclared criterion): matched-window sensitivity
of frozen profiles to attack-magnitude perturbations, single-feature and combined.

usage: p1_exploratory_sensitivity.py <ref_version> <versions,comma> <dataset>  (CTRL01)
Magnitudes are fixed here, before looking at any result of this script:
fractions -> 1.0; distinct_usernames -> 20; login_rate -> 60 per window;
"credential_attack" sets all four at once (a brute-force/spraying-shaped window).
"""

import json
import sys

import numpy as np

from afw.config import get_settings
from afw.container import build_container
from afw.ml.challenger_gate import tumbling

PROBES = {
    "auth_fail_frac": {"auth_fail_frac": 1.0},
    "client_err_frac": {"client_err_frac": 1.0},
    "distinct_usernames": {"distinct_usernames": 20.0},
    "login_rate": {"login_rate": 60.0},
    "credential_attack": {
        "auth_fail_frac": 1.0, "client_err_frac": 1.0,
        "distinct_usernames": 20.0, "login_rate": 60.0,
    },
}
c = build_container(get_settings(), simulated=True, migrate=False)
ref_v, vs, ds = int(sys.argv[1]), [int(x) for x in sys.argv[2].split(",")], sys.argv[3]
obs = c.datasets.observations(ds)


def load(v):
    p, ms = c.learning.load_version("rental", v)
    ws = tumbling(c.learning.windows(obs, c.learning.catalog("rental", p)))
    return {(w.source_ip, w.window_start): w for w in ws}, {m.record.detector.value: m for m in ms}


def flags(m, ws):
    return np.asarray(m.detector.score(np.array([w.as_row() for w in ws], dtype=float))) >= m.record.threshold


ref_w, ref_m = load(ref_v)
out = {"dataset": ds, "reference": ref_v, "magnitudes": PROBES, "versions": {}}
for v in vs:
    new_w, new_m = load(v)
    keys = [k for k in ref_w if k in new_w]
    res = {}
    for det, rm in ref_m.items():
        nm = new_m[det]
        a = [ref_w[k] for k in keys]
        b = [new_w[k] for k in keys]
        both = ~flags(rm, a) & ~flags(nm, b)
        sel = [i for i in np.flatnonzero(both)]
        r = {"matched_bases": len(sel)}
        for name, upd in PROBES.items():
            pa = [a[i].model_copy(update={"values": {**a[i].values, **upd}}) for i in sel]
            pb = [b[i].model_copy(update={"values": {**b[i].values, **upd}}) for i in sel]
            r[name] = {"reference": round(float(flags(rm, pa).mean()), 4) if sel else None,
                       "new": round(float(flags(nm, pb).mean()), 4) if sel else None}
        res[det] = r
    out["versions"][f"v{v}"] = res
print(json.dumps(out, indent=1))
