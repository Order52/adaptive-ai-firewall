"""A4 development diagnostic (no one-shot data consumed). Confirms, on the already-
consumed Phase E sets, that A3's F1 failure is the distinct_usernames quantity of the
security path calibrated without household coverage, and that household-covered
calibration removes it while the ceiling (>=5 accounts) still fires on spraying."""
import sys
from datetime import UTC, datetime
from pathlib import Path
import numpy as np
from afw.config import Settings
from afw.container import build_container
from afw.ml import p6_study as st
from afw.ml.security_path import QUANTITIES, SecurityPath, quantities
from afw.ml.registry import ArtifactStore

snap = Path(sys.argv[1])
_load = ArtifactStore.load
def _remap(self, record):
    p = record.artifact_path.replace("/var/lib/afw/", f"{snap}/")
    return _load(self, record.model_copy(update={"artifact_path": p}))
ArtifactStore.load = _remap

c = build_container(Settings(config=Path("config/lab.yaml"), data_dir=snap), simulated=True, migrate=False)
L, app = c.learning, "rental"
store = ArtifactStore(snap / "a4-diag-models")
now = datetime(2026, 10, 28, 14, 0, tzinfo=UTC)

# Train S exactly as A3 did: security calibrated on p7-val.
S = st.train("S", L, app, ["p7-train"], ["p7-val"], store, security=True, created_at=now)
sec = S.security
di = QUANTITIES.index("distinct_usernames")
print("security effective thresholds:", {q: round(v, 3) for q, v in S.security.effective().items()})
print("distinct_usernames: calibrated threshold =", round(float(sec.thresholds[di]), 3),
      "ceiling =", float(sec.ceilings[di]))

def windows(ds):
    cat = S.catalog
    w, _ = L._labeled([ds], cat)
    return list(w)

for ds in ["p6-final", "p6-final-shift"]:
    w = windows(ds)
    if not w:
        print(ds, "no windows"); continue
    X = np.array([quantities(v) for v in w])
    flags = sec.flags(w)
    # which quantity drove each flagged window
    over = (X > sec.thresholds) | (X >= sec.ceilings)
    du_only = flags & over[:, di] & (over.sum(axis=1) == 1)
    du_vals = X[:, di]
    print(f"\n{ds}: {len(w)} windows, flagged {int(flags.sum())} ({flags.mean():.4f})")
    print(f"  distinct_usernames distribution: "
          f"max {du_vals.max():.0f}, >1: {int((du_vals>1).sum())}, >=2: {int((du_vals>=2).sum())}, "
          f">=5 (ceiling): {int((du_vals>=5).sum())}")
    print(f"  windows flagged by distinct_usernames: {int(over[:,di].sum())}; "
          f"flagged by distinct_usernames ALONE: {int(du_only.sum())}")
    # counterfactual: raise distinct_usernames threshold to 4 (below ceiling 5), keep others
    cf = sec.thresholds.copy(); cf[di] = 4.0
    cf_flags = ((X > cf) | (X >= sec.ceilings)).any(axis=1)
    print(f"  with distinct_usernames calibrated at 4 (ceiling 5 unchanged): "
          f"flagged {int(cf_flags.sum())} ({cf_flags.mean():.4f})")
