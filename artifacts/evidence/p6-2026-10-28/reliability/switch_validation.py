"""ADR-040 validation with real processes (directive 10-28b item 4).

usage: switch_validation.py <data_dir> kill-rollback <n> | complete-rollback | state | corrupt <detector>
Runs the deployed code against a COPY of CTRL01's data directory (never the live one).
"kill-rollback n": a profile rollback v2 -> v1 whose process dies (os._exit, no cleanup,
no commit) right after its n-th status UPDATE. "state": a fresh process reports the
trusted profile, the active models and what the controller actually loads.
"""
import os
import sys
from pathlib import Path

from sqlalchemy import event

from afw.config import Settings
from afw.container import build_container
from afw.ml.registry import ArtifactStore

data = Path(sys.argv[1])
_load = ArtifactStore.load


def _remap(self, record):
    p = record.artifact_path.replace("/var/lib/afw/", f"{data}/")
    return _load(self, record.model_copy(update={"artifact_path": p}))


ArtifactStore.load = _remap
c = build_container(Settings(config=Path("config/lab.yaml"), data_dir=data), simulated=True)
mode = sys.argv[2]

if mode == "kill-rollback":
    n, seen = int(sys.argv[3]), [0]

    def after(conn, cursor, statement, params, context, executemany):
        if statement.lstrip().upper().startswith(("UPDATE PROFILES", "UPDATE MODELS")):
            seen[0] += 1
            if seen[0] == n:
                print(f"dying after status write {n}", flush=True)
                os._exit(137)

    event.listen(c.learning.models.engine, "after_cursor_execute", after)
    c.learning.rollback("rental", 1, "validation", "kill test")
    print("rollback completed (no kill reached)")
elif mode == "complete-rollback":
    c.learning.rollback("rental", 1, "validation", "complete")
    print("rollback completed")
elif mode == "corrupt":
    rec = next(m for m in c.learning.models.active("rental") if m.detector.value == sys.argv[3])
    path = Path(rec.artifact_path.replace("/var/lib/afw/", f"{data}/"))
    path.write_bytes(path.read_bytes()[:-64] + b"\0" * 64)
    print(f"corrupted {rec.detector.value} v{rec.profile_version} artifact {path.name}")
elif mode == "state":
    prof = c.profiles.trusted("rental") if hasattr(c, "profiles") else None
    prof = c.learning.profiles.trusted("rental")
    active = c.learning.models.active("rental")
    print("trusted profile:", prof.version if prof else None)
    print("active models:", sorted((m.detector.value, m.profile_version) for m in active))
    try:
        ok = c.controller.reload()
        inf = c.controller.inference
        print("controller reload:", ok, "profile", inf.profile.version if inf.profile else None,
              "models", sorted((k.value, m.record.profile_version) for k, m in inf.models.items()))
    except Exception as e:  # noqa: BLE001
        print("controller reload FAILED:", type(e).__name__, e)
