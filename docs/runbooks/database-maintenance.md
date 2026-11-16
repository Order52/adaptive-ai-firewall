# Database size and maintenance

SQLite at `/var/lib/afw/afw.sqlite3` on CTRL01 (11 GB disk).

**Retention (automatic, hourly):** raw observations, features, detections, IDS alerts and
network events: 7 days. Risk assessments: 90 days, except rows cited by a policy or by
feedback, which are kept. Freed pages are returned to the filesystem incrementally.

**Check size**
```bash
ssh -F ~/.config/afw/ssh_config ctrl01 'sudo ls -lh /var/lib/afw/afw.sqlite3; df -h /var/lib/afw | tail -1'
```
Alert if disk use exceeds 80 %.

**Compact once (offline, about 5 s per 500 MB; needs free space equal to the live data)**
```bash
bash scripts/backup_controller.sh                      # always first
ssh -F ~/.config/afw/ssh_config ctrl01 'sudo systemctl stop afw-controller; sudo -u afwctl /opt/afw/venv/bin/python - <<"PY"
import sqlite3
c = sqlite3.connect("/var/lib/afw/afw.sqlite3", timeout=120, isolation_level=None)
c.execute("PRAGMA auto_vacuum=2")   # incremental: retention can return freed pages from now on
c.execute("VACUUM")
print("integrity:", c.execute("PRAGMA integrity_check").fetchone()[0])
PY
sudo systemctl start afw-controller'
api /api/readyz
```
Done on 2026-11-16: 2.7 GB to 517 MB, 5 s downtime, integrity ok, mode set to incremental
auto-vacuum so retention can shrink the file from then on.

**Change retention:** `ASSESSMENT_RETENTION` and `WATCH_RETENTION` in `src/afw/services/runtime.py`
(a deploy is needed). Do not delete rows by hand: policy explanations depend on them.
