# Upgrade and rollback of the controller

The controller is the wheel built from this repository, installed on CTRL01 by Ansible.
Deploy = build the wheel from the working tree, copy it, `pip install` into the controller
venv, restart. Measured: **16 s** each way, API healthy afterwards (drill C, 2026-11-16).

**Before:** `uv run pytest tests/unit tests/integration`, `uv run mypy src`, `uv run ruff check src tests`;
a fresh `scripts/backup_controller.sh` (14 s).

**Upgrade**
```bash
git checkout <tag-or-branch> && uv run afw lab deploy --limit ctrl01
api /api/readyz        # {"ready": true} within about 20 s
```

**Rollback**
```bash
git checkout <previous-tag>          # or: git worktree add ../afw-prev <previous-tag>; cd ../afw-prev
uv run afw lab deploy --limit ctrl01 # the deploy builds from whatever is checked out
api /api/health
```
Caveats: (1) rolling back across a database migration needs the pre-upgrade backup;
migrations run on every start (`ExecStartPre=afw db upgrade`) and are forward-only.
(2) An older version may expose more than the current one (for example unauthenticated
`/api/health` detail before 2026-11-16): roll back only to investigate, then roll forward.
(3) `--limit` also reapplies the common hardening (SSH, journal) to that host.

Other hosts: `--limit waf01,app01,db01,usr01,atk01`. DESK01 is a separately baked image.
