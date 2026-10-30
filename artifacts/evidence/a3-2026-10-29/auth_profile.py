"""Descriptive: legitimate login behaviour in the A3 selection sets (what the AUTH rules faced).
usage: auth_profile.py <snapshot_dir>   (from the repo root)"""
import sys
from collections import Counter, defaultdict
from pathlib import Path

from afw.config import Settings
from afw.container import build_container
from afw.domain.events import AuthOutcome

c = build_container(Settings(config=Path("config/lab.yaml"), data_dir=Path(sys.argv[1])),
                    simulated=True, migrate=False)
for ds in ["a3-sel", "a3-sel-shift"]:
    obs = sorted((o for o in c.datasets.observations(ds) if o.auth_outcome is not None),
                 key=lambda o: o.observed_at)
    run: dict = defaultdict(int)
    longest: Counter = Counter()  # longest failure run per account
    per_src_fail: Counter = Counter()
    accounts_per_src: dict = defaultdict(set)
    for o in obs:
        k = (o.client_ip, o.username_hash)
        accounts_per_src[o.client_ip].add(o.username_hash)
        if o.auth_outcome is AuthOutcome.FAILURE:
            run[k] += 1
            per_src_fail[o.client_ip] += 1
            longest[k] = max(longest[k], run[k])
        else:
            run[k] = 0
    fails = sum(per_src_fail.values())
    print(f"{ds}: {len(obs)} login outcomes, {fails} failures from {len(per_src_fail)} sources; "
          f"longest per-account failure run histogram {dict(sorted(Counter(longest.values()).items()))}; "
          f"max accounts per source {max(len(v) for v in accounts_per_src.values())}")

# margin to the spraying rule: per source, the most open streaks at any one time (900 s lookback)
from datetime import timedelta  # noqa: E402

for ds in ["a3-sel", "a3-sel-shift"]:
    obs = sorted((o for o in c.datasets.observations(ds) if o.auth_outcome is not None),
                 key=lambda o: o.observed_at)
    by_src: dict = defaultdict(list)
    for o in obs:
        by_src[o.client_ip].append(o)
    peak = (0, 0)
    for src, xs in by_src.items():
        for i, o in enumerate(xs):
            lo = o.observed_at - timedelta(seconds=900)
            streak: dict = {}
            for p in xs[: i + 1]:
                if p.observed_at <= lo:
                    continue
                if p.auth_outcome is AuthOutcome.FAILURE:
                    streak[p.username_hash] = streak.get(p.username_hash, 0) + 1
                else:
                    streak[p.username_hash] = 0
            open_ = [v for v in streak.values() if v > 0]
            peak = max(peak, (len(open_), sum(open_)))
    print(f"{ds}: peak open streaks on one source (accounts, failures) = {peak}; "
          f"spraying needs >= (3, 5), guessing a streak >= 5")
