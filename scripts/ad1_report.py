#!/usr/bin/env python3
"""Judge gate A1 (docs/FINAL_YEAR_PLAN.md) from the windows collected by ad1_collect.py.

Thresholds are fixed here, as predeclared in the plan: on the unseen user's first 10 minutes the
champion must flag at least 50 % of windows (else NOT INFORMATIVE) and the challenger at most half
as many as the champion (else FAIL). Also prints the trend over time for the vouched users.

    python3 scripts/ad1_report.py WINDOWS.jsonl [--held 10.77.20.254] [--out report.json]
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

MIN_WINDOWS = 30
CHAMPION_MIN_RATE = 0.5
RATIO_MAX = 0.5
HELD_MINUTES = 10


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def rate(rows: list[dict], key: str) -> float | None:
    return sum(1 for r in rows if r[key]) / len(rows) if rows else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("windows", type=Path)
    ap.add_argument("--held", default="10.77.20.254")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    rows = [json.loads(x) for x in a.windows.read_text().splitlines()]
    wins = [r for r in rows if r.get("kind") == "window" and r.get("challenger_warm")]
    held_all = sorted((r for r in wins if r["source_ip"] == a.held), key=lambda r: r["window_end"])
    out: dict = {"held_user": a.held, "windows_collected": len(wins)}
    if held_all:
        start = ts(held_all[0]["window_end"])
        held = [
            r for r in held_all if ts(r["window_end"]) <= start + timedelta(minutes=HELD_MINUTES)
        ]
        ch, cl = rate(held, "champion_anomalous"), rate(held, "challenger_anomalous")
        out.update(
            held_windows=len(held),
            held_first_window=held_all[0]["window_end"],
            challenger_n_learned_at_start=held[0]["n_learned"],
            champion_flag_rate=ch,
            challenger_flag_rate=cl,
            mean_champion_score=sum(r["champion_score"] for r in held) / len(held),
            mean_challenger_score=sum(r["challenger_score"] for r in held) / len(held),
            threshold=held[0]["threshold"],
        )
        if len(held) < MIN_WINDOWS:
            verdict = f"NOT INFORMATIVE: {len(held)} windows, need {MIN_WINDOWS}"
        elif ch is None or ch < CHAMPION_MIN_RATE:
            verdict = f"NOT INFORMATIVE: champion flags only {ch:.0%}, need {CHAMPION_MIN_RATE:.0%}"
        elif cl is not None and cl <= RATIO_MAX * ch:
            verdict = "PASS"
        else:
            verdict = "FAIL"
        out["A1"] = verdict
    else:
        out["A1"] = "NOT RUN: no windows from the unseen user"
    # trend: per 10-minute bucket, vouched users only
    buckets: dict[str, list[dict]] = defaultdict(list)
    t0 = ts(min(r["window_end"] for r in wins)) if wins else None
    for r in wins:
        if r["source_ip"] == a.held or t0 is None:
            continue
        b = int((ts(r["window_end"]) - t0).total_seconds() // 600) * 10
        buckets[f"+{b:03d} min"].append(r)
    out["trend_vouched_users"] = {
        k: {
            "windows": len(v),
            "champion_flag_rate": round(rate(v, "champion_anomalous") or 0, 3),
            "challenger_flag_rate": round(rate(v, "challenger_anomalous") or 0, 3),
            "n_learned_max": max(r["n_learned"] for r in v),
        }
        for k, v in sorted(buckets.items())
    }
    text = json.dumps(out, indent=2)
    if a.out:
        a.out.write_text(text)
    print(text)


if __name__ == "__main__":
    main()
