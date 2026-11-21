#!/usr/bin/env python3
"""Collect champion-vs-challenger shadow scores from the live controller (gate A1).

Polls GET /api/learning/shadow every INTERVAL seconds and appends every window not seen before
to a JSONL file (the controller keeps only the newest windows), plus one status line per poll.
Read-only. The operator token is read from a file and never printed.

    python3 scripts/ad1_collect.py OUT.jsonl [--minutes 110] [--interval 60]
"""

from __future__ import annotations

import argparse
import json
import ssl
import time
import urllib.request
from pathlib import Path

BASE = "https://10.77.50.10:8080"
CA = Path.home() / ".config/afw/pki/lab-ca.pem"
TOKEN = Path.home() / ".config/afw/api/operator.token"


def fetch(ctx: ssl.SSLContext, token: str) -> dict:
    req = urllib.request.Request(  # noqa: S310 - fixed https URL
        f"{BASE}/api/learning/shadow?limit=1000", headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:  # noqa: S310 - fixed https URL
        return json.load(r)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--minutes", type=float, default=110)
    ap.add_argument("--interval", type=float, default=60)
    a = ap.parse_args()
    ctx = ssl.create_default_context(cafile=str(CA))
    token = TOKEN.read_text().strip()
    seen: set[tuple[str, str]] = set()
    if a.out.exists():
        for line in a.out.read_text().splitlines():
            r = json.loads(line)
            if r.get("kind") == "window":
                seen.add((r["source_ip"], r["window_end"]))
    end = time.time() + a.minutes * 60
    while time.time() < end:
        try:
            d = fetch(ctx, token)
        except Exception as e:  # keep collecting through a transient error
            print("poll failed:", type(e).__name__, flush=True)
            time.sleep(a.interval)
            continue
        st = d.get("status", {})
        rows = []
        for s in d.get("recent_shadow", []):
            key = (s["source_ip"], s["window_end"])
            if key not in seen:
                seen.add(key)
                rows.append({"kind": "window", **s})
        rows.append(
            {
                "kind": "status",
                "t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "n_learned": (st.get("n_learned") if isinstance(st, dict) else None),
                "counts": st.get("counts"),
                "excluded": st.get("excluded"),
                "agreement": d.get("agreement"),
            }
        )
        with a.out.open("a") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
